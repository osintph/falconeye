"""Ghost Admin API client and daily digest publisher for FalconEye.

Posts use the Ghost html card format rather than the Lexical editor format.
This is a deliberate choice: HTML cards require no client-side conversion,
are indefinitely supported by Ghost as a legacy content type, and keep this
module dependency-free beyond PyJWT + requests.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import jwt
import requests

from falconeye.db import get_connection, init_db

log = logging.getLogger(__name__)

_GHOST_API_PATH = "/ghost/api/admin"


class GhostClient:
    """Thin wrapper around the Ghost Admin API."""

    def __init__(self, api_url: str, admin_api_key: str) -> None:
        kid, secret_hex = admin_api_key.split(":", 1)
        self._kid = kid
        self._secret = bytes.fromhex(secret_hex)
        self._base = api_url.rstrip("/") + _GHOST_API_PATH

    def _jwt(self) -> str:
        now = int(time.time())
        payload = {"iat": now, "exp": now + 300, "aud": "/admin/"}
        return jwt.encode(
            payload, self._secret, algorithm="HS256", headers={"kid": self._kid}
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Ghost {self._jwt()}",
            "Content-Type": "application/json",
            "Accept-Version": "v5.0",
        }

    def find_post_by_slug(self, slug: str) -> dict | None:
        """Return the first post matching slug, or None."""
        resp = requests.get(
            f"{self._base}/posts/",
            headers=self._headers(),
            params={"filter": f"slug:{slug}", "limit": 1},
            timeout=15,
        )
        resp.raise_for_status()
        posts = resp.json().get("posts") or []
        return posts[0] if posts else None

    def create_post(self, title: str, html: str, tags: list[str],
                    status: str, author_slug: str) -> dict:
        """Create a new Ghost post. Returns the created post dict."""
        payload = {
            "posts": [{
                "title":   title,
                "html":    html,
                "status":  status,
                "tags":    [{"name": t} for t in tags],
                "authors": [{"slug": author_slug}],
            }]
        }
        resp = requests.post(
            f"{self._base}/posts/",
            headers=self._headers(),
            json=payload,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["posts"][0]

    def update_post(self, post_id: str, updated_at: str, html: str,
                    status: str) -> dict:
        """Update an existing Ghost post. Returns the updated post dict."""
        payload = {
            "posts": [{
                "html":       html,
                "status":     status,
                "updated_at": updated_at,
            }]
        }
        resp = requests.put(
            f"{self._base}/posts/{post_id}/",
            headers=self._headers(),
            json=payload,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["posts"][0]


def _build_digest_html(db_path, target_date: str) -> tuple[str, str, str]:
    """
    Build the digest HTML for target_date (YYYY-MM-DD).

    Returns (title, excerpt, html_body).
    Queries the 24-hour window ending at midnight of target_date UTC.
    """
    day_start = f"{target_date}T00:00:00Z"
    day_end   = f"{target_date}T23:59:59Z"

    conn = get_connection(db_path)

    new_iocs = conn.execute("""
        SELECT i.ioc_value, i.ioc_type, i.threat_type, i.tags,
               s.match_criterion, s.matched_value
          FROM sieve_matches s
          JOIN iocs i ON i.id = s.record_id AND s.record_type = 'ioc'
         WHERE i.fetched_at BETWEEN ? AND ?
         GROUP BY i.id
         ORDER BY i.fetched_at DESC
         LIMIT 50
    """, (day_start, day_end)).fetchall()

    new_cves = conn.execute("""
        SELECT c.cve_id, c.description, c.cvss_v3_severity, c.cvss_v3_score,
               c.kev_date_added
          FROM sieve_matches s
          JOIN cves c ON c.id = s.record_id AND s.record_type = 'cve'
         WHERE c.fetched_at BETWEEN ? AND ?
         GROUP BY c.id
         ORDER BY c.cvss_v3_score DESC NULLS LAST
         LIMIT 20
    """, (day_start, day_end)).fetchall()

    active_campaigns = conn.execute("""
        SELECT name, summary, ioc_count, status, last_seen, slug
          FROM campaigns
         WHERE status IN ('active', 'dormant')
         ORDER BY ioc_count DESC
         LIMIT 10
    """).fetchall()

    conn.close()

    title = f"FalconEye PH Daily Threat Brief: {target_date}"
    excerpt = (
        f"{len(new_iocs)} new PH-matched IOCs, {len(new_cves)} new CVE alerts, "
        f"{len(active_campaigns)} campaigns updated."
    )

    parts = [
        "<h2>Signal Summary</h2>",
        f"<p>{excerpt}</p>",
    ]

    if new_iocs:
        parts.append("<h2>New PH-Matched IOCs</h2>")
        parts.append(
            "<table><thead><tr>"
            "<th>Type</th><th>Value</th><th>Threat</th><th>PH signal</th>"
            "</tr></thead><tbody>"
        )
        for r in new_iocs:
            parts.append(
                f"<tr><td>{r['ioc_type']}</td>"
                f"<td><code>{r['ioc_value'][:120]}</code></td>"
                f"<td>{r['threat_type'] or '—'}</td>"
                f"<td>{r['match_criterion']}: {r['matched_value']}</td></tr>"
            )
        parts.append("</tbody></table>")

    if new_cves:
        parts.append("<h2>New CVE Alerts</h2>")
        parts.append(
            "<table><thead><tr>"
            "<th>CVE</th><th>Severity</th><th>Score</th><th>Description</th>"
            "</tr></thead><tbody>"
        )
        for r in new_cves:
            desc = (r["description"] or "")[:160]
            parts.append(
                f"<tr><td><a href=\"https://nvd.nist.gov/vuln/detail/{r['cve_id']}\">"
                f"{r['cve_id']}</a></td>"
                f"<td>{r['cvss_v3_severity'] or 'N/A'}</td>"
                f"<td>{r['cvss_v3_score'] or ''}</td>"
                f"<td>{desc}</td></tr>"
            )
        parts.append("</tbody></table>")

    if active_campaigns:
        parts.append("<h2>Active Campaigns</h2>")
        parts.append("<ul>")
        for c in active_campaigns:
            url = f"https://falconeye.osintph.info/campaign/{c['slug']}/"
            parts.append(
                f"<li><a href=\"{url}\">{c['name']}</a> — "
                f"{c['ioc_count']} IOCs, status: {c['status']}</li>"
            )
        parts.append("</ul>")

    parts.append(
        "<hr><p><em>FalconEye is an independent OSINT-PH project. "
        "Data sourced from URLhaus, CISA KEV, NVD, APNIC, and Shodan InternetDB. "
        f"View the full dashboard at <a href=\"https://falconeye.osintph.info\">"
        f"falconeye.osintph.info</a>.</em></p>"
    )

    return title, excerpt, "\n".join(parts)


def run_digest(db_path, config_dir=None) -> int:
    """
    Build and publish the daily digest to Ghost.

    Searches Ghost for an existing post with slug falconeye-digest-YYYY-MM-DD.
    If found, updates it. If not, creates it. On any Ghost API error, logs and
    returns 0 (never blocks the pipeline).

    Returns 0 always.
    """
    from falconeye.config import (
        get_ghost_admin_key,
        get_ghost_api_url,
        get_ghost_author_slug,
        get_digest_mode,
        ConfigError,
    )

    try:
        api_url     = get_ghost_api_url()
        admin_key   = get_ghost_admin_key()
        author_slug = get_ghost_author_slug()
        mode        = get_digest_mode()
    except ConfigError as exc:
        log.error("Digest: missing config — %s", exc)
        return 0

    init_db(db_path)
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    slug = f"falconeye-digest-{yesterday}"

    try:
        title, excerpt, html_body = _build_digest_html(db_path, yesterday)
    except Exception as exc:
        log.error("Digest: failed to build HTML for %s: %s", yesterday, exc)
        return 0

    client = GhostClient(api_url, admin_key)

    try:
        existing = client.find_post_by_slug(slug)
        if existing:
            client.update_post(
                existing["id"], existing["updated_at"], html_body, mode
            )
            log.info("Digest: updated post %s (slug=%s)", existing["id"], slug)
        else:
            post = client.create_post(
                title, html_body,
                tags=["FalconEye", "threat-intelligence", "Philippines"],
                status=mode,
                author_slug=author_slug,
            )
            log.info("Digest: created post %s (slug=%s)", post["id"], slug)
    except Exception as exc:
        log.error("Digest: Ghost API error for %s: %s", slug, exc)

    return 0


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    from falconeye.config import get_db_path
    _db = get_db_path()
    run_digest(_db)
    print("Digest run complete.")
