"""
Read-only acquisition of a phishing kit's victim-facing surface.

This is runkit.sh's sequence (index, assets, hashes, socket probe, console)
reimplemented with the guarded transport. The reference script used raw curl
because it was a standalone CLI; here every single outbound request goes
through app.utils.safe_fetch, which resolves once, rejects private and reserved
addresses, pins the connection to the validated IP, and revalidates every
redirect hop.

Nothing here executes kit code. Bundles are fetched as text and hashed. The
socket probe reads status codes only: no socket is opened, no frames are sent.

One caveat worth carrying: safe_fetch buffers the whole response body before
returning it, so the size caps below are enforced AFTER the transfer, not
during it. They stop an oversized bundle from reaching the analyzer; they do
not stop it from being downloaded.
"""

import hashlib
import logging
import re
from urllib.parse import urljoin, urlparse

from app.config import KIT_MAX_ASSETS, KIT_MAX_BUNDLE_BYTES
from app.scanner.rabbithunt_sig import KIT_UA, campaign_path, probe_socket as _probe_socket
from app.utils.safe_fetch import safe_fetch, SafeFetchError

log = logging.getLogger("falconeye.kit_acquire")

FETCH_TIMEOUT = 15.0

# A client-rendered shell is small and defers everything to a script tag. The
# near-empty body a plain fetch gets back is SPA behaviour, not evasion, and it
# is recorded as such rather than treated as a block.
SPA_MAX_SHELL_BYTES = 6000

_ASSET_RE = re.compile(r'(?P<attr>href|src)\s*=\s*"(?P<url>[^"]+\.(?:js|css))"', re.I)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*"(?P<url>[^"]+\.js)"', re.I)
_FRAMEWORK_RE = re.compile(
    r"__vite|/assets/|data-v-app|id=\"app\"|createApp|__NUXT__|__NEXT_DATA__|"
    r"ng-version|data-reactroot",
    re.I,
)


async def fetch_page(url: str) -> dict:
    """GET the landing page. Returns page metadata plus the body.

    Never raises: a blocked or unreachable target comes back with `error` set
    so the report can still render everything else.
    """
    out = {
        "url": url,
        "status": None,
        "server": "",
        "set_cookie": "",
        "session_cookie": "",
        "content_type": "",
        "body": "",
        "size_bytes": 0,
        "error": None,
        "blocked": False,
    }
    try:
        resp = await safe_fetch(url, headers={"User-Agent": KIT_UA}, timeout=FETCH_TIMEOUT)
    except SafeFetchError as exc:
        out["error"] = f"blocked by SSRF guard: {exc}"
        out["blocked"] = True
        return out
    except Exception as exc:
        out["error"] = f"fetch failed: {type(exc).__name__}"
        return out

    headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    body = resp.get("body", "") or ""
    out["status"] = resp.get("status")
    out["server"] = headers.get("server", "")
    out["content_type"] = headers.get("content-type", "")
    out["set_cookie"] = headers.get("set-cookie", "")
    out["body"] = body
    out["size_bytes"] = len(body.encode("utf-8", "replace"))
    out["url_final"] = resp.get("url_final", url)

    m = re.search(r"\b(_vt|_ga|PHPSESSID|session)=([^;]{1,80})", out["set_cookie"])
    if m:
        out["session_cookie"] = f"{m.group(1)}={m.group(2)}"
    return out


def is_spa(body: str) -> dict:
    """Detect a client-rendered SPA shell.

    Returns the verdict plus why, because "the body looked empty" is exactly
    the observation that gets misread as evasion.
    """
    if not body:
        return {"spa": False, "reason": "empty response", "shell_bytes": 0}

    size = len(body.encode("utf-8", "replace"))
    has_script = bool(_SCRIPT_SRC_RE.search(body))
    has_marker = bool(_FRAMEWORK_RE.search(body))
    text = re.sub(r"<script[^>]*>.*?</script>", " ", body, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    visible = len(re.sub(r"\s+", " ", text).strip())

    spa = bool(size < SPA_MAX_SHELL_BYTES and has_script and (has_marker or visible < 200))
    if spa:
        reason = (f"{size}B shell, script-tag entry bundle, {visible} chars of "
                  "visible text: client-rendered, not a block")
    elif has_script and has_marker:
        spa = True
        reason = f"{size}B body with SPA framework markers and a script entry point"
    else:
        reason = f"{size}B body, {visible} chars of visible text: server-rendered"

    return {"spa": spa, "reason": reason, "shell_bytes": size}


def extract_assets(body: str, base: str) -> list:
    """Every .js/.css reference, absolutized against `base`.

    The entry bundle is the one referenced as a script src, which is what the
    analyzer gets pointed at.
    """
    entry_urls = set()
    for m in _SCRIPT_SRC_RE.finditer(body or ""):
        try:
            entry_urls.add(urljoin(base, m.group("url")))
        except Exception:
            continue

    assets = []
    seen = set()
    for m in _ASSET_RE.finditer(body or ""):
        raw = m.group("url")
        try:
            absolute = urljoin(base, raw)
        except Exception:
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        name = parsed.path.rsplit("/", 1)[-1] or absolute
        assets.append({
            "name": name,
            "url": absolute,
            "ref": raw,
            "kind": "css" if name.lower().endswith(".css") else "js",
            "entry": absolute in entry_urls,
        })

    # Entry bundle first, then the remaining JS, then CSS.
    assets.sort(key=lambda a: (not a["entry"], a["kind"] != "js", a["name"]))
    return assets


async def fetch_bundles(assets: list, referer: str = "") -> list:
    """Fetch each JS asset, size-capped, keeping text and sha256.

    Bundle text is kept in memory for the analyzer and is never returned to a
    client or sent to an LLM.
    """
    headers = {"User-Agent": KIT_UA}
    if referer:
        headers["Referer"] = referer

    out = []
    js_assets = [a for a in assets if a["kind"] == "js"][:KIT_MAX_ASSETS]
    for asset in js_assets:
        entry = {
            "name": asset["name"],
            "url": asset["url"],
            "entry": asset["entry"],
            "sha256": "",
            "size_bytes": 0,
            "text": "",
            "error": None,
        }
        try:
            resp = await safe_fetch(asset["url"], headers=headers, timeout=FETCH_TIMEOUT)
        except SafeFetchError as exc:
            entry["error"] = f"blocked by SSRF guard: {exc}"
            out.append(entry)
            continue
        except Exception as exc:
            entry["error"] = f"fetch failed: {type(exc).__name__}"
            out.append(entry)
            continue

        if resp.get("status") != 200:
            entry["error"] = f"HTTP {resp.get('status')}"
            out.append(entry)
            continue

        body = resp.get("body", "") or ""
        raw = body.encode("utf-8", "replace")
        entry["size_bytes"] = len(raw)
        entry["sha256"] = hashlib.sha256(raw).hexdigest()
        if len(raw) > KIT_MAX_BUNDLE_BYTES:
            entry["error"] = (f"bundle too large: {len(raw)} bytes exceeds the "
                              f"{KIT_MAX_BUNDLE_BYTES} byte cap, not analyzed")
        else:
            entry["text"] = body
        out.append(entry)
    return out


async def probe_socket(host: str, path: str = "/") -> dict:
    """Path-scoped socket.io probe. See rabbithunt_sig.probe_socket."""
    return await _probe_socket(host, path)


async def acquire(url: str, page: dict | None = None) -> dict:
    """Run the whole acquisition sequence for one URL.

    Order matches runkit.sh: index, assets, bundle hashes, socket probe. Pass
    `page` to reuse a landing fetch the caller already did, so a report does
    not request the index twice.
    """
    if page is None:
        page = await fetch_page(url)
    parsed = urlparse(page.get("url_final", url) or url)
    host = parsed.hostname or ""
    path = campaign_path(page.get("url_final", url) or url)

    spa = is_spa(page["body"])
    base = page.get("url_final", url) or url
    assets = extract_assets(page["body"], base)
    bundles = await fetch_bundles(assets, referer=base)
    probe = await probe_socket(host, path) if host else {}

    return {
        "page": page,
        "host": host,
        "campaign_path": path,
        "spa": spa,
        "assets": assets,
        "bundles": bundles,
        "socket_probe": probe,
    }


def entry_bundle(bundles: list) -> dict | None:
    """The bundle to analyze: the script-src entry, else the largest fetched."""
    usable = [b for b in bundles if b.get("text")]
    if not usable:
        return None
    for b in usable:
        if b.get("entry"):
            return b
    return max(usable, key=lambda b: b.get("size_bytes", 0))
