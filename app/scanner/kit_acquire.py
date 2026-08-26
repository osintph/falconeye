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
from app.scanner.scope import OutOfScope, in_scope, registrable, require_in_scope
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


# Two request profiles, and no more. A cloaking kit decides what to serve from
# what the request looks like, so one profile can only ever report what that one
# profile saw. Two is enough to make divergence visible; a profile matrix turns
# one report into a fetch campaign against the target.
#
# `bare` is what the scanner has always sent, kept as the baseline so divergence
# is measured against current behaviour. `browser` is what a phone tapping a
# link out of a chat app sends.
PROFILE_BARE = "bare"
PROFILE_BROWSER = "browser"

_BROWSER_UA = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like "
    "Gecko) Chrome/131.0.6778.104 Mobile Safari/537.36"
)

PROFILE_HEADERS = {
    PROFILE_BARE: {
        "User-Agent": KIT_UA,
    },
    PROFILE_BROWSER: {
        "User-Agent": _BROWSER_UA,
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "image/avif,image/webp,*/*;q=0.8"),
        "Accept-Language": "en-PH,en;q=0.9",
        "Referer": "https://l.facebook.com/",
        "Sec-Ch-Ua": '"Chromium";v="131", "Not_A Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?1",
        "Sec-Ch-Ua-Platform": '"Android"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
}


async def fetch_page(url: str, profile: str = PROFILE_BARE) -> dict:
    """GET the landing page under one request profile.

    Returns page metadata plus the body. Never raises: a blocked or unreachable
    target comes back with `error` set so the report can still render
    everything else.

    `final_url`, `final_host` and `redirect_chain` record where the fetch ended
    up. They are informational. Nothing may derive a lookup target from them,
    because a cloaking kit chooses them. The case host comes from `url`, which
    is what the operator submitted, and from nowhere else.
    """
    submitted_host = (urlparse(url).hostname or "").lower()
    out = {
        "url": url,
        "profile": profile,
        "status": None,
        "server": "",
        "set_cookie": "",
        "session_cookie": "",
        "content_type": "",
        "body": "",
        "size_bytes": 0,
        "sha256": "",
        "error": None,
        "blocked": False,
        "url_final": url,
        "final_host": submitted_host,
        "redirect_chain": [],
        "scope_left": False,
    }
    headers = dict(PROFILE_HEADERS.get(profile) or PROFILE_HEADERS[PROFILE_BARE])
    try:
        resp = await safe_fetch(url, headers=headers, timeout=FETCH_TIMEOUT)
    except SafeFetchError as exc:
        out["error"] = f"blocked by SSRF guard: {exc}"
        out["blocked"] = True
        return out
    except Exception as exc:
        out["error"] = f"fetch failed: {type(exc).__name__}"
        return out

    headers_in = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    body = resp.get("body", "") or ""
    raw = body.encode("utf-8", "replace")
    out["status"] = resp.get("status")
    out["server"] = headers_in.get("server", "")
    out["content_type"] = headers_in.get("content-type", "")
    out["set_cookie"] = headers_in.get("set-cookie", "")
    out["body"] = body
    out["size_bytes"] = len(raw)
    out["sha256"] = hashlib.sha256(raw).hexdigest()
    out["url_final"] = resp.get("url_final", url)
    out["redirect_chain"] = resp.get("redirect_chain", []) or []
    out["final_host"] = (urlparse(out["url_final"]).hostname or "").lower()
    out["scope_left"] = not in_scope(out["final_host"], registrable(submitted_host))

    m = re.search(r"\b(_vt|_ga|PHPSESSID|session)=([^;]{1,80})", out["set_cookie"])
    if m:
        out["session_cookie"] = f"{m.group(1)}={m.group(2)}"
    return out


def profile_meta(page: dict) -> dict:
    """The side-by-side row for one profile. No body, just what it did."""
    return {
        "profile": page.get("profile"),
        "status": page.get("status"),
        "final_url": page.get("url_final"),
        "final_host": page.get("final_host"),
        "size_bytes": page.get("size_bytes"),
        "sha256": page.get("sha256"),
        "scope_left": page.get("scope_left"),
        "redirect_chain": page.get("redirect_chain"),
        "error": page.get("error"),
    }


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


def extract_assets(body: str, base: str, case_registrable: str = "") -> list:
    """Every .js/.css reference, absolutized against `base`.

    The entry bundle is the one referenced as a script src, which is what the
    analyzer gets pointed at.

    Each asset is marked `in_scope`. Pass `case_registrable` and anything hosted
    elsewhere is kept for the record but never fetched: a page that redirected
    the scanner to a third party lists that third party's assets, and pulling
    them would be a second wave of out-of-scope requests behind the first.
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
            "host": (parsed.hostname or "").lower(),
            "kind": "css" if name.lower().endswith(".css") else "js",
            "entry": absolute in entry_urls,
            "in_scope": in_scope(parsed.hostname or "", case_registrable)
                        if case_registrable else True,
        })

    # Entry bundle first, then the remaining JS, then CSS.
    assets.sort(key=lambda a: (not a["entry"], a["kind"] != "js", a["name"]))
    return assets


async def fetch_bundles(assets: list, referer: str = "", case_registrable: str = "",
                        profile: str = PROFILE_BARE, case_id: str = "") -> list:
    """Fetch each in-scope JS asset, size-capped, keeping text and sha256.

    Bundle text is kept in memory for the analyzer and is never returned to a
    client or sent to an LLM.

    An asset outside `case_registrable` is recorded as refused and no request is
    made for it.
    """
    headers = dict(PROFILE_HEADERS.get(profile) or PROFILE_HEADERS[PROFILE_BARE])
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
        if case_registrable:
            try:
                require_in_scope(asset.get("host", ""), case_registrable,
                                 what="bundle fetch", case_id=case_id)
            except OutOfScope as exc:
                entry["error"] = f"not fetched: {exc}"
                out.append(entry)
                continue
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


async def probe_socket(host: str, path: str, case_registrable: str,
                       case_id: str = "") -> dict:
    """Path-scoped socket.io probe, refused outside the case domain.

    `case_registrable` is mandatory and positional on purpose. The probe fires
    five unsolicited requests hunting for an operator console, which is exactly
    the traffic that must never land on a host that is not the subject of the
    case. Raises OutOfScope before any request is issued.
    """
    require_in_scope(host, case_registrable, what="socket probe", case_id=case_id)
    return await _probe_socket(host, path)


def page_from_html(url: str, html: str) -> dict:
    """A page dict built from operator-supplied HTML rather than a fetch.

    For a target that is geofenced or otherwise unreachable from wherever
    FalconEye runs. The operator can see the page; the scanner cannot. The case
    identity still comes from `url`, so enrichment and scope are unchanged, and
    the body is marked as supplied so no part of the report claims to have
    fetched it.
    """
    raw = (html or "").encode("utf-8", "replace")
    submitted_host = (urlparse(url).hostname or "").lower()
    return {
        "url": url,
        "profile": "supplied",
        "status": None,
        "server": "",
        "set_cookie": "",
        "session_cookie": "",
        "content_type": "text/html (supplied)",
        "body": html or "",
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "error": None,
        "blocked": False,
        "url_final": url,
        "final_host": submitted_host,
        "redirect_chain": [],
        "scope_left": False,
        "supplied": True,
    }


async def acquire(url: str, page: dict | None = None, case_id: str = "",
                  supplied: bool = False) -> dict:
    """Run the whole acquisition sequence for one URL.

    Order matches runkit.sh: index, assets, bundle hashes, socket probe. Pass
    `page` to reuse a landing fetch the caller already did, so a report does
    not request the index twice.

    The case host is `url`'s host. It is not read from url_final, not from a
    canonical link, not from og:url, not from a base href, and not from the
    dominant asset host. All of those are chosen by whoever controls the page,
    which on a cloaking kit is the adversary. This is the assignment that sent a
    whole case report, and five console probes, at an impersonated brand's
    production infrastructure.

    Both request profiles are fetched. Analysis proceeds on whichever one stayed
    inside the submitted domain, preferring `browser`, because a kit that cloaks
    against the bare profile still serves the real thing to a phone.
    """
    submitted_host = (urlparse(url).hostname or "").lower()
    case_registrable = registrable(submitted_host)
    path = campaign_path(url)

    if supplied and page is not None:
        # The body was handed to us. Fetching the target again would only
        # re-acquire whatever it serves this vantage, which is the thing that
        # did not work.
        profiles = {"supplied": profile_meta(page)}
        divergence = False
        chosen = page
    else:
        if page is None:
            page = await fetch_page(url, profile=PROFILE_BARE)
        bare = page
        browser = await fetch_page(url, profile=PROFILE_BROWSER)

        profiles = {
            PROFILE_BARE: profile_meta(bare),
            PROFILE_BROWSER: profile_meta(browser),
        }
        divergence = _profiles_diverge(bare, browser)

        # Prefer a profile that stayed in scope. If both left, the caller takes
        # the out-of-scope path and nothing below it runs.
        if not browser.get("scope_left") and not browser.get("error"):
            chosen = browser
        elif not bare.get("scope_left") and not bare.get("error"):
            chosen = bare
        else:
            chosen = browser if not browser.get("error") else bare

    scope_left = bool(chosen.get("scope_left"))

    result = {
        "page": chosen,
        "profiles": profiles,
        "profile_used": chosen.get("profile"),
        "profile_divergence": divergence,
        "host": submitted_host,
        "registrable_domain": case_registrable,
        "campaign_path": path,
        "final_url": chosen.get("url_final"),
        "final_host": chosen.get("final_host"),
        "redirect_chain": chosen.get("redirect_chain") or [],
        "scope_left": scope_left,
        "spa": is_spa(chosen.get("body", "")),
        "assets": [],
        "bundles": [],
        "socket_probe": {},
    }

    if scope_left:
        # Stop here. No assets, no bundles, no probe. The body in hand belongs
        # to somebody else and every request built from it would too.
        log.warning(
            "kit acquisition left scope: case=%s submitted=%s final=%s case_domain=%s",
            case_id or "-", submitted_host, chosen.get("final_host"), case_registrable,
        )
        return result

    # urljoin base is the submitted URL, not url_final, so a same-domain
    # redirect cannot quietly repoint relative asset refs.
    base = chosen.get("url_final") or url
    assets = extract_assets(chosen.get("body", ""), base, case_registrable)
    result["assets"] = assets
    result["bundles"] = await fetch_bundles(
        assets, referer=base, case_registrable=case_registrable,
        profile=chosen.get("profile", PROFILE_BARE), case_id=case_id,
    )
    if submitted_host:
        try:
            result["socket_probe"] = await probe_socket(
                submitted_host, path, case_registrable, case_id=case_id)
        except OutOfScope as exc:
            log.warning("socket probe refused: %s", exc)
            result["socket_probe"] = {"error": str(exc)}
    return result


def _profiles_diverge(bare: dict, browser: dict) -> bool:
    """True when the two profiles were served different things.

    Different final host, or same host and a different body, both count. A kit
    that answers a scanner and a phone differently is cloaking, and that is the
    signal regardless of which mechanism it used.
    """
    if bare.get("error") or browser.get("error"):
        return False
    if bare.get("final_host") != browser.get("final_host"):
        return True
    return bool(bare.get("sha256") and browser.get("sha256")
                and bare["sha256"] != browser["sha256"])


def entry_bundle(bundles: list) -> dict | None:
    """The bundle to analyze: the script-src entry, else the largest fetched."""
    usable = [b for b in bundles if b.get("text")]
    if not usable:
        return None
    for b in usable:
        if b.get("entry"):
            return b
    return max(usable, key=lambda b: b.get("size_bytes", 0))
