"""
Parse the vendored WhatsMyName (WMN) and Sherlock data files into one unified
internal site list.

Both are static MIT-licensed JSON files under app/data/. We do not depend on
either project's runtime code — we vendor the data and drive our own checker
(app/username/checker.py).

Design decisions taken here (per the v3.8.0 runbook, which left them to us):
  * NSFW: WMN cat == "xx NSFW xx" or Sherlock isNSFW == true. Excluded unless
    the caller opts in.
  * Priority (Quick Scan = priority 2 and 3): 3 = the ~30 highest-yield
    platforms (prefix-matched because WMN suffixes names, e.g. "GitHub (User)");
    2 = mid-tier developer / gaming / forum; 1 = everything else.

Nothing in this module raises on bad data — a malformed file yields [].
"""
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("falconeye.username")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
WMN_PATH = DATA_DIR / "whatsmyname" / "wmn-data.json"
SHERLOCK_PATH = DATA_DIR / "sherlock" / "data.json"

WMN_NSFW_CAT = "xx NSFW xx"


@dataclass
class Site:
    name: str
    url_template: str          # contains {account} / {username} / {}
    category: str              # Social | Developer | Gaming | Forum | Regional | Adult | Other
    detection: dict            # engine-specific keys (see checker.py)
    sources: list              # ["wmn"], ["sherlock"], or ["wmn", "sherlock"]
    is_nsfw: bool
    priority: int              # 1..3, higher = more likely to yield useful hits


# ---- categorisation ----

_WMN_CAT_MAP = {
    "social": "Social", "dating": "Social", "blog": "Social",
    "coding": "Developer", "tech": "Developer",
    "gaming": "Gaming",
    WMN_NSFW_CAT: "Adult",
}
_FORUM_KW = ("forum", "reddit", "board", "vbulletin", "4chan", "discourse")
_REGIONAL_KW = ("weibo", "vk", "qq", "wechat", "line", "naver", "douban", "renren", "odnoklassniki")
_DEV_KW = ("git", "stack", "code", "dev", "npm", "pypi", "docker", "replit", "hack", "kaggle", "leetcode")
_GAMING_KW = ("game", "gaming", "steam", "xbox", "playstation", "psn", "twitch", "osu", "speedrun", "chess")


def _norm_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


# Highest-yield platforms → priority 3. Prefix match because WMN names carry
# suffixes ("GitHub (User)", "YouTube Channel"). Short/ambiguous tokens are exact.
_P3_PREFIX = (
    "github", "gitlab", "bitbucket", "reddit", "instagram", "telegram", "tiktok",
    "youtube", "facebook", "twitch", "steam", "pinterest", "medium", "tumblr",
    "snapchat", "spotify", "soundcloud", "patreon", "mastodon", "stackoverflow",
    "hackernews", "vimeo", "flickr", "keybase", "replit", "producthunt", "quora",
    "pastebin", "gravatar", "twitter", "wordpress", "devto", "linktree",
)
_P3_EXACT = {"x", "vk", "npm"}


def _is_priority3(name: str) -> bool:
    n = _norm_name(name)
    if n in _P3_EXACT:
        return True
    return any(n.startswith(tok) for tok in _P3_PREFIX)


def _assign_priority(name: str, category: str) -> int:
    if _is_priority3(name):
        return 3
    if category in ("Developer", "Gaming", "Forum"):
        return 2
    return 1


def _keyword_category(name: str, host: str, default: str) -> str:
    blob = f"{name} {host}".lower()
    if any(k in blob for k in _FORUM_KW):
        return "Forum"
    if any(k in blob for k in _REGIONAL_KW):
        return "Regional"
    if any(k in blob for k in _DEV_KW):
        return "Developer"
    if any(k in blob for k in _GAMING_KW):
        return "Gaming"
    return default


def _host_key(url_template: str) -> str:
    """Normalized host of a template, ignoring the username placeholder.

    'https://{account}.medium.com/' -> 'medium.com'
    'https://github.com/{account}'  -> 'github.com'
    """
    stripped = (url_template or "")
    for ph in ("{account}", "{username}", "{}"):
        stripped = stripped.replace(ph, "")
    host = (urlparse(stripped).hostname or "").lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


# ---- adapters ----

def load_wmn(path: Path = WMN_PATH) -> list:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("username: failed to load WMN data (%s): %s", path, exc)
        return []
    sites_raw = raw.get("sites") if isinstance(raw, dict) else raw
    if not isinstance(sites_raw, list):
        return []

    out = []
    for s in sites_raw:
        if not isinstance(s, dict):
            continue
        name = s.get("name")
        uri = s.get("uri_check") or s.get("uri_pretty")
        if not name or not uri or ("{account}" not in uri and "{username}" not in uri):
            continue
        cat_raw = s.get("cat", "")
        is_nsfw = cat_raw == WMN_NSFW_CAT
        category = _WMN_CAT_MAP.get(cat_raw)
        if category is None:
            category = _keyword_category(name, _host_key(uri), "Other")
        detection = {
            "engine": "wmn",
            "e_code": s.get("e_code"),
            "e_string": s.get("e_string") or "",
            "m_code": s.get("m_code"),
            "m_string": s.get("m_string") or "",
            "known": s.get("known") or [],
        }
        out.append(Site(
            name=name, url_template=uri, category=category, detection=detection,
            sources=["wmn"], is_nsfw=is_nsfw,
            priority=_assign_priority(name, category),
        ))
    return out


def load_sherlock(path: Path = SHERLOCK_PATH) -> list:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("username: failed to load Sherlock data (%s): %s", path, exc)
        return []
    if not isinstance(raw, dict):
        return []

    out = []
    for name, s in raw.items():
        if name.startswith("$") or not isinstance(s, dict):
            continue
        url = s.get("url")
        if not url or "{}" not in url:
            continue
        is_nsfw = bool(s.get("isNSFW"))
        category = _keyword_category(name, _host_key(url), "Social")
        if is_nsfw:
            category = "Adult"
        detection = {
            "engine": "sherlock",
            "errorType": s.get("errorType"),
            "errorMsg": s.get("errorMsg"),
            "errorCode": s.get("errorCode"),
            "errorUrl": s.get("errorUrl"),
            "regexCheck": s.get("regexCheck"),
            "known": [s["username_claimed"]] if s.get("username_claimed") else [],
        }
        out.append(Site(
            name=name, url_template=url, category=category, detection=detection,
            sources=["sherlock"], is_nsfw=is_nsfw,
            priority=_assign_priority(name, category),
        ))
    return out


def merge_sites(wmn_sites: list, sherlock_sites: list) -> list:
    """Keep all WMN sites; append Sherlock-only sites; tag cross-engine overlaps
    as dual-source (WMN detection preferred, per the runbook)."""
    anchor_by_host = {}
    for s in wmn_sites:
        anchor_by_host.setdefault(_host_key(s.url_template), s)

    merged = list(wmn_sites)
    for s in sherlock_sites:
        anchor = anchor_by_host.get(_host_key(s.url_template))
        if anchor is not None:
            if "sherlock" not in anchor.sources:
                anchor.sources.append("sherlock")
        else:
            merged.append(s)
    return merged


def load_all(sherlock: bool = True) -> list:
    wmn = load_wmn()
    sher = load_sherlock() if sherlock else []
    return merge_sites(wmn, sher)


# ---- cached singleton ----

_SITES = None


def get_all_sites() -> list:
    global _SITES
    if _SITES is None:
        _SITES = load_all()
        log.info("username: loaded %d sites", len(_SITES))
    return _SITES


def select_sites(scope: str, include_nsfw: bool) -> list:
    """Filter the cached site list by scan scope and NSFW opt-in.

    Quick = priority 2 and 3; Full = all priorities.
    """
    sites = get_all_sites()
    min_priority = 2 if scope == "quick" else 1
    out = []
    for s in sites:
        if s.priority < min_priority:
            continue
        if s.is_nsfw and not include_nsfw:
            continue
        out.append(s)
    return out
