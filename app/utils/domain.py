import re
from urllib.parse import urlparse

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


def normalize_domain(raw: str) -> str | None:
    """
    Normalize a user-supplied domain. Returns None if invalid.
    Strips protocol, path, port, query string, leading www, and trailing dot.
    """
    if not raw:
        return None

    raw = raw.strip().lower()

    # Strip protocol
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or ""

    # Strip path/port/query manually if not parsed above
    raw = raw.split("/")[0].split(":")[0].split("?")[0].split("#")[0]

    # Strip leading www.
    if raw.startswith("www."):
        raw = raw[4:]

    # Strip trailing dot
    raw = raw.rstrip(".")

    if not raw or not DOMAIN_RE.match(raw):
        return None

    return raw


def extract_tld(domain: str) -> str:
    """Return the TLD portion of a domain. For 'sub.example.co.uk' returns 'uk'."""
    return domain.rsplit(".", 1)[-1] if "." in domain else ""
