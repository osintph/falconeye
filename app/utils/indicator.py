import re

SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def classify_indicator(raw: str) -> tuple[str | None, str | None]:
    """
    Returns (type, normalized_value).
    Type is one of: 'sha256', 'sha1', 'md5', 'url', or None if unrecognized.
    """
    if not raw:
        return None, None
    raw = raw.strip()

    if URL_RE.match(raw):
        return "url", raw
    if SHA256_RE.match(raw):
        return "sha256", raw.lower()
    if SHA1_RE.match(raw):
        return "sha1", raw.lower()
    if MD5_RE.match(raw):
        return "md5", raw.lower()

    return None, None
