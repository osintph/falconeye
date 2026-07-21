"""
Input normalization and IOC extraction for the Telegram Intelligence tab.

Accepts any of: @handle, bare handle, https://t.me/handle, https://t.me/s/handle,
t.me/handle. Unlike the old Channel Inspector, this covers users and bots too,
not just channels — Telegram usernames are namespace-shared across all entity
types, so the same normalization applies regardless of what the identifier
turns out to resolve to.
"""
import re
from urllib.parse import urlparse

IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9_]{4,32}$")

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
TME_LINK_PATTERN = re.compile(r'(?:https?://)?t\.me/(?:s/)?([a-zA-Z0-9_]{4,32})\b', re.IGNORECASE)
HANDLE_PATTERN = re.compile(r'(?<![\w.])@([a-zA-Z][a-zA-Z0-9_]{3,31})\b')
BTC_PATTERN = re.compile(r'\b(?:bc1[a-z0-9]{8,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
ETH_PATTERN = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
TRC20_PATTERN = re.compile(r'\bT[A-Za-z1-9]{33}\b')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
PH_PHONE_PATTERN = re.compile(r'(?:\+?63|0)9\d{9}\b')
INTL_PHONE_PATTERN = re.compile(r'\+\d{1,3}[\s-]?\d{6,14}\b')

BRAND_KEYWORDS = {
    "GCash": ["gcash", "g-cash"],
    "Maya": ["maya", "paymaya"],
    "BPI": ["bpi"],
    "BDO": ["bdo", "banco de oro"],
    "Landbank": ["landbank", "land bank"],
    "UnionBank": ["unionbank", "union bank"],
    "RCBC": ["rcbc"],
    "Metrobank": ["metrobank"],
    "Binance": ["binance"],
    "USDT": ["usdt", "tether"],
    "TRX": ["trx", "tron"],
    "PayPal": ["paypal"],
    "Wise": ["wise", "transferwise"],
}


def normalize_query(raw: str) -> str | None:
    """Accept @handle, bare handle, or any t.me URL form. Returns the canonical
    identifier (no @, no URL) or None if it doesn't look like a valid Telegram
    username at all."""
    if not raw:
        return None
    raw = raw.strip()

    if raw.startswith("@"):
        raw = raw[1:]

    if "t.me/" in raw.lower():
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        path = parsed.path.strip("/")
        if path.startswith("s/"):
            path = path[2:]
        raw = path.split("/")[0]

    raw = raw.split("/")[0].split("?")[0].split("#")[0]
    raw = raw.strip().lstrip("@")

    if not raw or not IDENTIFIER_RE.match(raw):
        return None

    return raw


def detect_brands(text: str) -> list[str]:
    text_lower = text.lower()
    return [brand for brand, kws in BRAND_KEYWORDS.items() if any(kw in text_lower for kw in kws)]


def extract_iocs(text: str, *, exclude_handle: str | None = None) -> dict:
    """Pull IOCs out of a blob of text (bio, description, or a message body).

    URLs and t.me links are kept in separate buckets — a t.me link is itself a
    pivot target back into this tab, distinct from a generic URL Expander pivot.
    The entity's own handle/canonical link is excluded from "other handles" /
    "other t.me links" so results don't just point back at themselves.
    """
    all_urls = list(set(URL_PATTERN.findall(text)))
    tme_handles = set(m.lower() for m in TME_LINK_PATTERN.findall(text))
    handle_mentions = set(m.lower() for m in HANDLE_PATTERN.findall(text))
    if exclude_handle:
        tme_handles.discard(exclude_handle.lower())
        handle_mentions.discard(exclude_handle.lower())
    other_handles = sorted(tme_handles | handle_mentions)

    urls = [u for u in all_urls if "t.me/" not in u.lower()]
    tme_links = sorted({f"https://t.me/{h}" for h in tme_handles})

    btc = list(set(BTC_PATTERN.findall(text)))
    eth = list(set(ETH_PATTERN.findall(text)))
    trc20 = list(set(TRC20_PATTERN.findall(text)))
    emails = list(set(EMAIL_PATTERN.findall(text)))

    ph_phones = list(set(PH_PHONE_PATTERN.findall(text)))
    intl_phones_raw = list(set(INTL_PHONE_PATTERN.findall(text)))
    intl_phones = [p for p in intl_phones_raw if not any(p.endswith(ph[-10:]) for ph in ph_phones)]

    return {
        "urls": urls,
        "telegram_links": tme_links,
        "telegram_handles": other_handles,
        "crypto_btc": btc,
        "crypto_eth": eth,
        "crypto_trc20": trc20,
        "emails": emails,
        "phones_ph": ph_phones,
        "phones_intl": intl_phones,
        "brands": detect_brands(text),
    }


def aggregate_iocs(text_blobs: list[str], *, exclude_handle: str | None = None) -> dict:
    """Extract + merge IOCs across several text blobs (bio + message bodies),
    deduplicated."""
    agg: dict = {
        "urls": set(), "telegram_links": set(), "telegram_handles": set(),
        "crypto_btc": set(), "crypto_eth": set(), "crypto_trc20": set(),
        "emails": set(), "phones_ph": set(), "phones_intl": set(), "brands": set(),
    }
    for blob in text_blobs:
        if not blob:
            continue
        found = extract_iocs(blob, exclude_handle=exclude_handle)
        for key, values in found.items():
            agg[key].update(values)
    return {k: sorted(v) for k, v in agg.items()}
