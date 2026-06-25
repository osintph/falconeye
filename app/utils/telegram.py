import re
from urllib.parse import urlparse

CHANNEL_RE = re.compile(r"^[a-zA-Z0-9_]{4,32}$")

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
BTC_PATTERN = re.compile(r'\b(?:bc1[a-z0-9]{8,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
ETH_PATTERN = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
TRC20_PATTERN = re.compile(r'\bT[A-Za-z1-9]{33}\b')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
PH_PHONE_PATTERN = re.compile(r'(?:\+?63|0)9\d{9}\b')
INTL_PHONE_PATTERN = re.compile(r'\+\d{1,3}[\s-]?\d{6,14}\b')
ACCOUNT_PATTERN = re.compile(r'\b\d{10,16}\b')

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


def normalize_channel(raw: str) -> str | None:
    """
    Accept any of:
      - @channelname
      - channelname
      - https://t.me/channelname
      - https://t.me/s/channelname
      - t.me/channelname
    Returns the canonical channel name or None if invalid.
    """
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

    raw = raw.split("/")[0]
    raw = raw.strip().lstrip("@")

    if not raw or not CHANNEL_RE.match(raw):
        return None

    return raw


def extract_iocs(text: str) -> dict:
    """Pull IOCs out of a single message body."""
    urls = list(set(URL_PATTERN.findall(text)))
    btc = list(set(BTC_PATTERN.findall(text)))
    eth = list(set(ETH_PATTERN.findall(text)))
    trc20 = list(set(TRC20_PATTERN.findall(text)))
    emails = list(set(EMAIL_PATTERN.findall(text)))

    ph_phones = list(set(PH_PHONE_PATTERN.findall(text)))
    intl_phones_raw = list(set(INTL_PHONE_PATTERN.findall(text)))
    intl_phones = [p for p in intl_phones_raw if not any(p.endswith(ph[-10:]) for ph in ph_phones)]

    accounts_raw = ACCOUNT_PATTERN.findall(text)
    all_phone_digits = set()
    for p in ph_phones + intl_phones:
        digits = re.sub(r'\D', '', p)
        all_phone_digits.add(digits[-10:])
    accounts = [a for a in accounts_raw if a[-10:] not in all_phone_digits]
    accounts = list(set(accounts))

    return {
        "urls": urls,
        "crypto_btc": btc,
        "crypto_eth": eth,
        "crypto_trc20": trc20,
        "emails": emails,
        "phones_ph": ph_phones,
        "phones_intl": intl_phones,
        "possible_accounts": accounts,
    }


def detect_brands(text: str) -> list[str]:
    """Return list of brand keywords mentioned in text."""
    text_lower = text.lower()
    matched = []
    for brand, keywords in BRAND_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            matched.append(brand)
    return matched


def aggregate_iocs(messages: list[dict]) -> dict:
    """Aggregate IOCs across all messages, deduplicated."""
    agg = {
        "urls": set(),
        "crypto_btc": set(),
        "crypto_eth": set(),
        "crypto_trc20": set(),
        "emails": set(),
        "phones_ph": set(),
        "phones_intl": set(),
        "possible_accounts": set(),
        "brands": set(),
    }
    for msg in messages:
        for key in ["urls", "crypto_btc", "crypto_eth", "crypto_trc20",
                    "emails", "phones_ph", "phones_intl", "possible_accounts"]:
            agg[key].update(msg.get("iocs", {}).get(key, []))
        agg["brands"].update(msg.get("brands", []))
    return {k: sorted(v) for k, v in agg.items()}
