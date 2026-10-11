"""The single list of upstreams an ASM run consults.

Same pattern as app/ip_sources/catalog.py: the tab intro and the privacy policy
are both rendered from this list so they cannot drift apart. A source switched
off on this instance is left out of the "sources used" copy because the domain's
data is never sent to it.

No em dashes in this module.
"""
from app import config

# Passive discovery and active probe sources that are always on (free, keyless or
# low-key). These are named in the tab intro.
DISCOVERY_SOURCES = (
    {"key": "crtsh", "label": "crt.sh"},
    {"key": "certspotter", "label": "Cert Spotter"},
    {"key": "mnemonic", "label": "Mnemonic passive DNS"},
    {"key": "wayback", "label": "the Wayback Machine"},
    {"key": "ripestat", "label": "RIPEstat"},
)

# Optional enrichment sources, each behind its own flag. Off by default.
ENRICHMENT_SOURCES = (
    {"key": "shodan", "label": "Shodan", "enabled": lambda: config.SHODAN_ENABLED},
    {"key": "censys", "label": "Censys", "enabled": lambda: config.CENSYS_ENABLED},
    {"key": "brightdata", "label": "Bright Data", "enabled": lambda: config.BRIGHTDATA_ENABLED},
)

ALL_SOURCES = DISCOVERY_SOURCES + ENRICHMENT_SOURCES


def _is_enabled(source: dict) -> bool:
    gate = source.get("enabled")
    if gate is None:
        return True
    try:
        return bool(gate())
    except Exception:  # noqa: BLE001 - a broken gate must not blank the page
        return True


def _join(labels) -> str:
    labels = list(labels)
    if len(labels) <= 1:
        return labels[0] if labels else ""
    return ", ".join(labels[:-1]) + " and " + labels[-1]


def discovery_labels() -> str:
    """The always-on discovery sources, for the tab intro."""
    return _join(s["label"] for s in DISCOVERY_SOURCES)


def all_labels() -> str:
    """Every upstream a scan sends the domain to on this instance, for the privacy
    copy."""
    return _join(s["label"] for s in ALL_SOURCES if _is_enabled(s))
