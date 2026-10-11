"""The single list of sources a Phishing Hunt consults, for the tab copy and the
privacy policy, mirroring app/ip_sources/catalog.py. No em dashes."""
from app import config

_BASE = ("crt.sh", "dnstwist permutations", "urlscan.io", "URLhaus")


def _join(labels) -> str:
    labels = list(labels)
    if len(labels) <= 1:
        return labels[0] if labels else ""
    return ", ".join(labels[:-1]) + " and " + labels[-1]


def discovery_labels() -> str:
    labels = list(_BASE)
    if config.HUNT_NRD_URL:
        labels.append("a newly registered domain feed")
    return _join(labels)
