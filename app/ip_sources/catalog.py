"""
The single list of upstreams an IP lookup consults.

Before v3.33.4 this was written out by hand in four places and had drifted: the
tab intro named five sources, the in-tab privacy note named nine, the home page
feature card said "Shodan and GreyNoise", and the privacy policy table named
nine in a different order. A visitor could not tell from the page where their
IP was actually sent, which is precisely what a privacy note is for.

Both the tab copy and the privacy policy are now rendered from this list, so
they cannot disagree. Adding a source means adding it here and nowhere else.
"""

# The five keyed sources that produce the consensus verdict. Order matches
# app.ip_sources.reputation._NAMES.
REPUTATION_SOURCES = (
    {"key": "abuseipdb", "label": "AbuseIPDB", "env": "ABUSEIPDB_KEY"},
    {"key": "virustotal", "label": "VirusTotal", "env": "VT_KEY"},
    {"key": "otx", "label": "AlienVault OTX", "env": "OTX_API_KEY"},
    {"key": "censys", "label": "Censys", "env": "CENSYS_PAT"},
    {"key": "threatfox", "label": "ThreatFox", "env": "ABUSECH_AUTH_KEY"},
)

# Keyless upstreams the same lookup also queries. They do not vote on the
# verdict, but the IP is still sent to them, so the privacy note must say so.
SUPPORTING_SOURCES = (
    {"key": "shodan", "label": "Shodan InternetDB / CVEDB", "env": None},
    {"key": "greynoise", "label": "GreyNoise", "env": "GREYNOISE_API_KEY"},
    {"key": "ripestat", "label": "RIPEstat", "env": None},
    {"key": "urlhaus", "label": "URLhaus", "env": "ABUSECH_AUTH_KEY"},
)

ALL_SOURCES = REPUTATION_SOURCES + SUPPORTING_SOURCES


def _join(labels) -> str:
    """"a, b and c", the way the page reads it."""
    labels = list(labels)
    if len(labels) <= 1:
        return labels[0] if labels else ""
    return ", ".join(labels[:-1]) + " and " + labels[-1]


def reputation_labels() -> str:
    """The five verdict sources, for the tab intro."""
    return _join(s["label"] for s in REPUTATION_SOURCES)


def all_labels() -> str:
    """Every upstream the IP is sent to, for the privacy copy."""
    return _join(s["label"] for s in ALL_SOURCES)
