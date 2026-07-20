"""
Shared types for the multi-source IP reputation feature (v3.9.0).

Every source module returns a normalized SourceResult with an explicit `state`
so one source failing (timeout, 429, 401, malformed, missing key) never blanks
the card or 500s the endpoint — the frontend renders each sub-card from its own
state. Source fetchers NEVER raise; they map failures onto a state.

These are fixed-host vendor APIs (like the existing Shodan/GreyNoise/RIPEstat
fetchers in ip_intel.py), so they use httpx directly rather than safe_fetch,
which is reserved for attacker-controlled URLs. The IP is validated public by
the caller before any of this runs.
"""
from dataclasses import asdict, dataclass, field

FETCH_TIMEOUT = 12.0
USER_AGENT = "FalconEye/3.9 (osintph.info; IP reputation)"

# state values
OK = "ok"
NO_KEY = "no_key"
QUOTA = "quota"
ERROR = "error"
NOT_FOUND = "not_found"


@dataclass
class SourceResult:
    source: str                 # "abuseipdb" | "virustotal" | "otx" | "censys" | "threatfox"
    ok: bool
    state: str                  # OK | NO_KEY | QUOTA | ERROR | NOT_FOUND
    data: dict = field(default_factory=dict)
    error: str | None = None
    country: str | None = None  # 2-letter code where available, for geo consensus

    def as_dict(self) -> dict:
        return asdict(self)
