"""
Per-hop geolocation for the Route Map tab: this instance's sources, the
routemap package's engine.

The physics bound, the source order and the hop annotations moved to
``routemap_engine.geo`` in v3.36.0; read that module's docstring for the
derivation of the bound and why each annotation exists. Every public name is
re-exported here so the routes, the Atlas client and the tests keep reading
``geo.<name>``.

What stays here is the wiring: the IP database call carries this instance's
User-Agent and timeout, Hoiho goes through ``app.routemap.hoiho`` (this
instance's config and database cache), and the per-source budgets are module
attributes. :func:`sources` reads all of them at call time, so patching any
name in this module changes the next trace, which is what the tests rely on.
"""
from __future__ import annotations

from routemap_engine import geo as _engine
from routemap_engine.geo import (  # noqa: F401 - re-exported for callers
    ANNOT_ASYMMETRIC, ANNOT_ICMP_LIMIT, ANNOT_LOCAL, ANNOT_NO_ICMP, ANNOT_RTT_IMPOSSIBLE,
    INFLATION_ABS_MS, INFLATION_FACTOR, IP_DB_CONCURRENCY, KM_PER_MS_ROUND_TRIP,
    REVERSE_DNS_CONCURRENCY, REVERSE_DNS_MAX, REVERSE_DNS_TIMEOUT, RIPESTAT_GEO, SLACK_KM,
    SOURCE_HOIHO, SOURCE_IP_DB, SOURCE_LOCAL, SOURCE_SITE_CODE, SOURCE_UNRESOLVED,
    Sources, annotate, classify_address, first_located, haversine_km, is_sentinel,
    locate_hops, max_distance_km, reverse_dns, rtt_allows)

from app.config import HTTPX_TIMEOUT, OPERATOR_CONTACT_UA
from app.routemap import hoiho
from app.routemap.parse import Hop

USER_AGENT = f"FalconEye/3.35 ({OPERATOR_CONTACT_UA}; traceroute geolocation)"

# Hard ceilings on each source. See routemap_engine.geo for why each has the
# value it has; they are here so an operator (or a test) can change them.
HOIHO_BUDGET_SECONDS = _engine.HOIHO_BUDGET_SECONDS
IP_DB_BUDGET_SECONDS = _engine.IP_DB_BUDGET_SECONDS
REVERSE_DNS_BUDGET_SECONDS = _engine.REVERSE_DNS_BUDGET_SECONDS


async def ip_geolocate(addresses: list[str]) -> dict:
    """Geolocate public addresses through RIPEstat. Never raises."""
    return await _engine.ip_geolocate(addresses, user_agent=USER_AGENT, timeout=HTTPX_TIMEOUT)


def sources() -> Sources:
    """This instance's sources, read now. Hoiho honours HOIHO_ENABLED itself."""
    return Sources(hoiho=hoiho.lookup, ip_db=ip_geolocate, ptr=reverse_dns,
                   hoiho_budget=HOIHO_BUDGET_SECONDS,
                   ip_db_budget=IP_DB_BUDGET_SECONDS,
                   ptr_budget=REVERSE_DNS_BUDGET_SECONDS)


async def resolve(hops: list[Hop], origin: tuple[float, float] | None) -> dict:
    """Locate and annotate a parsed trace with this instance's sources."""
    return await _engine.resolve(hops, origin, sources())
