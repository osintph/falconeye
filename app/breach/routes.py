"""
Breach Check API (Have I Been Pwned integration).

  POST /api/breach/email    Body: {"email": str}
  POST /api/breach/domain   Body: {"domain": str}
  GET  /api/breach/recent   5 most recently added breaches (no input)
  GET  /api/breach/all      Full HIBP breach corpus (no input)
  GET  /api/breach/dataclasses

Email and domain use POST + a JSON body (never a query string) specifically so
the address/domain never lands in an access log — nginx logs the request
line, not the body. Rate-limit hits on /email and /domain return HTTP 200 with
`{"rate_limited": true, ...}` (not 429) — a deliberate choice for this tab,
matching the testing contract, not the 429 raised by /api/abuse/lookup.

Pwned Passwords (K-anonymity) has NO endpoint here at all: the browser calls
api.pwnedpasswords.com directly so the password never reaches this server —
proxying it would break the one property that makes the check trustworthy.
"""
import asyncio
import logging
import re

import dns.resolver
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from slowapi import Limiter

from app.breach import client, store
from app.utils.client_ip import get_client_ip, get_client_ip_key
from app.utils.domain import normalize_domain

log = logging.getLogger("falconeye.breach")

router = APIRouter(prefix="/api/breach", tags=["breach"])
limiter = Limiter(key_func=get_client_ip_key)

# Basic RFC 5322 shape (mirrors app.abuse.lookup's EMAIL_RE) — a security
# boundary, not just UX: this value is path-embedded into the HIBP URL.
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

EMAIL_CACHE_TTL = 24 * 3600
DOMAIN_CACHE_TTL = 12 * 3600
ALL_BREACHES_TTL = 6 * 3600
LATEST_BREACH_TTL = 3600

EMAIL_IP_PER_HOUR = 5
EMAIL_IP_PER_DAY = 30
DOMAIN_IP_PER_HOUR = 5
DOMAIN_IP_PER_DAY = 30
EMAIL_GLOBAL_PER_DAY = 200
DOMAIN_GLOBAL_PER_DAY = 200
_HOUR = 3600
_DAY = 86400

_DNS_TIMEOUT = 5.0


class EmailCheckRequest(BaseModel):
    email: str


class DomainCheckRequest(BaseModel):
    domain: str


# ---------- shared helpers ----------

async def _get_breach_meta(name: str) -> dict | None:
    """Cache-first fetch of one breach's full metadata (indefinite TTL —
    breach details don't change)."""
    key = store.meta_cache_key(name)
    cached = store.get_cached(key, None)
    if cached is not None:
        return cached
    raw = await client.fetch_breach_metadata(name)
    if raw is None:
        return None
    shaped = client.shape_breach(raw)
    store.store_cached(key, shaped)
    return shaped


async def _enrich_names(names: list) -> list:
    results = await asyncio.gather(*[_get_breach_meta(n) for n in names if n])
    return [r for r in results if r]


def _warm_meta_cache(raw_breaches: list) -> None:
    """Opportunistically seed the per-breach metadata cache from a bulk fetch
    (all-breaches / latest-breach), so a later email/domain enrichment lookup
    for the same breach is a cache hit instead of a redundant free-endpoint call."""
    for raw in raw_breaches:
        name = (raw or {}).get("Name")
        if name:
            store.store_cached(store.meta_cache_key(name), client.shape_breach(raw))


def _resolve_hosting_ip_sync(domain: str):
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = _DNS_TIMEOUT
        resolver.timeout = _DNS_TIMEOUT
        answers = resolver.resolve(domain, "A")
        for rdata in answers:
            return str(rdata)
    except Exception:
        return None
    return None


async def _resolve_hosting_ip(domain: str):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _resolve_hosting_ip_sync, domain)


def _rate_limited(message: str) -> dict:
    return {"rate_limited": True, "error": message}


# ---------- email ----------

@router.post("/email")
@limiter.limit("10/minute")
async def check_email(req: EmailCheckRequest, request: Request):
    email = (req.email or "").strip()
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Invalid email address.")

    cache_key = store.email_cache_key(email)
    cached = store.get_cached(cache_key, EMAIL_CACHE_TTL)
    if cached is not None:
        return {**cached, "cache_hit": True, "rate_limited": False}

    client_ip = get_client_ip(request)
    if store.count_recent(f"email_ip:{client_ip}", _HOUR) >= EMAIL_IP_PER_HOUR:
        return _rate_limited(f"Email search limit reached ({EMAIL_IP_PER_HOUR} per hour). Try again later.")
    if store.count_recent(f"email_ip:{client_ip}", _DAY) >= EMAIL_IP_PER_DAY:
        return _rate_limited(f"Email search limit reached ({EMAIL_IP_PER_DAY} per day). Try again tomorrow.")
    if store.count_recent("email_global", _DAY) >= EMAIL_GLOBAL_PER_DAY:
        return _rate_limited("The service is at its global daily email-search capacity. Try again later.")
    store.record_event(f"email_ip:{client_ip}")
    store.record_event("email_global")

    try:
        raw_breaches, raw_pastes = await asyncio.gather(
            client.fetch_breached_account(email), client.fetch_paste_account(email),
        )
    except client.HibpError as exc:
        log.warning("breach: email lookup failed: %s", exc)
        raise HTTPException(status_code=502, detail="Have I Been Pwned lookup failed. Try again shortly.")

    names = [b.get("Name") for b in raw_breaches]
    breaches = await _enrich_names(names)
    breaches.sort(key=lambda b: (b.get("breach_date") or "", b.get("name") or ""))
    pastes = [client.shape_paste(p) for p in raw_pastes]

    dates = [b["breach_date"] for b in breaches if b.get("breach_date")]
    result = {
        "breach_count": len(breaches),
        "paste_count": len(pastes),
        "earliest_breach_date": min(dates) if dates else None,
        "latest_breach_date": max(dates) if dates else None,
        "password_exposed_count": sum(1 for b in breaches if "Passwords" in (b.get("data_classes") or [])),
        "breaches": breaches,
        "pastes": pastes,
    }
    store.store_cached(cache_key, result)
    return {**result, "cache_hit": False, "rate_limited": False}


# ---------- domain ----------

@router.post("/domain")
@limiter.limit("10/minute")
async def check_domain(req: DomainCheckRequest, request: Request):
    normalized = normalize_domain(req.domain or "")
    if not normalized:
        raise HTTPException(status_code=400, detail="Invalid domain name.")

    cache_key = store.domain_cache_key(normalized)
    cached = store.get_cached(cache_key, DOMAIN_CACHE_TTL)
    if cached is not None:
        return {**cached, "cache_hit": True, "rate_limited": False}

    client_ip = get_client_ip(request)
    if store.count_recent(f"domain_ip:{client_ip}", _HOUR) >= DOMAIN_IP_PER_HOUR:
        return _rate_limited(f"Domain search limit reached ({DOMAIN_IP_PER_HOUR} per hour). Try again later.")
    if store.count_recent(f"domain_ip:{client_ip}", _DAY) >= DOMAIN_IP_PER_DAY:
        return _rate_limited(f"Domain search limit reached ({DOMAIN_IP_PER_DAY} per day). Try again tomorrow.")
    if store.count_recent("domain_global", _DAY) >= DOMAIN_GLOBAL_PER_DAY:
        return _rate_limited("The service is at its global daily domain-search capacity. Try again later.")
    store.record_event(f"domain_ip:{client_ip}")
    store.record_event("domain_global")

    try:
        raw_breaches = await client.fetch_breaches_by_domain(normalized)
    except client.HibpError as exc:
        log.warning("breach: domain lookup failed: %s", exc)
        raise HTTPException(status_code=502, detail="Have I Been Pwned lookup failed. Try again shortly.")

    names = [b.get("Name") for b in raw_breaches]
    breaches = await _enrich_names(names)
    breaches.sort(key=lambda b: (b.get("breach_date") or "", b.get("name") or ""))

    hosting_ip = await _resolve_hosting_ip(normalized)

    result = {
        "domain": normalized,
        "hosting_ip": hosting_ip,
        "breach_count": len(breaches),
        "breaches": breaches,
    }
    store.store_cached(cache_key, result)
    return {**result, "cache_hit": False, "rate_limited": False}


# ---------- passive / reference sections (no input, no rate limit) ----------

@router.get("/recent")
async def recent_breaches():
    all_cached = store.get_cached(store.ALL_BREACHES_KEY, ALL_BREACHES_TTL)
    if all_cached is None:
        try:
            raw = await client.fetch_all_breaches()
        except client.HibpError as exc:
            raise HTTPException(status_code=502, detail=f"Could not load breach list: {exc}")
        all_cached = [client.shape_breach(b) for b in raw]
        store.store_cached(store.ALL_BREACHES_KEY, all_cached)
        _warm_meta_cache(raw)

    latest_cached = store.get_cached(store.LATEST_BREACH_KEY, LATEST_BREACH_TTL)
    if latest_cached is None:
        try:
            raw_latest = await client.fetch_latest_breach()
        except client.HibpError:
            raw_latest = None
        latest_cached = client.shape_breach(raw_latest) if raw_latest else {}
        store.store_cached(store.LATEST_BREACH_KEY, latest_cached)

    merged = {b["name"]: b for b in all_cached if b.get("name")}
    if latest_cached.get("name"):
        merged[latest_cached["name"]] = latest_cached

    ordered = sorted(merged.values(), key=lambda b: b.get("added_date") or "", reverse=True)
    return {"breaches": ordered[:5]}


@router.get("/all")
async def all_breaches():
    cached = store.get_cached(store.ALL_BREACHES_KEY, ALL_BREACHES_TTL)
    cache_hit = cached is not None
    if cached is None:
        try:
            raw = await client.fetch_all_breaches()
        except client.HibpError as exc:
            raise HTTPException(status_code=502, detail=f"Could not load breach list: {exc}")
        cached = [client.shape_breach(b) for b in raw]
        store.store_cached(store.ALL_BREACHES_KEY, cached)
        _warm_meta_cache(raw)
    return {"breaches": cached, "count": len(cached), "cache_hit": cache_hit}


@router.get("/dataclasses")
async def data_classes():
    cached = store.get_cached(store.DATACLASSES_KEY, None)
    if cached is None:
        try:
            raw = await client.fetch_dataclasses()
        except client.HibpError as exc:
            raise HTTPException(status_code=502, detail=f"Could not load data classes: {exc}")
        cached = {"data_classes": raw}
        store.store_cached(store.DATACLASSES_KEY, cached)
    return cached
