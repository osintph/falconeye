"""
Route Map API.

Three ways in, one pipeline out. Whichever way the trace text arrives, it goes
through the same parser (app/routemap/parse.py) and the same geolocation pass
(app/routemap/geo.py), so there is exactly one place a hop can be placed and
exactly one place a format bug can live:

  POST /api/routemap/trace          RIPE Atlas runs it from a probe near the user
  POST /api/routemap/analyze        the user pasted it
  POST /api/routemap/ingest/{token} the user ran it themselves and piped it here

Supporting endpoints: /capabilities (what this instance can do), /cities (the
origin picker's offline search), /origin-guess (a city-level pre-fill from the
visitor's IP), /command and /pending (the run-it-yourself handshake).

NOTHING FROM A TRACE IS STORED
------------------------------
Trace text, coordinates, city and the visitor's IP are used to build one
response and then dropped. The only thing that outlives a request is the Hoiho
hostname cache (router hostnames, 30 days) and the Atlas probe/credit
bookkeeping. User-supplied values in log lines go through logsafe.tag().
"""
from __future__ import annotations

import ipaddress
import logging

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field
from slowapi import Limiter

from app.config import (ATLAS_PER_DAY, HTTPX_TIMEOUT, OPERATOR_CONTACT_UA,
                        ROUTEMAP_ANALYSES_PER_DAY, ROUTEMAP_MAX_UPLOAD_BYTES,
                        ROUTEMAP_TOKENS_PER_DAY, ROUTEMAP_TOKEN_TTL_SECONDS)
from app.routemap import atlas, cities, geo, hoiho, sitecodes, tokens
from app.routemap.parse import MAX_TRACE_BYTES, PARSER_LABELS, TraceParseError, parse_trace
from app.utils import rate_limit
from app.utils.client_ip import get_client_ip, get_client_ip_key
from app.utils.logsafe import tag

router = APIRouter(prefix="/api/routemap", tags=["routemap"])
limiter = Limiter(key_func=get_client_ip_key)
log = logging.getLogger("falconeye.routemap")

USER_AGENT = f"FalconEye/3.35 ({OPERATOR_CONTACT_UA}; Route Map)"

_RL_ANALYZE = "routemap_analyze_rl"
_RL_TOKEN = "routemap_token_rl"
_RL_ATLAS = "routemap_atlas_rl"
for _table in (_RL_ANALYZE, _RL_TOKEN, _RL_ATLAS):
    rate_limit.init_table(_table)


# ---------------------------------------------------------------- requests ---

class AnalyzeRequest(BaseModel):
    trace_text: str = Field(..., max_length=MAX_TRACE_BYTES)
    origin_lat: float | None = None
    origin_lon: float | None = None


class TraceRequest(BaseModel):
    target: str = Field(..., max_length=tokens.MAX_TARGET_LENGTH)
    origin_lat: float | None = None
    origin_lon: float | None = None


class CommandRequest(BaseModel):
    target: str = Field(..., max_length=tokens.MAX_TARGET_LENGTH)


def _origin(lat: float | None, lon: float | None) -> tuple[float, float] | None:
    """Validate a supplied origin. Out-of-range is no origin, not an error.

    The coordinates arrive already rounded to about 10 km by the browser. They
    are used for this response and never stored.
    """
    if lat is None or lon is None:
        return None
    try:
        lat, lon = float(lat), float(lon)
    except (TypeError, ValueError):
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None
    return (round(lat, 2), round(lon, 2))


def _origin_block(origin: tuple[float, float] | None, located: list) -> dict:
    """What the response says about where the path starts."""
    if origin is None:
        anchor = geo.first_located(located)
        if anchor is None:
            return {"lat": None, "lon": None, "label": None, "source": "none"}
        city = cities.nearest(*anchor)
        return {"lat": anchor[0], "lon": anchor[1],
                "label": (city or {}).get("display"), "source": "first-hop"}
    city = cities.nearest(*origin)
    return {"lat": origin[0], "lon": origin[1],
            "label": (city or {}).get("display") or f"{origin[0]}, {origin[1]}",
            "source": "supplied"}


async def _analyse(trace_text: str, origin: tuple[float, float] | None,
                   extra: dict | None = None) -> dict:
    """Parse and locate one trace. The single path every entry point joins."""
    try:
        parsed = parse_trace(trace_text)
    except TraceParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not parsed.hops:
        raise HTTPException(status_code=400, detail="No hops were found in that trace.")

    resolved = await geo.resolve(parsed.hops, origin)
    located = resolved["hops"]
    body = {
        "parser": parsed.parser,
        "parser_label": PARSER_LABELS.get(parsed.parser, parsed.parser),
        "target": parsed.target,
        "warnings": parsed.warnings,
        "hoiho_ruleset_date": resolved["hoiho_ruleset_date"],
        "origin": _origin_block(origin, located),
        "hops": located,
    }
    if extra:
        body.update(extra)
    placed = sum(1 for h in located if h.get("lat") is not None)
    log.info("event=routemap_analyze parser=%s hops=%d placed=%d",
             parsed.parser, len(located), placed)
    return body


def _daily(table: str, request: Request, limit: int, what: str) -> str:
    source_ip = get_client_ip(request)
    allowed, used = rate_limit.check(table, source_ip, limit)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Daily limit reached ({used}/{limit} {what} per 24 hours). Try again later.")
    rate_limit.record(table, source_ip)
    return source_ip


# ------------------------------------------------------------ capabilities ---

@router.get("/capabilities")
async def capabilities():
    """What this instance can actually do, so the tab does not offer what it cannot.

    ``upload_enabled`` is a live check, not a config read: the handshake needs a
    store both the uploading shell's worker and the polling browser's worker can
    see, and "Redis is importable" is not the same claim as "Redis answers".
    """
    upload_ok = await tokens.healthy() or tokens.store_kind() == "process"
    return {
        "atlas_enabled": atlas.configured(),
        "hoiho_enabled": hoiho.HOIHO_ENABLED,
        "upload_enabled": upload_ok,
        "upload_store": tokens.store_kind(),
        "site_code_count": sitecodes.count(),
        "token_ttl_seconds": ROUTEMAP_TOKEN_TTL_SECONDS,
    }


# ------------------------------------------------------------------ cities ---

@router.get("/cities")
@limiter.limit("60/minute")
async def search_cities(request: Request, q: str = ""):
    """The origin picker's search. Offline: nothing leaves this server."""
    return {"results": cities.search(q), "attribution": cities.ATTRIBUTION,
            "attribution_url": cities.ATTRIBUTION_URL}


@router.get("/origin-guess")
@limiter.limit("20/minute")
async def origin_guess(request: Request):
    """A city-level pre-fill for the picker, from the visitor's own IP.

    Only ever a suggestion the visitor confirms. The IP is read through the
    same trusted-proxy logic every rate limit uses, is never logged in the
    clear, and neither it nor the result is stored.
    """
    client_ip = get_client_ip(request)
    try:
        ipaddress.ip_address(client_ip)
    except ValueError:
        return {"available": False}

    records = await geo.ip_geolocate([client_ip])
    record = records.get(client_ip)
    if not record:
        log.info("event=routemap_origin_guess ip=%s result=none", tag(client_ip))
        return {"available": False}

    lat, lon = round(record["lat"], 1), round(record["lon"], 1)
    city = cities.nearest(lat, lon)
    log.info("event=routemap_origin_guess ip=%s result=ok", tag(client_ip))
    return {"available": True, "lat": lat, "lon": lon,
            "display": (city or {}).get("display") or f"{lat}, {lon}",
            "cc": record.get("cc")}


# ----------------------------------------------------------------- analyze ---

@router.post("/analyze")
@limiter.limit("20/minute")
async def analyze(request: Request, body: AnalyzeRequest):
    """A pasted trace. No probing of any kind happens here."""
    _daily(_RL_ANALYZE, request, ROUTEMAP_ANALYSES_PER_DAY, "route analyses")
    return await _analyse(body.trace_text, _origin(body.origin_lat, body.origin_lon))


# ------------------------------------------------------------------- Atlas ---

async def _client_network(client_ip: str) -> tuple[int | None, str | None]:
    """The visitor's ASN and country, for probe selection.

    Derived from their IP here rather than by handing RIPE Atlas a coordinate
    filter, which is what keeps the visitor's own position out of the Atlas
    request entirely.
    """
    asn = country = None
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://stat.ripe.net/data/network-info/data.json",
                params={"resource": client_ip}, timeout=HTTPX_TIMEOUT,
                headers={"User-Agent": USER_AGENT})
        if response.status_code == 200:
            asns = ((response.json() or {}).get("data") or {}).get("asns") or []
            if asns:
                asn = int(asns[0])
    except Exception as exc:
        log.warning("network-info lookup failed for %s: %s", tag(client_ip), exc)

    records = await geo.ip_geolocate([client_ip])
    record = records.get(client_ip)
    if record:
        country = record.get("cc")
    return asn, country


@router.post("/trace")
@limiter.limit("6/minute")
async def trace(request: Request, body: TraceRequest):
    """Run one traceroute on a RIPE Atlas probe near the visitor.

    Every failure mode comes back as 503 with a ``kind`` the tab maps onto its
    own message and the Advanced fallback, rather than as a bare error: an
    instance with Atlas switched off is not broken, it just cannot do this.
    """
    try:
        target = tokens.validate_target(body.target)
    except tokens.InvalidTarget as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not atlas.configured():
        raise HTTPException(
            status_code=503,
            detail={"kind": "disabled",
                    "message": "Atlas tracing is switched off on this instance."})

    client_ip = _daily(_RL_ATLAS, request, ATLAS_PER_DAY, "Atlas traces")
    origin = _origin(body.origin_lat, body.origin_lon)
    asn, country = await _client_network(client_ip)

    try:
        run = await atlas.trace(target, asn, country, origin)
    except atlas.AtlasUnavailable as exc:
        log.info("event=routemap_atlas_unavailable kind=%s target=%s",
                 exc.kind, tag(target))
        raise HTTPException(status_code=503,
                            detail={"kind": exc.kind, "message": exc.message}) from exc

    probe = run["probe"]
    return await _analyse(run["trace_text"], origin, extra={
        "source": "atlas",
        "measurement_id": run["measurement_id"],
        "probe": {
            "id": probe.get("id"),
            "asn": probe.get("asn"),
            "country": probe.get("country"),
            "distance_km": probe.get("distance_km"),
            "city": (cities.nearest(probe["lat"], probe["lon"]) or {}).get("display"),
        },
    })


# ------------------------------------------------- run it yourself, upload ---

@router.post("/command")
@limiter.limit("20/minute")
async def make_command(request: Request, body: CommandRequest):
    """Mint a single-use upload token and render the commands for it."""
    try:
        target = tokens.validate_target(body.target)
    except tokens.InvalidTarget as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    _daily(_RL_TOKEN, request, ROUTEMAP_TOKENS_PER_DAY, "upload links")
    try:
        issued = await tokens.issue(target)
    except tokens.StoreUnavailable as exc:
        # Nothing here is the caller's fault, and the paste path still works, so
        # the message says that rather than reporting a bare failure.
        raise HTTPException(
            status_code=503,
            detail="The upload service is unavailable on this instance right now. "
                   "Run the trace yourself and paste it instead.") from exc
    base = str(request.base_url).rstrip("/")
    ingest_url = f"{base}/api/routemap/ingest/{issued['token']}"
    return {
        "token": issued["token"],
        "poll_key": issued["poll_key"],
        "expires_at": issued["expires_at"],
        "ttl_seconds": ROUTEMAP_TOKEN_TTL_SECONDS,
        "platform": tokens.detect_platform(request.headers.get("user-agent", "")),
        "commands": tokens.render_commands(target, ingest_url),
    }


@router.post("/ingest/{token}")
@limiter.limit("20/minute")
async def ingest(request: Request, token: str):
    """Receive one uploaded trace. text/plain, size-capped, token single use.

    The body is read with an explicit cap rather than trusted, because this
    endpoint is unauthenticated by construction: the token in the URL is the
    only credential, and an attacker who guesses one should still not be able
    to make this process read an unbounded body into memory.
    """
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > ROUTEMAP_MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="That trace is too large.")

    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > ROUTEMAP_MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="That trace is too large.")

    text = body.decode("utf-8", "replace").strip()
    if not text:
        raise HTTPException(status_code=400, detail="The upload was empty.")

    try:
        await tokens.deposit(token, text)
    except tokens.StoreUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="The upload service is unavailable right now. Paste the trace "
                   "into the Route Map tab instead.\n") from exc
    except tokens.TokenError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    # Answered as plain text because the thing reading it is a shell pipeline,
    # not a browser.
    return Response(content="Trace received. Go back to the Route Map tab.\n",
                    media_type="text/plain")


@router.get("/pending/{token}")
@limiter.limit("120/minute")
async def pending(request: Request, token: str, key: str = "",
                  origin_lat: float | None = None, origin_lon: float | None = None):
    """Poll for an uploaded trace, and analyse it the moment it arrives.

    ``key`` is the poll secret the page kept; it is what ties collection to the
    browser that asked for the command.
    """
    try:
        state = await tokens.collect(token, key)
    except tokens.StoreUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="The upload service is unavailable right now.") from exc
    except tokens.TokenError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    if state["status"] != "ready":
        return state

    result = await _analyse(state["trace_text"], _origin(origin_lat, origin_lon),
                            extra={"source": "upload"})
    result["target"] = result.get("target") or state.get("target")
    return result
