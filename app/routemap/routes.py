"""
Route Map API.

Three ways in, one pipeline out. Whichever way the trace text arrives, it goes
through the same engine, ``routemap_engine.analyse`` (the routemap-engine package
since v3.36.0, shared with the desktop app), with this instance's sources from
app/routemap/geo.py, so there is exactly one place a hop can be placed and
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

import asyncio
import ipaddress
import logging

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from routemap_engine import analyse as engine_analyse
from routemap_engine import normalise_origin
from slowapi import Limiter

from app.config import (ATLAS_PER_DAY, HTTPX_TIMEOUT, OPERATOR_CONTACT_UA,
                        ROUTEMAP_ANALYSES_PER_DAY, ROUTEMAP_MAX_UPLOAD_BYTES,
                        ROUTEMAP_TOKENS_PER_DAY, ROUTEMAP_TOKEN_TTL_SECONDS)
from app.routemap import atlas, cities, geo, hoiho, sitecodes, tokens
from app.routemap.parse import MAX_TRACE_BYTES, TraceParseError
from app.utils import rate_limit
from app.utils.client_ip import get_client_ip, get_client_ip_key
from app.utils.logsafe import tag

router = APIRouter(prefix="/api/routemap", tags=["routemap"])
limiter = Limiter(key_func=get_client_ip_key)
log = logging.getLogger("falconeye.routemap")

USER_AGENT = f"FalconEye/3.35 ({OPERATOR_CONTACT_UA}; Route Map)"

# Strong references to in-flight background jobs. asyncio only holds a weak
# reference to a task, so a task nobody keeps can be garbage collected
# mid-flight; the set is the standard way to stop that, and the done-callback
# is what stops it growing.
_JOBS: set = set()


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _JOBS.add(task)
    task.add_done_callback(_JOBS.discard)


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
    # The page knows where it is when it asks for the command. The shell that
    # uploads the trace does not, so the origin is attached to the job here
    # rather than raced in on the first poll.
    origin_lat: float | None = None
    origin_lon: float | None = None


def _origin(lat: float | None, lon: float | None) -> tuple[float, float] | None:
    """Validate a supplied origin. Out-of-range is no origin, not an error.

    The coordinates arrive already rounded to about 10 km by the browser. They
    are used for this response and never stored.
    """
    return normalise_origin(lat, lon)


async def _analyse(trace_text: str, origin: tuple[float, float] | None,
                   extra: dict | None = None) -> dict:
    """Parse and locate one trace. The single path every entry point joins."""
    try:
        route = await engine_analyse(trace_text, origin, sources=geo.sources())
    except TraceParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    body = route.to_dict()
    if extra:
        body.update(extra)
    log.info("event=routemap_analyze parser=%s hops=%d placed=%d",
             route.parser, len(route.hops), len(route.placed))
    return body


async def _process_upload(token: str, origin: tuple[float, float] | None) -> None:
    """Analyse an uploaded trace once, in the background, and store the result.

    This is the work that used to happen inside the poll request. Any failure
    is recorded on the job so the page is told, rather than left polling a
    token whose work died silently.
    """
    try:
        state = await tokens.peek(token)
        if state is None or not state.get("trace_text"):
            return
        # The origin the page recorded when it asked for the command.
        saved = state.get("origin")
        if origin is None and isinstance(saved, (list, tuple)) and len(saved) == 2:
            origin = (saved[0], saved[1])
        result = await _analyse(state["trace_text"], origin, extra={"source": "upload"})
        result["target"] = result.get("target") or state.get("target")
        await tokens.store_result(token, result)
    except HTTPException as exc:
        await tokens.store_error(token, "parse", str(exc.detail))
    except Exception as exc:  # noqa: BLE001 - a job must never die silently
        log.exception("route map upload job failed for %s", tag(token))
        await tokens.store_error(token, "failed",
                                 "The trace could not be processed.")


async def _process_atlas(token: str, measurement_id: int, probe: dict,
                         origin: tuple[float, float] | None) -> None:
    """Wait for a scheduled Atlas measurement, analyse it, store the result."""
    try:
        trace_text = await atlas.collect_result(measurement_id)
        result = await _analyse(trace_text, origin, extra={
            "source": "atlas",
            "measurement_id": measurement_id,
            "probe": probe,
        })
        await tokens.store_result(token, result)
    except atlas.AtlasUnavailable as exc:
        await tokens.store_error(token, exc.kind, exc.message)
    except HTTPException as exc:
        await tokens.store_error(token, "parse", str(exc.detail))
    except Exception as exc:  # noqa: BLE001
        log.exception("route map atlas job failed for %s", tag(token))
        await tokens.store_error(token, "failed",
                                 "The Atlas measurement could not be processed.")


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

    # Neither the ASN nor the country could be read from the address: the
    # visitor is behind something that hides it, or the lookup failed. The
    # origin they already gave us still narrows it, and resolving a country
    # from coordinates is a lookup in the bundled city table, so it costs no
    # request and tells nobody anything. Without this the trace gives up with
    # "no probe near you" while a perfectly good probe sits in their country.
    if not asn and not country and origin is not None:
        nearby = cities.nearest(*origin)
        country = (nearby or {}).get("cc")

    try:
        run = await atlas.start(target, asn, country, origin)
    except atlas.AtlasUnavailable as exc:
        log.info("event=routemap_atlas_unavailable kind=%s target=%s",
                 exc.kind, tag(target))
        raise HTTPException(status_code=503,
                            detail={"kind": exc.kind, "message": exc.message}) from exc

    raw = run["probe"]
    probe = {
        "id": raw.get("id"),
        "asn": raw.get("asn"),
        "country": raw.get("country"),
        "distance_km": raw.get("distance_km"),
        "city": ((cities.nearest(raw["lat"], raw["lon"]) or {}).get("display")
                 if raw.get("lat") is not None else None),
    }

    # The measurement is scheduled; waiting for it is up to two minutes, which
    # is longer than nginx and gunicorn will hold a request open. So the page
    # gets a job to poll and the waiting happens in the background.
    issued = await tokens.issue(target, kind="atlas")
    await tokens.update(issued["token"], status=tokens.STATUS_WAITING, probe=probe)
    _spawn(_process_atlas(issued["token"], run["measurement_id"], probe, origin))

    return JSONResponse(status_code=202, content={
        "status": "running",
        "token": issued["token"],
        "poll_key": issued["poll_key"],
        "expires_at": issued["expires_at"],
        "measurement_id": run["measurement_id"],
        "probe": probe,
        "target": target,
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
    origin = _origin(body.origin_lat, body.origin_lon)
    try:
        issued = await tokens.issue(target)
        if origin is not None:
            await tokens.update(issued["token"], origin=list(origin))
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
        # Analysed once, here, in the background. The poll is a status read.
        _spawn(_process_upload(token, None))
    except tokens.StoreUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="The upload service is unavailable right now. Paste the trace "
                   "into the Route Map tab instead.\n") from exc
    except tokens.TokenError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    # JSON on every outcome, success and failure alike. The caller is a shell
    # pipeline, and a pipeline that gets an HTML page back (a Cloudflare
    # challenge, say) needs to be able to tell that apart from a result. Every
    # error path here already raises HTTPException, which FastAPI renders as
    # JSON, so this is the only branch that had to change.
    return JSONResponse(status_code=200, content={
        "status": "received",
        "message": "Trace received. Go back to the Route Map tab.",
    })


@router.get("/pending/{token}")
@limiter.limit("120/minute")
async def pending(request: Request, token: str, key: str = "",
                  origin_lat: float | None = None, origin_lon: float | None = None):
    """Poll a job. A status read: no external call, no pipeline, no waiting.

    ``key`` is the poll secret the page kept; it is what ties collection to the
    browser that asked for the job.

    This used to run the whole geolocation pipeline, so a poll could take longer
    than nginx and gunicorn would allow and the worker was killed underneath it.
    An upload that had already succeeded then came back as 502. The work now
    happens once, in the background, and this returns 200 with a status or the
    finished result.

    The origin is accepted here only to attach it to an upload job whose origin
    was not known when the shell uploaded it; it never triggers work.
    """
    origin = _origin(origin_lat, origin_lon)
    if origin is not None:
        try:
            await tokens.set_origin_once(token, origin)
        except tokens.StoreUnavailable:
            pass

    try:
        state = await tokens.collect(token, key)
    except tokens.StoreUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="The upload service is unavailable right now.") from exc
    except tokens.TokenError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return state
