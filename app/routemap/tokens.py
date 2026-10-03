"""
Single-use upload tokens for "run it locally, we will pick it up".

THE SHAPE OF THE FEATURE
------------------------
FalconEye does not run traceroutes. The user runs one on their own machine,
which is the only place a trace of *their* path can come from, and the tab shows
a one-line command that pipes the output here:

    traceroute 1.1.1.1 2>&1 | curl -s --data-binary @- https://host/api/routemap/ingest/<token>

The command uploads text and nothing else. There is deliberately no
``curl | sh`` and no ``irm | iex``: the user is being asked to run a command
they can read in full, not to download and execute whatever this server feels
like sending. That constraint is why the command is a pipe into curl rather than
anything more convenient.

WHY THERE ARE TWO SECRETS
-------------------------
``token`` goes in the URL the user pastes into a terminal. It will be in their
shell history, possibly on their screen in a screenshot, and it travels as a
path segment. Anyone holding it can *write* a trace.

``poll_key`` never leaves the page that asked for the token. It is required to
*read* the result. That is the session binding: the browser that requested the
command is the only thing that can collect what comes back, and it holds even
when the upload arrives from a different address than the browser (IPv6 shell
against an IPv4 browser, a trace run from a different machine on purpose),
which an IP-based binding would get wrong.

WHERE THE STATE LIVES, AND WHY NOT IN THE DATABASE
--------------------------------------------------
Redis, with the TTL as the expiry, because the upload and the poll are two
different requests that land on two different gunicorn workers. An in-process
dict is correct on a one-worker install and wrong two times in three on the
standard three-worker one, so Redis is the real implementation and the
in-process dict exists only as the fallback for a box without it (and for the
tests). :func:`store_kind` reports which one is in use, and the API refuses to
issue a token it knows it cannot collect against.

The trace text is never written to the application database. It lives in Redis
for at most :data:`~app.config.ROUTEMAP_TOKEN_TTL_SECONDS` and is deleted the
moment it is collected, which is what "used for the render only" means in
practice.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import secrets
import time

from app.config import ROUTEMAP_TOKEN_TTL_SECONDS
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.routemap.tokens")

# 32 bytes of urandom, hex. The token is the only credential on the ingest
# endpoint, so it is sized to be unguessable rather than to be typed.
TOKEN_BYTES = 32
POLL_KEY_BYTES = 32

_PREFIX = "routemap:token:"

try:
    import redis.asyncio as _aioredis
    _redis = _aioredis.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
except ImportError:  # pragma: no cover - redis is in requirements.txt
    _redis = None
    log.warning("redis package not installed; Route Map upload falls back to "
                "per-process state, which is only correct with one worker")

# The fallback. Values are (expires_at, payload dict).
_local: dict[str, tuple[float, dict]] = {}

# Set when Redis is installed but not answering. The upload path then reports
# itself unavailable rather than silently using per-process state, which on the
# standard three-worker deployment would mean the browser polls one worker
# while the shell uploaded to another and the trace never appears. Paste still
# works, because it needs no store at all.
_redis_down = False


class StoreUnavailable(Exception):
    """The handshake store cannot be reached, so an upload cannot be brokered."""


def store_kind() -> str:
    if _redis is None:
        return "process"
    return "unavailable" if _redis_down else "redis"


# ------------------------------------------------------- target validation ----
#
# The target is interpolated into a command string that a human is told to run
# in their own shell. That makes this page a place where attacker-supplied text
# can become someone else's shell command, so the validation here is not about
# whether the target is reachable, it is about whether what we are about to
# print is a hostname and only a hostname.
#
# Allowlist, not denylist: letters, digits, dot and hyphen for a hostname, plus
# the colon form for IPv6. Everything else is refused, which covers the shell
# metacharacters (; | & $ ` ( ) < > newline, quotes, backslash, space) without
# having to enumerate them and without depending on having enumerated them all.

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z][A-Za-z0-9-]{0,62}$")
# A single label with no dot ("localhost", an internal short name) is refused:
# it cannot be a public traceroute target and accepting it only widens what can
# be printed.

MAX_TARGET_LENGTH = 253


class InvalidTarget(ValueError):
    """The target is not a plain hostname or IP address."""


def validate_target(raw: str) -> str:
    """Return the canonical target, or raise :class:`InvalidTarget`.

    The returned value is what may be printed into the displayed command. A
    caller must use this result and never the raw input.
    """
    text = (raw or "").strip()
    if not text:
        raise InvalidTarget("give a hostname or IP address to trace to")
    if len(text) > MAX_TARGET_LENGTH:
        raise InvalidTarget(f"the target is longer than {MAX_TARGET_LENGTH} characters")

    # An IP address first, so the hostname rules never have to reason about
    # colons, zone ids or dotted-quad edge cases.
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            raise InvalidTarget("that address is not a traceroute target")
        return str(address)

    if not _HOSTNAME_RE.match(text):
        raise InvalidTarget(
            "the target must be a hostname such as example.com or an IP address, "
            "with no scheme, path, port, spaces or shell characters")
    return text.lower()


# ------------------------------------------------------- command rendering ----

# The commands shown to the user. One per platform, each a pipe from a
# traceroute tool into an HTTP POST of plain text, and nothing else.
#
# Windows uses Invoke-RestMethod rather than curl.exe because tracert's output
# needs Out-String to arrive as one body rather than as an object stream, and
# because Invoke-RestMethod is present on every supported PowerShell without
# anything being installed.
COMMAND_TEMPLATES = {
    "windows": ("tracert {target} | Out-String | Invoke-RestMethod -Method Post "
                "-ContentType 'text/plain' -Uri {url}"),
    "unix": "traceroute {target} 2>&1 | curl -s --data-binary @- {url}",
    "mtr": "mtr --report-wide --show-ips -c 3 {target} 2>&1 | curl -s --data-binary @- {url}",
}

COMMAND_LABELS = {
    "windows": "Windows (PowerShell)",
    "unix": "Linux or macOS (traceroute)",
    "mtr": "Linux or macOS (mtr, gives per-hop loss)",
}


def render_commands(target: str, ingest_url: str) -> list[dict]:
    """Every platform's command, for a target that has already been validated.

    Raises ValueError if handed an unvalidated target, because the whole point
    of :func:`validate_target` is that nothing reaches a command string without
    going through it.
    """
    if validate_target(target) != target:
        raise ValueError("render_commands needs the canonical validated target")
    return [
        {"key": key, "label": COMMAND_LABELS[key],
         "command": template.format(target=target, url=ingest_url)}
        for key, template in COMMAND_TEMPLATES.items()
    ]


def detect_platform(user_agent: str) -> str:
    """Which command to show first, from the User-Agent.

    A hint for the default tab, never a restriction: every command is returned
    and the UI offers a manual switch, because a User-Agent is a guess and
    somebody reading this on a phone is going to run the trace somewhere else.
    """
    agent = (user_agent or "").lower()
    if "windows" in agent:
        return "windows"
    return "unix"


# -------------------------------------------------------------- the store ----

async def issue(target: str) -> dict:
    """Mint a token for *target*. Returns the public record plus the poll key."""
    token = secrets.token_hex(TOKEN_BYTES)
    poll_key = secrets.token_hex(POLL_KEY_BYTES)
    now = time.time()
    payload = {
        "target": target,
        "poll_key": poll_key,
        "created_at": now,
        "expires_at": now + ROUTEMAP_TOKEN_TTL_SECONDS,
        "trace_text": None,
        "uploaded_at": None,
    }
    await _put(token, payload)
    log.info("event=routemap_token action=issued token=%s target=%s ttl=%ds",
             tag(token), tag(target), ROUTEMAP_TOKEN_TTL_SECONDS)
    return {"token": token, "poll_key": poll_key,
            "expires_at": payload["expires_at"]}


def _note_redis_failure(operation: str, exc: Exception) -> None:
    global _redis_down
    if not _redis_down:
        log.error(
            "the Route Map upload store is unreachable (%s: %s). Uploads are "
            "disabled until Redis answers again; pasting a trace is unaffected. "
            "Check: systemctl status redis-server", operation, exc)
    _redis_down = True


async def _put(token: str, payload: dict) -> None:
    global _redis_down
    if _redis is not None:
        try:
            await _redis.setex(_PREFIX + token, ROUTEMAP_TOKEN_TTL_SECONDS,
                               json.dumps(payload))
        except Exception as exc:
            _note_redis_failure("write", exc)
            raise StoreUnavailable(str(exc)) from exc
        _redis_down = False
        return
    _local[token] = (payload["expires_at"], payload)
    _prune_local()


def _prune_local() -> None:
    now = time.time()
    for key in [k for k, (expires, _) in _local.items() if expires <= now]:
        _local.pop(key, None)


async def _get(token: str) -> dict | None:
    global _redis_down
    if _redis is not None:
        try:
            raw = await _redis.get(_PREFIX + token)
        except Exception as exc:
            _note_redis_failure("read", exc)
            raise StoreUnavailable(str(exc)) from exc
        _redis_down = False
        return json.loads(raw) if raw else None
    _prune_local()
    entry = _local.get(token)
    return entry[1] if entry else None


async def _drop(token: str) -> None:
    if _redis is not None:
        try:
            await _redis.delete(_PREFIX + token)
        except Exception as exc:
            # The record has already been handed over; failing to delete it is
            # untidy, not a reason to lose the caller's result. It expires on
            # its own TTL regardless.
            _note_redis_failure("delete", exc)
        return
    _local.pop(token, None)


class TokenError(Exception):
    """A token could not be used. The message is shown to the caller."""


async def deposit(token: str, trace_text: str) -> str:
    """Attach an uploaded trace to *token*. Single use.

    Returns the target the token was issued for. Raises :class:`TokenError`
    with the same message for an unknown, expired and already-used token: they
    are the same situation from the uploader's point of view, and telling them
    apart would turn the endpoint into an oracle for which tokens exist.
    """
    if not re.fullmatch(r"[0-9a-f]{%d}" % (TOKEN_BYTES * 2), token or ""):
        raise TokenError("that upload link is not valid")
    payload = await _get(token)
    if payload is None or payload.get("expires_at", 0) <= time.time():
        raise TokenError("that upload link has expired or has already been used. "
                         "Generate a new command in the Route Map tab.")
    if payload.get("trace_text") is not None:
        raise TokenError("that upload link has expired or has already been used. "
                         "Generate a new command in the Route Map tab.")
    payload["trace_text"] = trace_text
    payload["uploaded_at"] = time.time()
    await _put(token, payload)
    log.info("event=routemap_token action=uploaded token=%s bytes=%d",
             tag(token), len(trace_text))
    return payload.get("target") or ""


async def collect(token: str, poll_key: str) -> dict:
    """What the polling page gets. Deletes the record once it hands over a trace.

    ``{"status": "waiting"}`` until something is uploaded, then
    ``{"status": "ready", "trace_text": ..., "target": ...}`` exactly once.
    """
    payload = await _get(token)
    if payload is None:
        return {"status": "expired"}
    # Constant-time, because this is the credential that reads the result.
    if not secrets.compare_digest(str(payload.get("poll_key") or ""), str(poll_key or "")):
        raise TokenError("that upload link does not belong to this page")
    if payload.get("trace_text") is None:
        return {"status": "waiting",
                "expires_at": payload.get("expires_at"),
                "target": payload.get("target")}
    trace_text = payload["trace_text"]
    target = payload.get("target") or ""
    # Handed over once and then gone: the text exists to be rendered, not kept.
    await _drop(token)
    log.info("event=routemap_token action=collected token=%s", tag(token))
    return {"status": "ready", "trace_text": trace_text, "target": target}


async def healthy() -> bool:
    """Whether the store will actually carry a handoff between two workers.

    False means the tab must not offer the upload flow: with no shared store
    the browser and the uploading shell can land on different workers. This is
    what /capabilities reports, so the UI can hide a path it cannot complete
    instead of showing a command that silently never returns.
    """
    global _redis_down
    if _redis is None:
        return False
    try:
        ok = bool(await _redis.ping())
    except Exception as exc:
        _note_redis_failure("ping", exc)
        return False
    _redis_down = not ok
    return ok
