"""
Registered-service enumeration for one email address, via the holehe library.

WHAT THIS DOES, IN PLAIN TERMS
------------------------------
It does not ask a vendor a question. It makes **this server** start a signup, a
login or a password-recovery flow at each of a list of third-party sites, once per
site, and reads whether the site says the address is already taken. So enabling it
means our IP probes twenty services on behalf of whoever typed an address into the
box. That is why it is off by default, capped at five lookups per IP per day, and
documented in the runbook with a warning rather than a feature note.

WHAT IT WILL AND WILL NOT RETURN
--------------------------------
A holehe module returns this per service:

    {"name", "rateLimit", "exists", "emailrecovery", "phoneNumber", "others"}

``emailrecovery`` and ``phoneNumber`` are partially masked recovery details for a
real person, and ``others`` is unbounded. None of them is ever returned from here.
The sanitiser is an **allowlist of two fields**: the service label (ours, not the
module's) and ``registered`` as a plain bool. A module that cannot decide
(``exists is None``, which is what rate limiting looks like) produces no row at
all, because "unknown" rendered next to "no" reads as "no".

WHY NOT safe_fetch
------------------
``safe_fetch`` is for URLs an attacker supplies. Here the URLs are compile-time
constants inside third-party module code, and the attacker-supplied value is the
email address, which travels in a body or a query parameter. What that code could
do instead is build a URL out of the email's domain, so each module is given an
httpx transport that can only reach the hosts declared for it in ALLOWED_HOSTS
below, checked per request. A blocked request fails the module, and a failed
module is simply absent from the result.

THE LIBRARY
-----------
Verified 2026-09-27:

- ``holehe`` on PyPI, current version 1.61, uploaded 2022-07-21.
- Repository https://github.com/megadose/holehe, GPL-3.0, last pushed
  2024-09-10, not archived, 118 open issues. Effectively unmaintained.
- Invoked as a library, not as the ``holehe`` binary: each module is
  ``async def module(email, client, out)`` and appends one dict to ``out``
  (documented in the project README's "Python Example").
- It is deliberately NOT in requirements.txt. It is GPL-3.0 (compatible with this
  project's AGPL-3.0, but still a licence an operator should choose to take on),
  it pulls in trio, tqdm, termcolor and colorama for a feature that is off by
  default, and the import is what gates the feature: if the library is not
  installed, this source behaves exactly as if disabled. See
  docs/deploy-runbook.md.
"""
import asyncio
import logging
import re

import httpx

from app import config
from app.utils import cache, rate_limit

log = logging.getLogger("falconeye.holehe")

CACHE_TABLE = "holehe_cache"
RATE_LIMIT_TABLE = "holehe_rate_limit"

# Per-request timeout. The wall clock for the whole lookup is separate and
# shorter than the sum of these, by design: slow services are dropped, not
# waited for.
REQUEST_TIMEOUT = 8.0

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


# The curated list. Mainstream services where "this address has an account" is a
# fact about an account rather than about a person's private life: no dating, no
# adult, no health, no people-search brokers. Password-recovery modules are
# avoided in favour of signup and login checks, since a recovery flow is the one
# most likely to put mail in the target's inbox.
#
# (label rendered on the card, holehe module path)
ALLOWLIST = (
    ("GitHub", "programing.github"),
    ("CodePen", "programing.codepen"),
    ("Replit", "programing.replit"),
    ("Docker Hub", "software.docker"),
    ("Firefox Accounts", "software.firefox"),
    ("LastPass", "software.lastpass"),
    ("Internet Archive", "software.archive"),
    ("WordPress.com", "cms.wordpress"),
    ("Gravatar", "cms.gravatar"),
    ("Twitter", "social_media.twitter"),
    ("Instagram", "social_media.instagram"),
    ("Pinterest", "social_media.pinterest"),
    ("Tumblr", "social_media.tumblr"),
    ("Discord", "social_media.discord"),
    ("Imgur", "social_media.imgur"),
    ("Patreon", "social_media.patreon"),
    ("Spotify", "music.spotify"),
    ("SoundCloud", "music.soundcloud"),
    ("Amazon", "shopping.amazon"),
    ("eBay", "shopping.ebay"),
)

# The hosts each module is permitted to reach, read out of the module sources at
# holehe 1.61. Registrable-domain suffixes: a module may reach the domain and its
# subdomains and nothing else.
ALLOWED_HOSTS = {
    "programing.github": {"github.com"},
    "programing.codepen": {"codepen.io"},
    "programing.replit": {"replit.com"},
    "software.docker": {"docker.com"},
    "software.firefox": {"firefox.com"},
    "software.lastpass": {"lastpass.com"},
    "software.archive": {"archive.org"},
    "cms.wordpress": {"wordpress.com"},
    "cms.gravatar": {"gravatar.com"},
    "social_media.twitter": {"twitter.com"},
    "social_media.instagram": {"instagram.com"},
    "social_media.pinterest": {"pinterest.com"},
    "social_media.tumblr": {"tumblr.com"},
    "social_media.discord": {"discord.com"},
    "social_media.imgur": {"imgur.com"},
    "social_media.patreon": {"patreon.com"},
    "music.spotify": {"spotify.com"},
    "music.soundcloud": {"soundcloud.com"},
    "shopping.amazon": {"amazon.com"},
    "shopping.ebay": {"ebay.com"},
}


class BlockedHost(RuntimeError):
    """A module tried to reach a host it had not declared."""


class _GuardedTransport(httpx.AsyncHTTPTransport):
    """An httpx transport that refuses any host outside `allowed`.

    Subdomains of a listed domain pass (spclient.wg.spotify.com for spotify.com);
    a domain that merely ends with one of the strings does not
    (spotify.com.evil.example).
    """

    def __init__(self, allowed: set, **kw):
        super().__init__(**kw)
        self._allow = {h.lower().lstrip(".") for h in allowed}

    def _allowed(self, host: str | None) -> bool:
        host = (host or "").lower().rstrip(".")
        return any(host == h or host.endswith("." + h) for h in self._allow)

    async def handle_async_request(self, request):
        if not self._allowed(request.url.host):
            raise BlockedHost(f"{request.url.host} is not declared for this module")
        return await super().handle_async_request(request)


def _guarded_transport(allowed: set) -> _GuardedTransport:
    return _GuardedTransport(allowed)


def init() -> None:
    """Create this source's own tables. Idempotent, safe at import."""
    cache.init_table(CACHE_TABLE, key_col="query_key")
    rate_limit.init_table(RATE_LIMIT_TABLE)


def _quota_ok(source_ip: str) -> bool:
    """Per-IP daily cap, checked only when we are about to probe upstream.

    Five a day, an order of magnitude below every other source, because each
    lookup is twenty outbound requests to third parties from our address. A cache
    hit never consumes quota, and being over the cap is not an error: the
    enrichment is simply absent.
    """
    try:
        allowed, _used = rate_limit.check(RATE_LIMIT_TABLE, source_ip, config.HOLEHE_PER_DAY)
        if allowed:
            rate_limit.record(RATE_LIMIT_TABLE, source_ip)
        return allowed
    except Exception as exc:  # noqa: BLE001 - never break a tab over bookkeeping
        log.warning("holehe rate-limit check failed, skipping lookup: %s", exc)
        return False


def _load_modules() -> list:
    """[(label, callable)] for the allowlist, or [] if the library is absent.

    Imported lazily and per call, so an instance without holehe installed (the
    default) never pays for it and never fails because of it.
    """
    import importlib

    loaded = []
    for label, path in ALLOWLIST:
        module_name = path.rsplit(".", 1)[-1]
        try:
            module = importlib.import_module(f"holehe.modules.{path}")
            func = getattr(module, module_name)
        except Exception as exc:  # noqa: BLE001 - absent, renamed or broken
            log.warning("holehe module %s unavailable: %s", path, exc)
            continue
        loaded.append((label, func, path))
    return [(label, func) for label, func, _ in loaded] if loaded else []


def _row(label: str, raw) -> dict | None:
    """Allowlist one module's output down to a label and a yes/no.

    The module's own `name` is ignored on purpose: it is upstream text, and the
    label we asked for is the only thing that reaches the page. `exists` must be
    a real bool; a string, an int or a missing key is a shape we do not recognise
    and produces nothing.
    """
    if not isinstance(raw, dict):
        return None
    exists = raw.get("exists")
    if not isinstance(exists, bool):
        return None
    if raw.get("rateLimit") is True:
        return None
    return {"service": label, "registered": exists}


async def _run_one(label: str, func, path: str, email: str, results: list,
                   semaphore: asyncio.Semaphore) -> None:
    """One module, on its own guarded client, contained."""
    async with semaphore:
        out: list = []
        transport = _guarded_transport(ALLOWED_HOSTS.get(path) or set())
        try:
            async with httpx.AsyncClient(transport=transport,
                                         timeout=REQUEST_TIMEOUT) as client:
                await func(email, client, out)
        except asyncio.CancelledError:
            raise
        except BaseException as exc:  # noqa: BLE001 - third-party code, contained
            log.warning("holehe %s failed: %s: %s", label, type(exc).__name__, exc)
            return
        for raw in out:
            row = _row(label, raw)
            if row is not None:
                results.append(row)
                return


async def _gather(modules: list, email: str, results: list) -> None:
    semaphore = asyncio.Semaphore(config.HOLEHE_CONCURRENCY)
    paths = dict(ALLOWLIST)
    await asyncio.gather(*[
        _run_one(label, func, paths.get(label, ""), email, results, semaphore)
        for label, func in modules
    ], return_exceptions=True)


async def lookup_email(email: str, source_ip: str = "") -> dict | None:
    """Which allowlisted services say this address is registered, or None.

    None means "this source has nothing", for every reason there is: disabled,
    library absent, over the per-IP cap, nothing answered in time, everything
    failed. The caller renders nothing, so the tab looks exactly as it does with
    the feature off.
    """
    if not config.HOLEHE_ENABLED:
        return None
    email = (email or "").strip().lower()
    if not _EMAIL_RE.match(email):
        return None

    key = f"email:{email}"
    try:
        hit = cache.get(CACHE_TABLE, key, config.HOLEHE_CACHE_TTL_HOURS, key_col="query_key")
    except Exception as exc:  # noqa: BLE001 - a cache problem must not break the tab
        log.warning("holehe cache read failed: %s", exc)
        hit = None
    if hit is not None:
        hit.pop("cache_hit", None)
        hit.pop("fetched_at", None)
        return hit

    modules = _load_modules()
    if not modules:
        return None

    if not _quota_ok(source_ip or "unknown"):
        return None

    results: list = []
    try:
        await asyncio.wait_for(_gather(modules, email, results),
                               timeout=config.HOLEHE_TIMEOUT_SECONDS)
    except (asyncio.TimeoutError, TimeoutError):
        # A partial answer is still an answer: the services that replied are
        # reported and the card says how many of them there were. What did not
        # finish is absent, never rendered as "not registered".
        log.info("holehe wall clock reached with %d of %d answered",
                 len(results), len(modules))
    except Exception as exc:  # noqa: BLE001 - this source must never break a tab
        log.warning("holehe lookup failed: %s", exc)
        return None

    if not results:
        return None

    order = [label for label, _ in ALLOWLIST]
    results.sort(key=lambda r: order.index(r["service"]) if r["service"] in order else 99)
    clean = {
        "services": results,
        "checked": len(results),
        "total": len(modules),
        "found": any(r["registered"] for r in results),
    }

    try:
        cache.set(CACHE_TABLE, key, clean, key_col="query_key")
    except Exception as exc:  # noqa: BLE001
        log.warning("holehe cache write failed: %s", exc)
    return clean


# Self-create on import, like the other sources. Guarded because import must
# never fail on a box where the data directory is not writable yet.
try:
    init()
except Exception as _exc:  # noqa: BLE001
    log.warning("holehe tables not initialised at import: %s", _exc)
