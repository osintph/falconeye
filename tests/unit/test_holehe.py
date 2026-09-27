"""Registered-service enumeration: off by default, capped, and stripped to two fields.

This source is different in kind from every other one in FalconEye. It does not
ask a vendor a question; it makes our own server sign up, log in or start a
password reset at a list of third-party sites, once per site, to see which ones
say "that address is already taken". Enabling it means our IP probes dozens of
services on behalf of whoever typed an address into the box.

So the constraints are the feature:

- off unless the operator sets HOLEHE_ENABLED
- a curated allowlist of services, with no dating, adult or health platforms,
  because "is this person registered at X" is a different question when X is a
  dating or a mental-health site
- a hard wall-clock timeout, because twenty third-party sites will not all answer
- a concurrency cap, so one lookup cannot fan out as fast as it can open sockets
- five lookups per IP per day, an order of magnitude below any other source
- only the service name and a yes/no leave this module: holehe modules also
  return partial recovery emails and partial phone numbers, and those are exactly
  what a people-search tool would want

Every one of those is asserted below, against the shape of the rule rather than
one instance of it: a new module added to the allowlist has to pass the same
tests.
"""
import asyncio
import os
import sqlite3
import time

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import pytest

from app.holehe import client as holehe
from app.utils import cache


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "holehe.db")
    monkeypatch.setattr(cache, "DB_PATH", path)
    from app.utils import rate_limit
    monkeypatch.setattr(rate_limit, "DB_PATH", path)
    holehe.init()
    return path


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(holehe.config, "HOLEHE_ENABLED", True)


def _fake_module(name, exists, *, extra=None, sleep=0.0, boom=False):
    """A stand-in for a holehe module: same (email, client, out) contract."""
    async def module(email, client, out):
        if sleep:
            await asyncio.sleep(sleep)
        if boom:
            raise RuntimeError("module blew up")
        row = {"name": name, "domain": f"{name}.example", "method": "register",
               "frequent_rate_limit": False, "rateLimit": False, "exists": exists,
               "emailrecovery": "j***e@gmail.com", "phoneNumber": "0*****78",
               "others": {"note": "anything at all"}}
        row.update(extra or {})
        out.append(row)
    return module


def _stub_modules(monkeypatch, modules):
    """Replace the loaded module table with (label, callable) pairs."""
    monkeypatch.setattr(holehe, "_load_modules", lambda: modules)


# ---------- the kill switch ----------

def test_disabled_returns_none_and_touches_nothing(db, monkeypatch):
    monkeypatch.setattr(holehe.config, "HOLEHE_ENABLED", False)

    def boom():
        raise AssertionError("modules were loaded while disabled")

    monkeypatch.setattr(holehe, "_load_modules", boom)
    assert asyncio.run(holehe.lookup_email("a@b.example", "1.2.3.4")) is None


def test_the_default_is_off():
    import inspect

    from app import config
    src = inspect.getsource(config)
    assert 'getenv_clean("HOLEHE_ENABLED", "false")' in src, (
        "HOLEHE_ENABLED must default to false: enabling it makes this instance's "
        "IP probe dozens of third-party sites per lookup"
    )


def test_env_example_documents_the_flag_and_what_it_costs():
    text = open(".env.example", encoding="utf-8").read()
    assert "HOLEHE_ENABLED=false" in text
    low = text.lower()
    for needed in ("outbound", "rate limit", "holehe"):
        assert needed in low, f".env.example does not mention {needed!r}"


def test_the_runbook_warns_about_the_outbound_probes():
    text = open("docs/deploy-runbook.md", encoding="utf-8").read().lower()
    assert "holehe" in text
    assert "outbound" in text
    assert "flagged" in text or "blocked" in text


# ---------- the allowlist ----------

def test_the_allowlist_has_no_dating_adult_or_health_services():
    forbidden = (
        "porn", "xnxx", "xvideos", "redtube", "tinder", "badoo", "grindr",
        "okcupid", "match", "adultfriend", "7cups", "sevencups", "caringbridge",
        "webmd", "patient", "therapy", "psych",
    )
    for label, path in holehe.ALLOWLIST:
        blob = f"{label} {path}".lower()
        for word in forbidden:
            assert word not in blob, (
                f"{label} ({path}) looks like a dating, adult or health service; "
                "those are out of scope for this feature"
            )


def test_the_allowlist_excludes_the_module_categories_we_refuse():
    for _label, path in holehe.ALLOWLIST:
        for category in (".porn.", ".medical.", ".dating."):
            assert category not in f".{path}.".replace("/", "."), path


def test_every_allowlisted_module_declares_the_hosts_it_may_reach():
    """A module is third-party code. It gets a transport that can only reach the
    hosts we listed for it, so a module that starts building a URL out of the
    email domain cannot send our traffic somewhere new."""
    for label, path in holehe.ALLOWLIST:
        hosts = holehe.ALLOWED_HOSTS.get(path)
        assert hosts, f"{label} ({path}) has no declared hosts"
        for host in hosts:
            assert "/" not in host and ":" not in host, f"{label}: {host!r} is not a hostname"


def test_the_allowlist_is_a_modest_curated_list():
    assert 5 <= len(holehe.ALLOWLIST) <= 30, (
        f"{len(holehe.ALLOWLIST)} services: the cap exists because every one of "
        "them is an outbound probe from our address"
    )
    labels = [label for label, _ in holehe.ALLOWLIST]
    assert len(labels) == len(set(labels)), "duplicate service labels"


# ---------- only two fields leave this module ----------

def test_only_the_service_name_and_a_yes_no_are_returned(db, enabled, monkeypatch):
    _stub_modules(monkeypatch, [("GitHub", _fake_module("github", True))])
    out = asyncio.run(holehe.lookup_email("a@b.example", "1.2.3.4"))
    assert out["services"] == [{"service": "GitHub", "registered": True}]

    blob = repr(out)
    for leaked in ("gmail.com", "0*****78", "emailrecovery", "phoneNumber",
                   "others", "rateLimit", "method", "domain"):
        assert leaked not in blob, f"{leaked!r} reached the caller: {blob}"


def test_the_service_name_comes_from_our_table_not_the_module(db, enabled, monkeypatch):
    """The module's own `name` field is upstream data. We render the label we
    asked for, so a module cannot put text of its own on our page."""
    _stub_modules(monkeypatch, [
        ("GitHub", _fake_module("<script>alert(1)</script>", True)),
    ])
    out = asyncio.run(holehe.lookup_email("a@b.example", "1.2.3.4"))
    assert out["services"] == [{"service": "GitHub", "registered": True}]


def test_a_module_that_cannot_decide_is_dropped_not_rendered(db, enabled, monkeypatch):
    """exists=None means rate-limited or unparseable. "Unknown" must not be shown
    as "not registered"."""
    _stub_modules(monkeypatch, [
        ("GitHub", _fake_module("github", True)),
        ("Imgur", _fake_module("imgur", None, extra={"rateLimit": True})),
    ])
    out = asyncio.run(holehe.lookup_email("a@b.example", "1.2.3.4"))
    assert out["services"] == [{"service": "GitHub", "registered": True}]
    assert out["checked"] == 1
    assert out["total"] == 2, "the card must be able to say 1 of 2 answered"


def test_a_registered_no_is_reported_as_a_no(db, enabled, monkeypatch):
    _stub_modules(monkeypatch, [("Imgur", _fake_module("imgur", False))])
    out = asyncio.run(holehe.lookup_email("a@b.example", "1.2.3.4"))
    assert out["services"] == [{"service": "Imgur", "registered": False}]
    assert out["found"] is False, "nothing registered anywhere is not a finding"


def test_found_is_true_only_when_something_is_registered(db, enabled, monkeypatch):
    _stub_modules(monkeypatch, [
        ("Imgur", _fake_module("imgur", False)),
        ("GitHub", _fake_module("github", True)),
    ])
    out = asyncio.run(holehe.lookup_email("a@b.example", "1.2.3.4"))
    assert out["found"] is True


# ---------- schema drift ----------

@pytest.mark.parametrize("row", [
    {},
    {"exists": "yes"},
    {"exists": 1},
    {"name": "github"},
    None,
    [],
    "not a dict",
])
def test_a_shape_we_do_not_recognise_is_dropped(db, enabled, monkeypatch, row):
    """holehe is pinned but unmaintained since 2024. A module that changes its
    output must produce no row, never a guess."""
    async def module(email, client, out):
        out.append(row)

    _stub_modules(monkeypatch, [("GitHub", module)])
    out = asyncio.run(holehe.lookup_email("a@b.example", "1.2.3.4"))
    assert out is None or out["services"] == []


def test_a_module_that_raises_is_dropped(db, enabled, monkeypatch):
    _stub_modules(monkeypatch, [
        ("GitHub", _fake_module("github", True, boom=True)),
        ("Imgur", _fake_module("imgur", False)),
    ])
    out = asyncio.run(holehe.lookup_email("a@b.example", "1.2.3.4"))
    assert out["services"] == [{"service": "Imgur", "registered": False}]


def test_every_module_failing_looks_exactly_like_disabled(db, enabled, monkeypatch):
    _stub_modules(monkeypatch, [("GitHub", _fake_module("github", True, boom=True))])
    assert asyncio.run(holehe.lookup_email("a@b.example", "1.2.3.4")) is None


def test_the_library_being_absent_looks_exactly_like_disabled(db, enabled, monkeypatch):
    monkeypatch.setattr(holehe, "_load_modules", lambda: [])
    assert asyncio.run(holehe.lookup_email("a@b.example", "1.2.3.4")) is None


# ---------- the caps ----------

def test_the_wall_clock_timeout_is_enforced(db, enabled, monkeypatch):
    monkeypatch.setattr(holehe.config, "HOLEHE_TIMEOUT_SECONDS", 0.25)
    _stub_modules(monkeypatch, [
        ("GitHub", _fake_module("github", True)),
        ("Slow", _fake_module("slow", True, sleep=5.0)),
    ])
    started = time.monotonic()
    out = asyncio.run(holehe.lookup_email("a@b.example", "1.2.3.4"))
    elapsed = time.monotonic() - started
    assert elapsed < 2.0, f"the timeout did not fire: {elapsed:.2f}s"
    # What finished is still an answer; what did not is simply absent.
    assert out["services"] == [{"service": "GitHub", "registered": True}]
    assert out["checked"] == 1 and out["total"] == 2


def test_nothing_finishing_before_the_timeout_looks_like_disabled(db, enabled, monkeypatch):
    monkeypatch.setattr(holehe.config, "HOLEHE_TIMEOUT_SECONDS", 0.2)
    _stub_modules(monkeypatch, [("Slow", _fake_module("slow", True, sleep=5.0))])
    assert asyncio.run(holehe.lookup_email("a@b.example", "1.2.3.4")) is None


def test_concurrency_is_capped(db, enabled, monkeypatch):
    """One lookup must not open twenty sockets at once from our address."""
    monkeypatch.setattr(holehe.config, "HOLEHE_CONCURRENCY", 3)
    live, peak = {"n": 0}, {"n": 0}

    def tracker(label):
        async def module(email, client, out):
            live["n"] += 1
            peak["n"] = max(peak["n"], live["n"])
            await asyncio.sleep(0.05)
            live["n"] -= 1
            out.append({"name": label, "exists": True, "rateLimit": False})
        return module

    _stub_modules(monkeypatch, [(f"S{i}", tracker(f"s{i}")) for i in range(12)])
    out = asyncio.run(holehe.lookup_email("a@b.example", "1.2.3.4"))
    assert out["checked"] == 12
    assert peak["n"] <= 3, f"{peak['n']} modules ran at once with a cap of 3"


def test_the_concurrency_cap_cannot_be_configured_away(monkeypatch):
    monkeypatch.setenv("HOLEHE_CONCURRENCY", "500")
    import importlib

    from app import config as config_module
    reloaded = importlib.reload(config_module)
    try:
        assert reloaded.HOLEHE_CONCURRENCY <= 8, (
            "the concurrency cap is a property of being a good neighbour, not a "
            "tuning knob"
        )
    finally:
        importlib.reload(reloaded)


def test_the_per_ip_daily_cap_is_five(db, enabled, monkeypatch):
    assert holehe.config.HOLEHE_PER_DAY == 5
    _stub_modules(monkeypatch, [("GitHub", _fake_module("github", True))])
    for i in range(5):
        assert asyncio.run(holehe.lookup_email(f"a{i}@b.example", "9.9.9.9")) is not None
    assert asyncio.run(holehe.lookup_email("a6@b.example", "9.9.9.9")) is None, (
        "the sixth lookup from one IP was allowed"
    )


def test_the_daily_cap_is_per_ip(db, enabled, monkeypatch):
    _stub_modules(monkeypatch, [("GitHub", _fake_module("github", True))])
    for i in range(5):
        asyncio.run(holehe.lookup_email(f"a{i}@b.example", "9.9.9.9"))
    assert asyncio.run(holehe.lookup_email("z@b.example", "8.8.8.8")) is not None


def test_a_cache_hit_does_not_spend_the_daily_cap(db, enabled, monkeypatch):
    calls = {"n": 0}

    def counting(label):
        async def module(email, client, out):
            calls["n"] += 1
            out.append({"name": label, "exists": True, "rateLimit": False})
        return module

    _stub_modules(monkeypatch, [("GitHub", counting("github"))])
    for _ in range(9):
        out = asyncio.run(holehe.lookup_email("same@b.example", "7.7.7.7"))
        assert out["services"] == [{"service": "GitHub", "registered": True}]
    assert calls["n"] == 1, "a cached answer re-probed the third-party sites"


def test_a_failure_is_never_cached(db, enabled, monkeypatch):
    """Otherwise one bad minute pins an empty card for the whole TTL."""
    state = {"boom": True}

    async def module(email, client, out):
        if state["boom"]:
            raise RuntimeError("down")
        out.append({"name": "github", "exists": True, "rateLimit": False})

    _stub_modules(monkeypatch, [("GitHub", module)])
    assert asyncio.run(holehe.lookup_email("x@b.example", "6.6.6.6")) is None
    state["boom"] = False
    out = asyncio.run(holehe.lookup_email("x@b.example", "6.6.6.6"))
    assert out["services"] == [{"service": "GitHub", "registered": True}]


# ---------- the host guard ----------

def test_a_module_cannot_reach_a_host_it_did_not_declare():
    import httpx

    transport = holehe._guarded_transport({"github.com"})
    request = httpx.Request("GET", "https://evil.example/collect")
    with pytest.raises(holehe.BlockedHost):
        asyncio.run(transport.handle_async_request(request))


def test_a_declared_host_and_its_subdomains_pass():
    import httpx

    transport = holehe._guarded_transport({"spotify.com"})
    for url in ("https://spotify.com/x", "https://spclient.wg.spotify.com/y"):
        request = httpx.Request("GET", url)
        assert transport._allowed(request.url.host) is True, url
    assert transport._allowed("notspotify.com") is False
    assert transport._allowed("spotify.com.evil.example") is False


# ---------- tables ----------

def test_the_source_creates_its_own_tables(db):
    conn = sqlite3.connect(db)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert holehe.CACHE_TABLE in names
    assert holehe.RATE_LIMIT_TABLE in names


def test_it_does_not_share_another_sources_tables():
    from app.hudsonrock import client as hudsonrock
    assert holehe.CACHE_TABLE != hudsonrock.CACHE_TABLE
    assert holehe.RATE_LIMIT_TABLE != hudsonrock.RATE_LIMIT_TABLE


# ---------- wiring ----------

def test_the_email_tab_attaches_it_outside_its_own_cache():
    import inspect

    from app.routers import email_header
    src = inspect.getsource(email_header)
    assert "holehe.lookup_email" in src
    cache_set = src.index("cache.set(_CACHE_TABLE, header_id, parsed")
    attach = src.rindex('parsed["holehe"]')
    assert attach > cache_set, (
        "the enumeration result is being written into the 24 hour analysis "
        "cache; it has its own cache and its own per-IP cap"
    )


def test_it_is_not_wired_into_any_other_tab():
    import pathlib

    for path in pathlib.Path("app").rglob("*.py"):
        if path.parts[1] == "holehe":
            continue
        text = path.read_text(encoding="utf-8")
        if "holehe" not in text:
            continue
        assert path.name == "email_header.py" or path.name == "config.py", (
            f"{path} references holehe; this source is Email Risk Assessment only"
        )


def test_the_card_names_the_source():
    js = open("app/static/app.js", encoding="utf-8").read()
    assert "renderHoleheCard" in js
    assert "holehe" in js.lower()
    assert "github.com/megadose/holehe" in js, "the attribution link is missing"


# ---------- the real library, when it is installed ----------

def test_every_allowlisted_module_exists_in_the_installed_library():
    """A drift guard for the library itself: holehe is pinned at 1.61 and
    unmaintained, so a module that is renamed or dropped must fail here rather
    than silently disappear from the card."""
    pytest.importorskip("holehe", reason="holehe is an optional dependency")
    import importlib

    for label, path in holehe.ALLOWLIST:
        name = path.rsplit(".", 1)[-1]
        module = importlib.import_module(f"holehe.modules.{path}")
        func = getattr(module, name, None)
        assert callable(func), f"{label}: holehe.modules.{path}.{name} is not callable"
        import inspect
        params = list(inspect.signature(func).parameters)
        assert params == ["email", "client", "out"], (
            f"{label}: signature changed to {params}"
        )


def test_the_installed_library_is_the_pinned_version():
    pytest.importorskip("holehe", reason="holehe is an optional dependency")
    from holehe import core
    assert core.__version__ == "1.61", (
        f"holehe {core.__version__} is installed; the allowlist and the host "
        "guard were read from 1.61"
    )
