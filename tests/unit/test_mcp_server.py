"""The MCP server exposes the app's own endpoints, and nothing person-centric.

app/mcp_server.py is a stdio server for one operator on their own box. It adds no
analysis of its own: each tool is a thin call onto the same HTTP route the tab
uses, in-process, so the per-IP rate limits, the SSRF guard in the URL expander,
the prompt-safety wrapping in the LLM paths and the output sanitisation all apply
exactly as they do to a browser request. If a tool ever grows its own copy of an
endpoint's logic, these tests are where that shows up.

Two boundaries are asserted here rather than left to review:

1. The seven tools are the seven, and none of the person-centric tabs (username
   enumeration, phone, Telegram, reverse image search, sockpuppet, dork
   generator) is reachable through MCP.
2. Every tool resolves to the very same function object the HTTP app routes to.

The SDK is not a dependency of the web app (see docs/mcp.md: mcp 2.2.0
requires uvicorn>=0.31.1 and this deployment pins 0.29.0 for the gunicorn worker
class), so the tests that build a real server skip when it is absent. Everything
about the tool table itself runs without it.
"""
import io
import os
import sys

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import pytest

from app import mcp_server
from app.ransomware import routes as ransomware_routes
from app.routers import (
    domain_intel,
    email_header,
    ip_intel,
    qr_analyzer,
    script_decoder,
    url_expander,
)

EXPECTED = {
    "ip_reputation": ip_intel.lookup_ip,
    "domain_intel": domain_intel.lookup_domain,
    "email_header_analyze": email_header.analyze,
    "script_decode": script_decoder.decode,
    "url_expand": url_expander.expand,
    "qr_analyze": qr_analyzer.decode,
    "ransomware_watch_search": ransomware_routes.search_victims,
}

# Tabs that answer questions about a person rather than about an indicator. Out
# of scope for MCP on purpose: behind an agent they turn a compromise check into
# people-search, which is the same line app/hudsonrock/client.py draws.
FORBIDDEN_SUBSTRINGS = (
    "username", "user_name", "phone", "telegram", "sockpuppet", "persona",
    "image_search", "reverse_image", "dork", "prospect", "breach",
)


# ---------- 1. the tool table ----------

def test_exactly_the_seven_tools_are_registered():
    assert set(mcp_server.tool_names()) == set(EXPECTED)
    assert len(mcp_server.TOOLS) == 7


def test_tool_names_are_unique():
    names = list(mcp_server.tool_names())
    assert len(names) == len(set(names))


@pytest.mark.parametrize("needle", FORBIDDEN_SUBSTRINGS)
def test_no_person_centric_tool_is_exposed(needle):
    for tool in mcp_server.TOOLS:
        haystack = f"{tool.name} {tool.path}".lower()
        assert needle not in haystack, (
            f"tool {tool.name!r} ({tool.path}) reaches the {needle!r} surface; "
            "person-centric tabs are deliberately not exposed over MCP"
        )


def test_the_module_does_not_import_the_person_centric_routers():
    src = open("app/mcp_server.py", encoding="utf-8").read()
    for needle in ("username", "telegram", "sockpuppet", "image_search",
                   "dork_generator", "prospect", "breach"):
        assert f"import {needle}" not in src and f"{needle} import" not in src, (
            f"{needle} is imported by the MCP server"
        )


# ---------- 2. same code path as the router ----------

def _api_routes():
    """Every APIRoute on the app.

    This FastAPI/Starlette pair wraps each include_router() call in an
    _IncludedRouter rather than flattening it into app.routes, so the real routes
    live one level down.
    """
    from app.main import app

    found, seen = [], set()

    def walk(routes):
        for route in routes:
            if id(route) in seen:
                continue
            seen.add(id(route))
            if getattr(route, "endpoint", None) is not None and getattr(route, "path", None):
                found.append(route)
            inner = getattr(route, "original_router", None)
            if inner is not None:
                walk(getattr(inner, "routes", []))
            walk(getattr(route, "routes", []))

    walk(app.routes)
    return found


def _route_for(tool):
    for route in _api_routes():
        if route.path == tool.path and tool.method in (getattr(route, "methods", None) or set()):
            return route
    raise AssertionError(f"no {tool.method} {tool.path} route on the app")


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_each_tool_resolves_to_the_routers_own_function(name):
    tool = mcp_server.by_name(name)
    route = _route_for(tool)
    expected = EXPECTED[name]
    endpoint = route.endpoint
    # FastAPI keeps the decorated function; unwrap the rate limiter's wrapper.
    unwrapped = getattr(endpoint, "__wrapped__", endpoint)
    expected_unwrapped = getattr(expected, "__wrapped__", expected)
    assert endpoint is expected or unwrapped is expected_unwrapped, (
        f"{name} does not go through {expected.__module__}.{expected.__name__}; "
        "an MCP tool must not reimplement an endpoint"
    )


def test_no_tool_body_reimplements_analysis():
    """Every handler is a call to _request(); nothing else is allowed to be long."""
    import inspect

    for tool in mcp_server.TOOLS:
        src = inspect.getsource(tool.handler)
        assert "_request(" in src, f"{tool.name} does not go through the app"
        # A thin wrapper. The cap is generous, the point is that analysis cannot
        # quietly move in here.
        assert len(src.splitlines()) <= 40, f"{tool.name} has grown a body of its own"


# ---------- 3. descriptions ----------

@pytest.mark.parametrize("tool", mcp_server.TOOLS, ids=lambda t: t.name)
def test_every_description_states_the_input_and_the_cache(tool):
    d = tool.description
    assert len(d) > 60, f"{tool.name}: description too thin to be useful"
    assert tool.input_hint.lower() in d.lower(), (
        f"{tool.name}: the description does not say what the input is "
        f"({tool.input_hint})"
    )
    assert "cache" in d.lower(), f"{tool.name}: the description does not state the cache TTL"


@pytest.mark.parametrize("name", ["script_decode", "email_header_analyze"])
def test_the_llm_tools_say_whose_budget_they_spend(name):
    d = mcp_server.by_name(name).description.lower()
    assert "llm" in d
    assert "budget" in d or "spends" in d, f"{name} does not say it costs the operator"
    assert "daily" in d and "cap" in d, f"{name} does not mention the daily cap"


def test_the_non_llm_tools_do_not_claim_an_llm_cost():
    for name in ("ip_reputation", "domain_intel", "url_expand", "qr_analyze",
                 "ransomware_watch_search"):
        assert "llm budget" not in mcp_server.by_name(name).description.lower()


# ---------- 4. stdio only ----------

def test_the_server_speaks_stdio_and_nothing_else():
    src = open("app/mcp_server.py", encoding="utf-8").read()
    assert 'transport="stdio"' in src
    for forbidden in ("streamable-http", "streamable_http", "run_sse", "sse_app",
                      "run_streamable_http", "uvicorn.run", "uvicorn.Server",
                      ".listen(", "bind("):
        assert forbidden not in src, (
            f"{forbidden!r} appears in the MCP server: this is stdio only, there "
            "is no listener and no auth layer to protect one"
        )


def test_there_is_no_key_table_or_auth_layer():
    """Local mode has no authentication because it has nothing to authenticate:
    the only caller is the user who launched the process."""
    import re

    src = open("app/mcp_server.py", encoding="utf-8").read()
    patterns = (
        r"Authorization",         # an auth header
        r"Bearer",
        r"X-Api-Key",
        r"CREATE TABLE",          # no key table (per-investigator keys are out of scope)
        r"keys\s*=\s*\{",        # nor a dict standing in for one
        r"def authenticate",
        r"secrets\.compare_digest",
    )
    for pattern in patterns:
        assert not re.search(pattern, src, re.I), (
            f"{pattern!r} in the MCP server: local mode has no auth layer and no "
            "key table"
        )


def test_importing_the_server_writes_nothing_to_stdout():
    """stdout is the protocol channel: one stray print corrupts every message."""
    import importlib

    buf = io.StringIO()
    real = sys.stdout
    sys.stdout = buf
    try:
        importlib.reload(mcp_server)
    finally:
        sys.stdout = real
    assert buf.getvalue() == "", f"the MCP server wrote to stdout: {buf.getvalue()!r}"


def test_logging_is_pointed_at_stderr():
    """The app logs on import. Those records must not land on stdout."""
    import logging

    mcp_server.silence_stdout_logging()
    for name in ("falconeye", "root"):
        logger = logging.getLogger(None if name == "root" else name)
        for handler in logger.handlers:
            stream = getattr(handler, "stream", None)
            assert stream is not sys.stdout, (
                f"a {name} log handler writes to stdout, which is the MCP wire"
            )


# ---------- 5. it starts with a bare .env ----------

_KEYS = ("ABUSEIPDB_KEY", "VT_KEY", "OTX_API_KEY", "ABUSECH_AUTH_KEY", "CENSYS_PAT",
         "ANTHROPIC_API_KEY", "GREYNOISE_API_KEY", "HIBP_API_KEY", "SEARCHAPI_KEY",
         "TELEGRAM_API_ID", "TELEGRAM_API_HASH", "TELEGRAM_BOT_TOKEN")


def test_the_tool_table_builds_with_no_keys_at_all(monkeypatch):
    for key in _KEYS:
        monkeypatch.delenv(key, raising=False)
    assert len(mcp_server.TOOLS) == 7
    assert set(mcp_server.tool_names()) == set(EXPECTED)


def test_the_server_builds_with_no_keys_at_all(monkeypatch):
    pytest.importorskip("mcp", reason="the MCP SDK is not installed in this venv")
    for key in _KEYS:
        monkeypatch.delenv(key, raising=False)
    import asyncio

    server = mcp_server.build_server()
    registered = {t.name for t in asyncio.run(server.list_tools())}
    assert registered == set(EXPECTED), registered


def test_the_registered_schemas_name_their_arguments():
    pytest.importorskip("mcp", reason="the MCP SDK is not installed in this venv")
    import asyncio

    server = mcp_server.build_server()
    tools = asyncio.run(server.list_tools())
    # mcp 2.x exposes the JSON Schema as input_schema (serialised as inputSchema).
    schemas = {t.name: (getattr(t, "input_schema", None) or {}).get("properties", {})
               for t in tools}
    assert "ip" in schemas["ip_reputation"]
    assert "domain" in schemas["domain_intel"]
    assert "raw_header" in schemas["email_header_analyze"]
    assert "code" in schemas["script_decode"]
    assert "url" in schemas["url_expand"]
    assert "query" in schemas["ransomware_watch_search"]


# ---------- 6. a real round trip ----------

def test_ip_reputation_returns_what_the_endpoint_returns(monkeypatch):
    import asyncio

    ip_intel.limiter.enabled = False

    async def shodan(c, ip): return {"ports": [80], "vulns": []}
    async def gn(c, ip): return {"classification": "benign"}
    async def ripe(c, ip): return {"asn": 64500, "asn_holder": "Example", "country": "PH"}
    async def uh(c, ip): return {"query_status": "no_results"}
    async def ptr(ip): return []
    async def asn(client, db, ip): return {"available": False}

    async def repsrc(ip, client, only=None):
        from app.ip_sources.base import OK, SourceResult
        names = list(only) if only else list(ip_intel.reputation.ALL_NAMES)
        return {n: SourceResult(n, True, OK, {"ports": []}, None).as_dict() for n in names}

    monkeypatch.setattr(ip_intel, "fetch_shodan_internetdb", shodan)
    monkeypatch.setattr(ip_intel, "fetch_greynoise", gn)
    monkeypatch.setattr(ip_intel, "fetch_ripestat", ripe)
    monkeypatch.setattr(ip_intel, "fetch_urlhaus_host", uh)
    monkeypatch.setattr(ip_intel, "fetch_reverse_dns", ptr)
    monkeypatch.setattr(ip_intel.asn_intel, "fetch", asn)
    monkeypatch.setattr(ip_intel.reputation, "fetch_sources", repsrc)

    out = asyncio.run(mcp_server.ip_reputation("62.60.130.193", refresh=True))
    assert out["ip"] == "62.60.130.193"
    assert out["reputation"]["verdict"]["sources_total"] == 4


def test_a_rejected_input_comes_back_as_a_tool_error():
    import asyncio

    with pytest.raises(mcp_server.ToolFailure) as ei:
        asyncio.run(mcp_server.ip_reputation("10.0.0.1"))
    assert "400" in str(ei.value) or "Invalid" in str(ei.value)


def test_a_missing_qr_file_is_a_tool_error_not_a_traceback():
    import asyncio

    with pytest.raises(mcp_server.ToolFailure):
        asyncio.run(mcp_server.qr_analyze(image_path="/nonexistent/qr.png"))


def test_qr_analyze_needs_one_of_its_two_inputs():
    import asyncio

    with pytest.raises(mcp_server.ToolFailure):
        asyncio.run(mcp_server.qr_analyze())


# ---------- 7. the client sees the API's own message ----------

def test_a_rejected_input_reaches_the_client_as_the_apis_own_message():
    """Without the ToolError bridge the client is told only "Error executing
    tool ip_reputation", and the operator cannot tell a bad input from an outage."""
    pytest.importorskip("mcp", reason="the MCP SDK is not installed in this venv")
    import asyncio

    from mcp import Client

    async def run():
        async with Client(mcp_server.build_server()) as client:
            return await client.call_tool("ip_reputation", {"ip": "10.0.0.1"})

    result = asyncio.run(run())
    assert result.is_error is True
    text = " ".join(getattr(c, "text", "") for c in result.content)
    assert "Invalid or non-routable IP address" in text, text
