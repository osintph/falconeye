"""
FalconEye over MCP. stdio transport, local mode, one operator.

WHAT THIS IS FOR
----------------
A self-hoster running FalconEye on their own box can point Claude Code or Claude
Desktop at this and use seven of the tabs as tools. It is the operator's own
instance, their own .env and their own quotas, driven from their own editor.

It is NOT a hosted service. There is no listener, no authentication, no key
table and no per-investigator anything: stdio only, so the only way to reach it
is to be the user who launched it. Do not put it behind a socket or a tunnel.
See docs/mcp.md for how to register it, and for why the SDK lives in its
own venv rather than in requirements.txt.

HOW THE TOOLS WORK
------------------
Each tool is a call onto the same HTTP route the browser tab uses, made in
process through httpx's ASGI transport. That is deliberate: the per-IP rate
limits, the SSRF guard in the URL expander, the MIME and size caps on the email
parser, the prompt-safety wrapping on the LLM calls and the output sanitisation
are all in those routes, and a tool that reimplemented any of it would be a
second code path that drifts. The response a tool returns is the response the
HTTP API returns, unchanged.

Two consequences worth knowing:

- The rate limits key on the client IP, and an in-process call has no peer
  address, so every MCP call shares the "unknown" bucket. That is the correct
  behaviour for a single-operator server: the caps still bound how much of an
  upstream quota (or LLM budget) one session can spend.
- Two tools spend money. script_decode and email_header_analyze call Anthropic
  with the operator's own ANTHROPIC_API_KEY under the existing per-day cap. Their
  descriptions say so, because behind an agent nobody sees the tab's warning.

STDOUT IS THE WIRE
------------------
The stdio binding says the server "MUST NOT write anything to its stdout that is
not a valid MCP message" and that stderr MAY carry logging
(https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio).
Importing the app configures logging, so silence_stdout_logging() below moves any
handler pointing at stdout over to stderr before a single record is emitted.
Never print() in this module.
"""
from __future__ import annotations

import functools
import logging
import os
import pathlib
import sys
from dataclasses import dataclass
from typing import Any, Callable

SERVER_NAME = "falconeye"
SERVER_VERSION = "3.34.4"

# app.main mounts StaticFiles(directory="app/static") and that path is relative to
# the process working directory, so importing the app from anywhere else raises.
# A stdio server inherits the client's working directory, which is whatever
# directory the editor happened to be in, so pin it here.
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def silence_stdout_logging() -> None:
    """Move every stdout log handler to stderr. Called before the app is imported.

    app/main.py attaches a StreamHandler to the "falconeye" logger, which defaults
    to stderr and is therefore already correct. This exists so that a future
    handler, or a library that logs to stdout, cannot silently corrupt the
    protocol stream.
    """
    for logger in (logging.getLogger(), logging.getLogger("falconeye")):
        for handler in list(logger.handlers):
            if getattr(handler, "stream", None) is sys.stdout:
                handler.stream = sys.stderr


class ToolFailure(RuntimeError):
    """A tool could not produce a result. Carries the API's own message."""


def _app():
    """The real FastAPI app, imported lazily and from the right directory."""
    os.chdir(_REPO_ROOT)
    silence_stdout_logging()
    from app.main import app as fastapi_app

    silence_stdout_logging()
    return fastapi_app


async def _request(method: str, path: str, *, params: dict | None = None,
                   json_body: dict | None = None, files: dict | None = None) -> Any:
    """One in-process call onto the app, returning the endpoint's own JSON.

    Every guard the HTTP API applies is applied here, because this IS the HTTP
    API: same routers, same middleware, same limiter. A non-2xx becomes a
    ToolFailure carrying the API's `detail`, so the client sees the same message a
    browser would rather than a traceback.
    """
    import httpx

    transport = httpx.ASGITransport(app=_app())
    async with httpx.AsyncClient(transport=transport,
                                 base_url="http://falconeye.invalid") as client:
        response = await client.request(method, path, params=params,
                                        json=json_body, files=files)

    try:
        payload = response.json()
    except Exception:  # noqa: BLE001 - a non-JSON body from our own API is a bug
        payload = {"detail": (response.text or "")[:500]}

    if response.status_code >= 400:
        detail = payload.get("detail") if isinstance(payload, dict) else None
        raise ToolFailure(f"HTTP {response.status_code}: {detail or 'request rejected'}")
    return payload


# ---------------------------------------------------------------- the tools ----
#
# Signatures are the tool schemas: the SDK derives them from the annotations, so
# the argument names below are what a client sees.

async def ip_reputation(ip: str, refresh: bool = False) -> dict:
    """Reputation, ports and ASN for one public IP address."""
    return await _request("GET", f"/api/ip/lookup/{ip}",
                          params={"refresh": "1"} if refresh else None)


async def domain_intel(domain: str, refresh: bool = False) -> dict:
    """Registration, DNS, certificate transparency and hosting for one domain."""
    return await _request("GET", f"/api/domain/lookup/{domain}",
                          params={"refresh": "1"} if refresh else None)


async def email_header_analyze(raw_header: str, raw_body: str = "",
                               refresh: bool = False) -> dict:
    """Authentication results, hop chain and BEC indicators for one email."""
    return await _request("POST", "/api/email-header/analyze", json_body={
        "raw_header": raw_header, "raw_body": raw_body, "refresh": bool(refresh)})


async def script_decode(code: str, hint: str = "") -> dict:
    """Explain one obfuscated script."""
    return await _request("POST", "/api/script-decoder/decode",
                          json_body={"code": code, "hint": hint})


async def url_expand(url: str) -> dict:
    """Follow one shortened or redirecting URL to where it lands."""
    return await _request("POST", "/api/url/expand", json_body={"url": url})


async def qr_analyze(image_path: str = "", data_uri: str = "") -> dict:
    """Decode one QR code image and assess what it points at."""
    if image_path:
        path = pathlib.Path(image_path).expanduser()
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise ToolFailure(f"cannot read {image_path}: {exc.strerror or exc}") from exc
        if size > _QR_MAX_BYTES:
            raise ToolFailure(
                f"{image_path} is {size} bytes; the decoder accepts at most {_QR_MAX_BYTES}")
        try:
            blob = path.read_bytes()
        except OSError as exc:
            raise ToolFailure(f"cannot read {image_path}: {exc.strerror or exc}") from exc
        return await _request("POST", "/api/qr/decode",
                              files={"image": (path.name, blob, "application/octet-stream")})
    if data_uri:
        return await _request("POST", "/api/qr/decode", json_body={"data_uri": data_uri})
    raise ToolFailure("provide image_path (a file on this machine) or data_uri")


async def ransomware_watch_search(query: str) -> dict:
    """Search the local ransomware victim archive."""
    return await _request("GET", "/api/ransomware/search", params={"q": query})


# The endpoint's own cap, so a file that cannot possibly be accepted is rejected
# before it is read into memory.
_QR_MAX_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    handler: Callable
    method: str
    path: str
    input_hint: str


_CACHE = {
    "ip": "Results are cached for 6 hours; pass refresh=true to re-query every source.",
    "domain": "Results are cached for 6 hours; pass refresh=true to re-query every source.",
    "email": "Results are cached for 24 hours; pass refresh=true to re-run the analysis.",
    "script": "Results are cached for 24 hours.",
    "url": "Not cached: every call follows the redirect chain again.",
    "qr": "Not cached: the image is decoded in memory and discarded.",
    "ransomware": "Search results are cached for 1 hour.",
}

_LLM = ("This calls Anthropic with this instance's own ANTHROPIC_API_KEY, so it "
        "spends the operator's LLM budget and counts against the existing daily "
        "cap for LLM calls. When the cap is reached the rest of the analysis "
        "still runs.")

TOOLS: tuple[Tool, ...] = (
    Tool(
        name="ip_reputation",
        input_hint="IP address",
        method="GET",
        path="/api/ip/lookup/{ip}",
        handler=ip_reputation,
        description=(
            "Look up one public IP address: a consensus reputation verdict over "
            "AbuseIPDB, VirusTotal, AlienVault OTX and ThreatFox, geolocation "
            "agreement between sources, open ports and services, known CVEs, "
            "scanner activity and URLhaus history. Input is a single public IPv4 "
            "or IPv6 IP address; private, loopback and reserved ranges are "
            "rejected. A verdict of INCOMPLETE means a source did not answer, "
            "not that the address is clean. " + _CACHE["ip"]
        ),
    ),
    Tool(
        name="domain_intel",
        input_hint="domain name",
        method="GET",
        path="/api/domain/lookup/{domain}",
        handler=domain_intel,
        description=(
            "Look up one domain name: RDAP or WHOIS registration, registrar and "
            "dates, DNS records, certificate transparency history with observed "
            "subdomains, and hosting or ASN attribution for the addresses it "
            "resolves to. Input is a single hostname such as example.com, with no "
            "scheme and no path. " + _CACHE["domain"]
        ),
    ),
    Tool(
        name="email_header_analyze",
        input_hint="raw email header",
        method="POST",
        path="/api/email-header/analyze",
        handler=email_header_analyze,
        description=(
            "Analyse one email: SPF, DKIM and DMARC results, the Received hop "
            "chain with per-hop delays and ASN attribution, display-name and "
            "reply-to mismatches, and business email compromise indicators. Input "
            "is the raw email header text, optionally with the message body as "
            "raw_body, which is what enables the scam-pattern and LLM passes. "
            + _LLM + " " + _CACHE["email"]
        ),
    ),
    Tool(
        name="script_decode",
        input_hint="script source",
        method="POST",
        path="/api/script-decoder/decode",
        handler=script_decode,
        description=(
            "Explain one obfuscated or packed script: what it does, the "
            "techniques it uses, the indicators it contains and how dangerous it "
            "looks. Input is the script source as text (JavaScript, PowerShell, "
            "VBScript, a base64 blob), optionally with a hint describing where it "
            "came from. " + _LLM + " " + _CACHE["script"]
        ),
    ),
    Tool(
        name="url_expand",
        input_hint="URL",
        method="POST",
        path="/api/url/expand",
        handler=url_expand,
        description=(
            "Follow one shortened or redirecting URL to its final destination and "
            "report every hop, the TLS certificate at the end, and any risk "
            "signals on the way. Input is a single http or https URL. The fetch "
            "goes through the SSRF guard, so a URL that resolves to a private or "
            "link-local address is refused rather than followed. " + _CACHE["url"]
        ),
    ),
    Tool(
        name="qr_analyze",
        input_hint="QR code image",
        method="POST",
        path="/api/qr/decode",
        handler=qr_analyze,
        description=(
            "Decode one QR code image and assess what it points at, including "
            "payload type, any redirect chain behind a shortened link, and "
            "quishing indicators. Input is a QR code image: either image_path, a "
            "path to a file on the machine running this server, or data_uri, a "
            "base64 data URI. Maximum 5 MB. " + _CACHE["qr"]
        ),
    ),
    Tool(
        name="ransomware_watch_search",
        input_hint="search term",
        method="GET",
        path="/api/ransomware/search",
        handler=ransomware_watch_search,
        description=(
            "Search this instance's local archive of ransomware leak-site victim "
            "postings by victim name, sector or group. Input is a search term of "
            "at least three characters. The archive is what this instance has "
            "collected, so an absence of results is not evidence that a victim "
            "was never posted. " + _CACHE["ransomware"]
        ),
    ),
)


def tool_names() -> tuple[str, ...]:
    return tuple(t.name for t in TOOLS)


def by_name(name: str) -> Tool:
    for tool in TOOLS:
        if tool.name == name:
            return tool
    raise KeyError(name)


def _bridged(handler, tool_error):
    """Turn a ToolFailure into the SDK's own anticipated-failure type.

    Without this the SDK wraps any exception in UnexpectedToolError and the
    client is told only "Error executing tool ip_reputation". The endpoint's own
    message ("Invalid or non-routable IP address") is the useful part, and the
    SDK forwards it when the tool raises ToolError. functools.wraps keeps
    __wrapped__, which is what the schema is derived from, so the argument names
    a client sees are still the handler's own.
    """
    @functools.wraps(handler)
    async def wrapper(*args, **kwargs):
        try:
            return await handler(*args, **kwargs)
        except ToolFailure as exc:
            raise tool_error(str(exc)) from exc

    return wrapper


def build_server():
    """Register the tools on an MCP server. Imports the SDK, nothing else does.

    Verified 2026-09-27 against mcp 2.2.0: FastMCP was renamed MCPServer in the
    2.x line (`from mcp.server import MCPServer`), and `mcp.server.fastmcp` no
    longer exists. See docs/mcp.md.
    """
    from mcp.server import MCPServer
    from mcp.server.mcpserver.exceptions import ToolError

    server = MCPServer(
        name=SERVER_NAME,
        version=SERVER_VERSION,
        instructions=(
            "FalconEye OSINT tools, served from one operator's own instance. "
            "Every result is third-party data reported as-is: it is evidence to "
            "check, not a verdict to act on. Two tools spend the operator's LLM "
            "budget, see their descriptions."
        ),
    )
    for tool in TOOLS:
        server.add_tool(_bridged(tool.handler, ToolError),
                        name=tool.name, description=tool.description)
    return server


def main() -> None:
    """Serve on stdio. The only entry point."""
    silence_stdout_logging()
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
