# FalconEye over MCP (local mode)

`app/mcp_server.py` serves seven FalconEye tools over the Model Context Protocol
on **stdio**, so an operator can drive their own instance from Claude Code or
Claude Desktop.

**This is for self-hosters and private instances. It is not for exposing to the
internet.** There is no listener, no authentication, no key table and no
per-investigator anything: the transport is the parent process's stdin and
stdout, so the only caller is the user who launched it. Do not put it behind a
socket, a tunnel or a reverse proxy. It reads the same `.env` as the web app, so
whoever can call it spends the operator's API quotas and the operator's LLM
budget.

## The tools

| Tool | Input | Route it calls | Cached |
|---|---|---|---|
| `ip_reputation` | public IPv4/IPv6 address | `GET /api/ip/lookup/{ip}` | 6 h |
| `domain_intel` | hostname | `GET /api/domain/lookup/{domain}` | 6 h |
| `email_header_analyze` | raw email header (+ optional body) | `POST /api/email-header/analyze` | 24 h |
| `script_decode` | script source (+ optional hint) | `POST /api/script-decoder/decode` | 24 h |
| `url_expand` | http/https URL | `POST /api/url/expand` | no |
| `qr_analyze` | local image path or base64 data URI | `POST /api/qr/decode` | no |
| `ransomware_watch_search` | search term, 3+ chars | `GET /api/ransomware/search` | 1 h |

Every tool is a call onto that route, made in-process through httpx's ASGI
transport, so the per-IP rate limits, the SSRF guard, the MIME and size caps, the
prompt-safety wrapping and the output sanitisation all apply unchanged, and a
tool returns exactly the JSON the HTTP API returns.

**Not exposed, deliberately:** username enumeration, phone, Telegram, reverse
image search, sockpuppet generation and the dork generator. Behind an agent those
turn an indicator check into people-search, which is the same line
`app/hudsonrock/client.py` draws. `tests/unit/test_mcp_server.py` fails if one of
them appears.

**Two tools spend money.** `script_decode` and `email_header_analyze` call
Anthropic with this instance's `ANTHROPIC_API_KEY`, under the existing per-day cap
(`LLM_RATE_LIMIT_PER_DAY`). Behind MCP that key is the operator's own, so the
behaviour is unchanged from the tabs; the tool descriptions say so, because
nobody reads the tab's warning when a model is calling the tool.

## Installing the SDK (its own venv)

Verified 2026-09-27:

| Fact | Value | Source |
|---|---|---|
| Package | `mcp` (the official Python SDK; `mcp[cli]` adds the `mcp` CLI) | <https://pypi.org/project/mcp/> |
| Current version | 2.2.0 | PyPI JSON API |
| Python | >= 3.10 | PyPI metadata |
| Transports | stdio, Streamable HTTP, SSE | <https://py.sdk.modelcontextprotocol.io/> |
| API | `from mcp.server import MCPServer`; `server.run(transport="stdio")` | SDK README at tag v2.2.0 |

In the 2.x line **FastMCP was renamed `MCPServer`** and `mcp.server.fastmcp` no
longer exists, so v1 snippets (`from mcp.server.fastmcp import FastMCP`) do not
apply.

`mcp` is **not** in `requirements.txt`, on purpose. It declares
`uvicorn>=0.31.1`, and this deployment pins `uvicorn==0.29.0` because the service
runs `gunicorn --worker-class uvicorn.workers.UvicornWorker` and the whole
client-IP trust model in `docs/deploy-runbook.md` is verified against that
version. Installing the SDK into the app venv would drag uvicorn forward for a
feature the web app does not use. So the MCP server gets its own venv:

```bash
sudo python3 -m venv /opt/falconeye/mcp-venv
sudo /opt/falconeye/mcp-venv/bin/pip install -r /opt/falconeye/app_src/requirements.txt
sudo /opt/falconeye/mcp-venv/bin/pip install 'mcp==2.2.0'
```

The second command upgrades uvicorn **inside that venv only**, which is harmless:
nothing in this venv runs gunicorn. The app venv is untouched.

Check it:

```bash
/opt/falconeye/mcp-venv/bin/python -c 'import mcp; from mcp.server import MCPServer; print("mcp ok")'
```

The server imports the app, so it needs what the app needs: a readable `.env`
(`FALCONEYE_DB`, the API keys) and a writable data directory. Run it as the same
user as the service (`ubuntu`), or it will not be able to open the SQLite
database.

## Registering it with Claude Code

Verified against Claude Code 2.1.274 (`claude mcp add --help`): the command is
`claude mcp add <name> [options] -- <command> [args...]`, stdio is the default
transport, `-e KEY=value` sets environment variables and `-s/--scope` picks
`local` (default), `user` or `project`.

```bash
claude mcp add falconeye \
  -e FALCONEYE_DB=/opt/falconeye/data/falconeye.db \
  -- /opt/falconeye/mcp-venv/bin/python -m app.mcp_server
```

Run it from the checkout (`/opt/falconeye/app_src`), or add `--scope user` and
rely on the server's own `chdir` to the package root, which it does because
`app/main.py` mounts `app/static` relative to the working directory.

Verify, then use it:

```bash
claude mcp list          # falconeye should be listed and health-checked
claude mcp get falconeye # shows the command and the connection state
claude mcp remove falconeye
```

Inside a session the tools appear as `mcp__falconeye__ip_reputation` and so on.

If the keys live in the service's `.env` rather than the shell, pass the ones the
tools need with repeated `-e` flags, or launch the server through a wrapper that
sources the file. Do not put keys on the command line of a shared machine: they
land in the process list.

## Registering it with Claude Desktop

Claude Desktop is macOS and Windows only, so this applies when FalconEye runs on
the same desktop machine, not on the VPS. Claude menu → **Settings** →
**Developer** → **Edit Config**, which opens:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "falconeye": {
      "command": "/opt/falconeye/mcp-venv/bin/python",
      "args": ["-m", "app.mcp_server"],
      "env": {
        "PYTHONPATH": "/opt/falconeye/app_src",
        "FALCONEYE_DB": "/opt/falconeye/data/falconeye.db"
      }
    }
  }
}
```

Paths must be absolute. Quit Claude Desktop completely and reopen it; the server
then appears under the **+** button in the composer → Connectors → Manage
connectors. Its stderr is written to
`~/Library/Logs/Claude/mcp-server-falconeye.log` (macOS) or
`%APPDATA%\Claude\logs\` (Windows), which is where to look when it does not
connect. Stdio servers log everything to stderr, so that file is not only errors.

Source for the config path, the JSON shape and the UI path:
<https://modelcontextprotocol.io/docs/develop/connect-local-servers>.

## Why stdout must stay clean

The stdio binding
(<https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio>)
requires newline-delimited JSON-RPC on stdout, one message per line, and says the
server "MUST NOT write anything to its `stdout` that is not a valid MCP message",
while `stderr` MAY carry any logging. The app configures logging on import, so
`silence_stdout_logging()` moves any handler pointing at stdout over to stderr
before a record can be written, and a test asserts that importing the module
writes nothing to stdout. **Never add a `print()` to anything the server imports.**

The spec also says servers SHOULD exit when stdin closes, which the SDK's stdio
runner handles.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Directory 'app/static' does not exist` | started outside the checkout with an old copy; the module chdirs to its own package root, so this means `app/` is not next to `app/mcp_server.py` |
| `unable to open database file` | `FALCONEYE_DB` unset or not writable by this user |
| Tool returns `HTTP 429: Daily limit reached` | the tab's own per-day cap; MCP calls share the "unknown" IP bucket |
| Tool returns `HTTP 503: ... not configured` | the key that tab needs is missing from the environment the server was launched with |
| Client reports a JSON parse error on every call | something wrote to stdout; check for a `print()` or a new log handler |
