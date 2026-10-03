"""
Start the MCP server the way a client does and make it list its tools.

    cd /opt/falconeye/app_src && /opt/falconeye/mcp-venv/bin/python scripts/mcp_check.py

Run by scripts/upgrade.sh (fe_check_mcp) after every upgrade, as the service
user with the service's .env loaded. It is the equivalent of `claude mcp list`'s
health check, without needing Claude Code on the box: spawn
``python -m app.mcp_server`` over stdio, send initialize and tools/list, and
compare the answer with the tools the server module declares.

WHY IT EXISTS
-------------
v3.36.0's upgrade reinstalled requirements.txt into the MCP venv, which pins a
uvicorn older than the MCP SDK requires. Nothing failed, nothing was printed,
and the box was left with an MCP venv in a state its own SDK does not support.
A check that only imports the module would not have caught it either; one that
runs the protocol end to end catches every way the server can fail to answer.

Exit 0 when the server answered with every declared tool, 1 otherwise.
"""
from __future__ import annotations

import asyncio
import os
import pathlib
import sys

TIMEOUT_SECONDS = 60
ROOT = pathlib.Path(__file__).resolve().parents[1]


async def _list_tools(python: str) -> list[str]:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    params = StdioServerParameters(command=python, args=["-m", "app.mcp_server"],
                                   env=dict(os.environ), cwd=str(ROOT))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
    return sorted(tool.name for tool in result.tools)


def main() -> int:
    python = sys.argv[1] if len(sys.argv) > 1 else sys.executable
    sys.path.insert(0, str(ROOT))
    try:
        from app.mcp_server import tool_names
        expected = sorted(tool_names())
    except Exception as exc:  # noqa: BLE001 - any failure here is the answer
        print(f"mcp_check: the server module does not import: {exc}", file=sys.stderr)
        return 1

    try:
        listed = asyncio.run(asyncio.wait_for(_list_tools(python), TIMEOUT_SECONDS))
    except Exception as exc:  # noqa: BLE001
        print(f"mcp_check: the server did not answer over stdio: {exc!r}", file=sys.stderr)
        return 1

    if listed != expected:
        print(f"mcp_check: tools listed {listed}, declared {expected}", file=sys.stderr)
        return 1
    print(f"mcp_check: ok, {len(listed)} tools: {', '.join(listed)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
