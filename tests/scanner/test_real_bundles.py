"""
Regression tests against the real Operation Paper Rabbit bundles.

Why this file exists
--------------------
The synthesized fixture scored STRONG MATCH while the real entry bundle scored
92 with the socket_channels signal dead, because the fixture registered its
channels with socket.on("config", ...) and the real kit does not: it registers
them through a wrapper that stores handlers in a Map. A fixture that is not
representative of the real artifact is a test that passes while the product is
broken, so the real bundles are checked here directly.

The bundles are live phishing kit source and are deliberately NOT committed to
this repository. Point the tests at a local copy:

    export FALCONEYE_KIT_BUNDLES=/path/to/bundles
    pytest tests/scanner/test_real_bundles.py

They are on the FalconEye VPS in the ubuntu home directory. Without them these
tests skip, so CI stays green; the fixture tests in test_kit_analyzer.py cover
the same behaviour on every run.

Expected sha256 (from the published teardown's indicator table) is asserted, so
a swapped or truncated file fails loudly rather than silently weakening the test.
"""

import hashlib
import os
import pathlib

import pytest

from app.scanner import kit_analyzer, rabbithunt_sig

BUNDLES = {
    "B3_5Glc7.js": "057a6dbdfb00f18f6542b62e531df344eb246d2bd5128de1e8ed36061d78a361",
    "CS7qCa7O.js": "84b2c89ddf9e9b637b2b2886f5772c6d368b51546356a9adc88fa1a81bb8fac7",
    "D2c36igU.js": "08ddd24c236084d324a27b8287a3833a62facd69d50e01476d43ca410c24eb7d",
}

_SEARCH_PATHS = [
    os.environ.get("FALCONEYE_KIT_BUNDLES", ""),
    os.path.expanduser("~/kit-bundles"),
    os.path.expanduser("~"),
]


def _find(name: str):
    for base in _SEARCH_PATHS:
        if not base:
            continue
        candidate = pathlib.Path(base) / name
        if candidate.is_file():
            return candidate
    return None


def _load(name: str) -> str:
    path = _find(name)
    if path is None:
        pytest.skip(
            f"{name} not available. Set FALCONEYE_KIT_BUNDLES to a directory "
            "holding the real kit bundles to run this test."
        )
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == BUNDLES[name], (
        f"{name} sha256 is {digest}, expected {BUNDLES[name]}. "
        "This is not the bundle these assertions were written against."
    )
    return raw.decode("utf-8", "replace")


@pytest.fixture(scope="module")
def signature():
    return rabbithunt_sig.get_signature()


# ---------------------------------------------------------------------------
# The kit chunk: everything of interest lives here
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def kit_chunk(signature):
    return kit_analyzer.analyze(_load("B3_5Glc7.js"), signature=signature)


def test_kit_chunk_decodes(kit_chunk):
    assert kit_chunk["error"] is None
    assert kit_chunk["decode_score"] == 1.0
    assert kit_chunk["table_entries"] == 1489


def test_kit_chunk_socket_channels_are_found(kit_chunk):
    """The regression this file was added for.

    config and operation are registered through a handler wrapper, never with
    socket.on, so an extractor that only reads .on()/.emit() finds neither.
    """
    channels = set(kit_chunk["socket"]["channels"])
    assert "config" in channels
    assert "operation" in channels


def test_kit_chunk_socket_config(kit_chunk):
    sock = kit_chunk["socket"]
    assert sock["path"] == "/console"
    assert sock["transports"] == ["websocket", "polling"]
    # Library markers live in the vendor chunk, but this bundle plainly
    # configures a socket, so `present` must not contradict the rest of the dict.
    assert sock["present"] is True


def test_kit_chunk_scores_strong_match(kit_chunk):
    result = rabbithunt_sig.score_bundle(kit_chunk)
    assert result["verdict"] == "STRONG MATCH"
    assert result["score_pct"] >= 95, (
        "regression: real kit chunk should score at or near full marks, got "
        f"{result['score_pct']}%"
    )


def test_kit_chunk_socket_channels_signal_hits(kit_chunk):
    """The weight-5 signal must actually be live, not silently dead."""
    result = rabbithunt_sig.score_bundle(kit_chunk)
    by_name = {s["name"]: s for s in result["signals"]}
    assert by_name["socket_channels"]["hit"] is True, \
        f"socket_channels missed: {by_name['socket_channels']['detail']}"
    assert by_name["socket_path"]["hit"] is True
    assert by_name["socket_channels"]["weight"] == 5


def test_kit_chunk_ground_truth_material(kit_chunk):
    pairs = {p["role"]: (p["key"], p["iv"]) for p in kit_chunk["crypto"]["pairs"]}
    assert pairs["storage"] == ("NLFRWBHXVQJTCPYK", "DMAGSZEIOPQUNTVC")
    assert pairs["transport"] == ("ZQMWLSPXJRDHKTNV", "YFBCUENAGPQLXJWR")

    keys = {k["name"]: k["md5"] for k in kit_chunk["storage_keys"]}
    assert keys["t_config"] == "2e14a1ac17c37597f4579a51c5f26330"

    assert len(kit_chunk["cjk_strings"]) == 11
    assert all(c["gloss"] for c in kit_chunk["cjk_strings"])

    routes = set(kit_chunk["hash_routes"])
    assert {"/phoneCode", "/emailCode", "/pinCode", "/appCode",
            "/tempCustomCode", "/expressCvv"} <= routes
    assert "/console" not in routes, "the socket path is not a victim view"

    assert {"GB", "US"} <= set(kit_chunk["locales"])


# ---------------------------------------------------------------------------
# The other two chunks must NOT match the signature
# ---------------------------------------------------------------------------

def test_entry_loader_does_not_match(signature):
    """The script-src entry is a thin loader and carries none of the signature.

    This is why the report analyzes every bundle and promotes the richest,
    rather than trusting the script tag.
    """
    analysis = kit_analyzer.analyze(_load("CS7qCa7O.js"), signature=signature)
    result = rabbithunt_sig.score_bundle(analysis)
    assert result["verdict"] == "NO MATCH"
    assert analysis["socket"]["path"] == ""
    assert analysis["crypto"]["pairs"] == []


def test_vendor_chunk_does_not_match(signature):
    """The vendor chunk holds the socket.io library, not the kit.

    Its own engine.io channel names must not be mistaken for the kit's.
    """
    analysis = kit_analyzer.analyze(_load("D2c36igU.js"), signature=signature)
    result = rabbithunt_sig.score_bundle(analysis)
    assert result["verdict"] == "NO MATCH"
    channels = set(analysis["socket"]["channels"])
    assert "config" not in channels
    assert "operation" not in channels


def test_only_the_kit_chunk_wins_promotion(signature):
    """The richest analysis is the kit chunk, not the entry or the vendor chunk."""
    scored = []
    for name in ("CS7qCa7O.js", "B3_5Glc7.js", "D2c36igU.js"):
        analysis = kit_analyzer.analyze(_load(name), signature=signature)
        scored.append((analysis, rabbithunt_sig.score_bundle(analysis)))

    from app.scanner import kit_report
    assert kit_report._pick_primary(scored) == 1
