"""
Unit tests for app/scanner/rabbithunt_sig.py

Covers the transparent scorer (hits AND misses reported, weighted), the
signature registry staying data-only, and the path-scoped socket.io probe that
is the highest-signal live discriminator.
"""

import pytest

from app.scanner import kit_analyzer, rabbithunt_sig
from tests.scanner.kit_fixtures import build_clean_bundle, build_obfuscated_bundle


@pytest.fixture(scope="module")
def analysis():
    return kit_analyzer.analyze(
        build_obfuscated_bundle(), signature=rabbithunt_sig.get_signature()
    )


# ---------- verdict tiers ----------

@pytest.mark.parametrize("pct,expected", [
    (100, "STRONG MATCH"), (70, "STRONG MATCH"),
    (69, "PARTIAL"), (40, "PARTIAL"),
    (39, "WEAK"), (20, "WEAK"),
    (19, "NO MATCH"), (0, "NO MATCH"),
])
def test_verdict_boundaries(pct, expected):
    assert rabbithunt_sig.verdict(pct) == expected


# ---------- bundle scoring ----------

def test_positive_fixture_is_a_strong_match(analysis):
    result = rabbithunt_sig.score_bundle(analysis)
    assert result["verdict"] == "STRONG MATCH"
    assert result["score_pct"] >= 70
    assert result["points"] == result["possible"]


def test_clean_bundle_is_no_match():
    clean = kit_analyzer.analyze(build_clean_bundle())
    result = rabbithunt_sig.score_bundle(clean)
    assert result["verdict"] == "NO MATCH"
    assert result["score_pct"] < 20
    assert result["points"] == 0


def test_every_signal_reports_hit_and_miss_with_a_weight(analysis):
    """Misses are evidence too and must never be hidden."""
    for source in (analysis, kit_analyzer.analyze(build_clean_bundle())):
        result = rabbithunt_sig.score_bundle(source)
        assert result["signals"]
        for signal in result["signals"]:
            assert set(signal) == {"name", "weight", "hit", "detail"}
            assert isinstance(signal["hit"], bool)
            assert signal["weight"] > 0

    clean_signals = rabbithunt_sig.score_bundle(
        kit_analyzer.analyze(build_clean_bundle()))["signals"]
    assert any(s["hit"] is False for s in clean_signals), "misses must be listed"


def test_content_token_names_all_appear_in_the_result(analysis):
    result = rabbithunt_sig.score_bundle(analysis)
    reported = {s["name"] for s in result["signals"]}
    for token in rabbithunt_sig.PAPER_RABBIT["content_tokens"]:
        assert token in reported


def test_raw_text_mode_still_scores_and_flags_itself():
    """Raw source is lower confidence, and the result says so."""
    result = rabbithunt_sig.score_bundle(
        "socket path /console with expressCvv and 解密异常!")
    assert result["note"]
    assert "RAW" in result["note"]
    assert result["score_pct"] > 0


def test_score_bundle_never_raises_on_junk():
    for junk in (None, 123, [], {}, "", b"bytes"):
        result = rabbithunt_sig.score_bundle(junk)
        assert "verdict" in result


# ---------- the path-scoped socket.io signal ----------

def test_path_scoped_signal_fires_on_404_root_and_204_path():
    """The published probe: /socket.io/ 404 while /com/socket.io/ 204."""
    assert rabbithunt_sig.path_scoped_hit(404, 204) is True


def test_path_scoped_signal_does_not_fire_on_404_at_both():
    assert rabbithunt_sig.path_scoped_hit(404, 404) is False


def test_path_scoped_signal_does_not_fire_for_an_ordinary_socketio_app():
    """204 at the root too means a normal socket.io app, not a scoped relay."""
    assert rabbithunt_sig.path_scoped_hit(204, 204) is False


@pytest.mark.parametrize("root,path,expected", [
    (404, 204, True),
    (200, 204, True),
    (None, 204, True),
    (404, 404, False),
    (404, 200, False),
    (404, None, False),
    (None, None, False),
    (204, 204, False),
])
def test_path_scoped_truth_table(root, path, expected):
    assert rabbithunt_sig.path_scoped_hit(root, path) is expected


def test_socketio_signal_carries_the_heaviest_weight():
    """It is the single highest-signal live discriminator, so it must outweigh
    every other network signal on its own."""
    weights = {}

    async def fake_probe(host, path="/"):
        return {
            "root": {"path": "/socket.io/", "status": 404},
            "campaign": {"path": "/com/socket.io/", "status": 204},
            "console": {"path": "/console", "status": 502},
            "console_polling": {"path": "/console/?transport=polling", "status": 400},
        }

    import asyncio

    async def run():
        return await rabbithunt_sig.score_host(
            "example.invalid", "/com/", probe=await fake_probe("h"))

    result = asyncio.run(run())
    for signal in result["signals"]:
        weights[signal["name"]] = signal["weight"]
    assert weights["socketio_path_scoped"] == 10
    assert weights["socketio_path_scoped"] > weights["operator_console_present"]

    fired = {s["name"] for s in result["signals"] if s["hit"]}
    assert "socketio_path_scoped" in fired
    assert "operator_console_present" in fired


# ---------- campaign path derivation ----------

@pytest.mark.parametrize("url,expected", [
    ("https://host.example/com/", "/com/"),
    ("https://host.example/com/index.html", "/com/"),
    ("https://host.example/", "/"),
    ("https://host.example", "/"),
    ("not a url at all", "/"),
])
def test_campaign_path(url, expected):
    assert rabbithunt_sig.campaign_path(url) == expected


# ---------- the registry stays data ----------

def test_signature_is_data_only():
    sig = rabbithunt_sig.get_signature()
    for field in ("crypto_pairs", "storage_keys", "socket", "hash_routes",
                  "locales", "cjk_glossary", "content_tokens", "aes_literals"):
        assert field in sig, f"{field} missing from the signature record"
    assert not any(callable(v) for v in sig.values()), \
        "a signature record must be data, never behaviour"


def test_unknown_signature_id_falls_back_rather_than_raising():
    assert rabbithunt_sig.get_signature("no_such_kit")["id"] == "paper_rabbit"


def test_ground_truth_values_are_intact():
    """These are confirmed values. A change here is a regression, not a tweak."""
    sig = rabbithunt_sig.get_signature()
    pairs = {p["role"]: (p["key"], p["iv"]) for p in sig["crypto_pairs"]}
    assert pairs["storage"] == ("NLFRWBHXVQJTCPYK", "DMAGSZEIOPQUNTVC")
    assert pairs["transport"] == ("ZQMWLSPXJRDHKTNV", "YFBCUENAGPQLXJWR")
    assert sig["storage_keys"] == ["t_config"]
    assert sig["socket"]["path"] == "/console"
    assert sig["socket"]["channels"] == ["config", "operation"]
    assert sig["socket"]["transports"] == ["websocket", "polling"]
    assert len(sig["cjk_glossary"]) == 11
    assert sig["hash_routes"][0] == "/index"
