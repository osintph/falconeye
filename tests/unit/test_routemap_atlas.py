"""The RIPE Atlas client, against recorded responses. No live calls, no key.

The key lives only in the VPS's .env. Nothing here needs it: every test drives
recorded shapes, which is also the only honest way to test the failure paths
(an expired key and an empty balance are not states you can ask for on demand).
"""
import asyncio
import os

import httpx
import pytest

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

from app.routemap import atlas

# A real Atlas traceroute result shape, trimmed to the fields the renderer uses.
RECORDED_RESULT = {
    "fw": 5080, "dst_name": "heise.de", "dst_addr": "193.99.144.80",
    "prb_id": 1018040, "msm_id": 123456789,
    "result": [
        {"hop": 1, "result": [
            {"from": "192.0.2.1", "rtt": 3.7, "size": 28, "ttl": 64},
            {"from": "192.0.2.1", "rtt": 3.5, "size": 28, "ttl": 64},
            {"x": "*"}]},
        {"hop": 2, "result": [{"x": "*"}, {"x": "*"}, {"x": "*"}]},
        {"hop": 3, "result": [
            {"from": "62.115.209.158", "rtt": 55.2, "size": 28, "ttl": 250,
             "name": "hnk-b4-link.ip.twelve99.net"}]},
    ],
}

RECORDED_PROBES = {
    "results": [
        # The operator's own software probe: country "Unknown", which is why
        # selection must not be country-led.
        {"id": 1018040, "asn_v4": 9299, "country_code": None,
         "status": {"name": "Connected"},
         "geometry": {"type": "Point", "coordinates": [121.03, 14.55]}},
        {"id": 2222, "asn_v4": 9299, "country_code": "PH",
         "status": {"name": "Connected"},
         "geometry": {"type": "Point", "coordinates": [123.32, 8.57]}},
    ],
}


@pytest.fixture(autouse=True)
def cold(monkeypatch):
    monkeypatch.setattr("app.utils.cache.get", lambda *a, **k: None)
    monkeypatch.setattr("app.utils.cache.set", lambda *a, **k: None)


# ---------- credits ----------

def test_the_published_cost_of_one_traceroute():
    """RIPE's formula is 10 * N * (int(S/1500) + 1); N=3, S=40 gives 30."""
    assert atlas.TRACEROUTE_CREDITS_PER_RESULT == 30


def test_the_instance_cap_is_enforced_before_the_account_balance():
    """Our own budget is checked first: it costs no request to RIPE."""
    async def _scenario():
        async def should_not_be_called():
            raise AssertionError("the account balance was queried needlessly")

        from app import config
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(atlas, "configured", lambda: True)
            mp.setattr(atlas, "spent_today", lambda: config.ATLAS_DAILY_CREDIT_CAP)
            mp.setattr(atlas, "balance", should_not_be_called)
            with pytest.raises(atlas.AtlasUnavailable) as caught:
                await atlas.check_budget()
            assert caught.value.kind == "credits"
    asyncio.run(_scenario())


def test_an_empty_account_is_refused_even_under_the_cap():
    async def _scenario():
        async def empty():
            return 0

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(atlas, "configured", lambda: True)
            mp.setattr(atlas, "spent_today", lambda: 0)
            mp.setattr(atlas, "balance", empty)
            with pytest.raises(atlas.AtlasUnavailable) as caught:
                await atlas.check_budget()
            assert caught.value.kind == "credits"
    asyncio.run(_scenario())


def test_an_unreadable_balance_does_not_block_a_trace():
    """RIPE's own accounting is authoritative; a failed read is not a refusal."""
    async def _scenario():
        async def unknown():
            return None

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(atlas, "configured", lambda: True)
            mp.setattr(atlas, "spent_today", lambda: 0)
            mp.setattr(atlas, "balance", unknown)
            await atlas.check_budget()
    asyncio.run(_scenario())


def test_an_instance_without_a_key_reports_itself_disabled():
    async def _scenario():
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(atlas, "configured", lambda: False)
            with pytest.raises(atlas.AtlasUnavailable) as caught:
                await atlas.check_budget()
            assert caught.value.kind == "disabled"
    asyncio.run(_scenario())


# ---------- probe selection ----------

def test_a_probe_whose_country_is_unknown_is_still_selected(monkeypatch):
    """Probe 1018040 reports no country. ASN-led selection must still find it."""
    async def _scenario():
        async def fake_get(self, url, **kwargs):
            class R:
                status_code = 200
                @staticmethod
                def json():
                    return RECORDED_PROBES
            return R()

        monkeypatch.setattr("httpx.AsyncClient.get", fake_get)
        probe = await atlas.select_probe(9299, None, (14.6, 121.0))
        assert probe["id"] == 1018040, "the nearest probe on the ASN was not chosen"
        assert probe["distance_km"] < 20
    asyncio.run(_scenario())


def test_probe_selection_never_sends_the_users_coordinates(monkeypatch):
    """The privacy property: RIPE learns the ASN, never where the visitor is."""
    async def _scenario():
        seen = {}

        async def capture(self, url, **kwargs):
            seen["url"] = url
            seen["params"] = kwargs.get("params") or {}

            class R:
                status_code = 200
                @staticmethod
                def json():
                    return RECORDED_PROBES
            return R()

        monkeypatch.setattr("httpx.AsyncClient.get", capture)
        await atlas.select_probe(9299, "PH", (14.6, 121.0))
        flat = f"{seen['url']}?{seen['params']}"
        for leaked in ("14.6", "121.0", "radius", "latitude", "longitude"):
            assert leaked not in flat, (
                f"probe selection sent {leaked!r} to RIPE Atlas: {flat}")
        assert seen["params"].get("asn_v4") == 9299
    asyncio.run(_scenario())


def test_no_probe_anywhere_is_its_own_failure_kind(monkeypatch):
    async def _scenario():
        async def empty(self, url, **kwargs):
            class R:
                status_code = 200
                @staticmethod
                def json():
                    return {"results": []}
            return R()

        monkeypatch.setattr("httpx.AsyncClient.get", empty)
        with pytest.raises(atlas.AtlasUnavailable) as caught:
            await atlas.select_probe(9299, "PH", (14.6, 121.0))
        assert caught.value.kind == "noprobe"
    asyncio.run(_scenario())


# ---------- rendering a result ----------

def test_an_atlas_result_renders_as_traceroute_the_parser_understands():
    """One parser for every source, so a format bug has one place to live."""
    from app.routemap.parse import parse_trace

    text = atlas.to_trace_text(RECORDED_RESULT)
    parsed = parse_trace(text)
    assert parsed.parser == "traceroute"
    assert [h.hop for h in parsed.hops] == [1, 2, 3]
    assert parsed.hops[0].addresses == ["192.0.2.1"]
    assert parsed.hops[0].loss_pct == pytest.approx(33.3)
    assert parsed.hops[1].loss_pct == 100.0
    assert parsed.hops[2].hostnames == ["hnk-b4-link.ip.twelve99.net"]
    assert parsed.hops[2].min_rtt_ms == pytest.approx(55.2)


def test_a_result_with_no_hops_does_not_crash_the_renderer():
    text = atlas.to_trace_text({"dst_name": "x", "dst_addr": "1.1.1.1", "result": []})
    assert "traceroute to x" in text


# ---------- the key ----------

def test_measurement_results_are_fetched_without_the_api_key():
    """The key is scoped to credits and scheduling; results are public."""
    client = atlas._public_client()
    try:
        assert "Authorization" not in client.headers
    finally:
        asyncio.run(client.aclose())


def test_no_log_line_in_this_module_can_carry_key_material():
    import pathlib
    source = pathlib.Path(atlas.__file__).read_text()
    for line in source.splitlines():
        if "log." in line:
            assert "ATLAS_API_KEY" not in line, f"key material in a log line: {line}"
            assert "Authorization" not in line, f"auth header in a log line: {line}"
