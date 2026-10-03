"""The CAIDA Hoiho client, against recorded responses. No live calls.

The recorded bodies below are real answers from https://api.hoiho.caida.org,
captured on 2026-10-03 while implementing against the service's OpenAPI
document. They encode three properties of the API that the client has to get
right and that a hand-written mock would probably get wrong:

  * lat and lng are STRINGS, not numbers
  * an unmatched hostname is simply ABSENT from "matches"; there is no
    per-hostname "no match" entry
  * garbage input is answered 200 with the garbage silently unmatched, so an
    empty "matches" means "no rule", never "something went wrong"
"""
import asyncio

import httpx
import pytest

from app.routemap import hoiho


@pytest.fixture(autouse=True)
def cold_cache(monkeypatch):
    """Every test here exercises the network path, so the cache is bypassed.

    Without this a hostname another test (or a developer's live run) already
    cached makes the client correctly skip the request, and the assertion about
    what was sent passes for the wrong reason.
    """
    monkeypatch.setattr("app.utils.cache.get", lambda *a, **k: None)
    monkeypatch.setattr("app.utils.cache.set", lambda *a, **k: None)

# Real response to a POST /lookups of the nine hostnames in the brief.
RECORDED_BATCH = {
    "summary": {"ruleset_date": "2024-08", "hostnames_requested": 9,
                "hostnames_matched": 3},
    "matches": [
        {"hostname": "ix-bundle-21.qcore1.h81-hongkong.as6453.net",
         "match_strs": ["hongkong"], "match_meanings": ["place"],
         "cc": "HK", "place": "Hong Kong", "lat": "22.278320", "lng": "114.174690"},
        {"hostname": "if-bundle-2-2.qcore2.sqn-sanjose.as6453.net",
         "match_strs": ["sanjose"], "match_meanings": ["place"],
         "cc": "US", "place": "San Jose", "st": "CA",
         "lat": "37.339390", "lng": "-121.894960"},
        {"hostname": "if-bundle-61-4.qcore2.ct8-chicago.as6453.net",
         "match_strs": ["chicago"], "match_meanings": ["place"],
         "cc": "US", "place": "Chicago", "st": "IL",
         "lat": "41.850030", "lng": "-87.650050"},
    ],
}

ASKED = [
    "hnk-b4-link.ip.twelve99.net", "sng-b6-link.ip.twelve99.net",
    "mei-b6-link.ip.twelve99.net", "prs-bb2-link.ip.twelve99.net",
    "ffm-bb2-link.ip.twelve99.net",
    "ix-bundle-21.qcore1.h81-hongkong.as6453.net",
    "if-bundle-2-2.qcore2.sqn-sanjose.as6453.net",
    "if-bundle-61-4.qcore2.ct8-chicago.as6453.net",
    "122.2.187.146.static.pldt.net",
]


def test_string_coordinates_become_usable_floats():
    record = hoiho._match_to_record(RECORDED_BATCH["matches"][0])
    assert record["located"] is True
    assert record["lat"] == pytest.approx(22.27832)
    assert record["lng"] == pytest.approx(114.17469)
    assert isinstance(record["lat"], float)


def test_a_match_with_a_place_but_no_coordinates_is_not_located():
    """There is nothing to draw, so it must fall through to the next source."""
    record = hoiho._match_to_record(
        {"hostname": "x.example.net", "place": "Somewhere", "cc": "XX"})
    assert record["located"] is False
    assert record["lat"] is None


@pytest.mark.parametrize("lat,lng", [
    ("not a number", "1.0"), (None, None), ("999", "0"), ("0", "999"),
    ("nan", "1.0"),
])
def test_unusable_coordinates_are_refused(lat, lng):
    record = hoiho._match_to_record({"hostname": "x.example.net", "lat": lat, "lng": lng})
    assert record["located"] is False


def test_the_evidence_for_the_claim_is_carried_through():
    """match_strs is why a hop was placed where it was, and the UI shows it."""
    record = hoiho._match_to_record(RECORDED_BATCH["matches"][1])
    assert record["match_strs"] == ["sanjose"]
    assert record["match_meanings"] == ["place"]


def test_an_unmatched_hostname_is_recorded_as_an_answer(monkeypatch):
    async def _scenario():
        """Absent from "matches" means "no rule", and must be cached as such.

        Otherwise every trace through Arelion re-asks CAIDA for hostnames it has
        already said it cannot place, which is most of the traffic we send them.
        """
        class FakeResponse:
            status_code = 200

            @staticmethod
            def json():
                return RECORDED_BATCH

        async def fake_post(self, *args, **kwargs):
            return FakeResponse()

        monkeypatch.setattr("httpx.AsyncClient.post", fake_post)
        async with httpx.AsyncClient() as client:
            records, ruleset = await hoiho._post_batch(client, ASKED)

        assert ruleset == "2024-08"
        assert set(records) == set(ASKED), "a hostname that was asked about has no record"
        assert records["ix-bundle-21.qcore1.h81-hongkong.as6453.net"]["located"] is True
        for miss in ("hnk-b4-link.ip.twelve99.net", "sng-b6-link.ip.twelve99.net",
                     "122.2.187.146.static.pldt.net"):
            assert records[miss]["located"] is False

    asyncio.run(_scenario())


def test_an_unreachable_api_is_not_an_exception(monkeypatch):
    async def _scenario():
        """A source that did not answer must leave the rest of the trace alone."""
        async def boom(self, *args, **kwargs):
            raise RuntimeError("connection refused")

        monkeypatch.setattr("httpx.AsyncClient.post", boom)
        async with httpx.AsyncClient() as client:
            records, ruleset = await hoiho._post_batch(client, ASKED)
        assert records == {}
        assert ruleset is None

    asyncio.run(_scenario())


def test_nothing_that_is_not_a_router_hostname_is_ever_sent(monkeypatch):
    async def _scenario():
        """The gate on what leaves this server."""
        sent = []

        async def capture(self, url, **kwargs):
            sent.extend(kwargs.get("json") or [])

            class R:
                status_code = 200
                @staticmethod
                def json():
                    return {"summary": {}, "matches": []}
            return R()

        monkeypatch.setattr("httpx.AsyncClient.post", capture)
        await hoiho.lookup(["_gateway", "router", "192.168.1.1", "???",
                            "hnk-b4-link.ip.twelve99.net"])
        assert sent == ["hnk-b4-link.ip.twelve99.net"], (
            f"these left the server and should not have: {sent}")

    asyncio.run(_scenario())


def test_the_source_can_be_switched_off(monkeypatch):
    async def _scenario():
        monkeypatch.setattr(hoiho, "HOIHO_ENABLED", False)
        records, ruleset = await hoiho.lookup(["hnk-b4-link.ip.twelve99.net"])
        assert records == {}
        assert ruleset is None

    asyncio.run(_scenario())
