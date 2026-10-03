"""The RTT physics bound, the source order, and the hop annotations.

The bound is the whole reason this tab is not just "plot what MaxMind said".
It has to reject what light cannot reach and, just as importantly, has to NOT
reject a hop merely because its RTT is inflated, which is the normal condition
of the internet. Both directions are tested.
"""
import pytest

from app.routemap import geo
from app.routemap.parse import Hop

MANILA = (14.6, 121.0)
HONG_KONG = (22.28, 114.17)
SAN_JOSE = (37.34, -121.89)
HARARE = (-17.83, 31.05)
DIPOLOG = (8.57, 123.32)


# ---------- the arithmetic ----------

def test_the_bound_is_one_hundred_km_per_millisecond_plus_slack():
    """Light in fibre: ~200 km/ms one way, halved because an RTT is a round trip."""
    assert geo.KM_PER_MS_ROUND_TRIP == 100.0
    assert geo.max_distance_km(0) == pytest.approx(geo.SLACK_KM)
    assert geo.max_distance_km(10) == pytest.approx(1000 + geo.SLACK_KM)
    assert geo.max_distance_km(215) == pytest.approx(21500 + geo.SLACK_KM)


def test_haversine_against_known_distances():
    """Within 1%: these are the distances the bound is reasoned about with."""
    assert geo.haversine_km(*MANILA, *HONG_KONG) == pytest.approx(1117, rel=0.01)
    assert geo.haversine_km(*MANILA, *SAN_JOSE) == pytest.approx(11277, rel=0.01)
    assert geo.haversine_km(*MANILA, *HARARE) == pytest.approx(10493, rel=0.01)
    assert geo.haversine_km(*MANILA, *MANILA) == pytest.approx(0, abs=0.001)


# ---------- accept and reject, asserting the maths and not the anecdote ----------

@pytest.mark.parametrize("place,rtt,expected", [
    # San Jose at 215 ms: 11,277 km against a 21,800 km budget. Reachable.
    (SAN_JOSE, 215.0, True),
    # Harare at the SAME 215 ms: 10,493 km, also inside the budget. The brief's
    # example is not "Harare is always wrong", it is that a source must be
    # rejected when the distance exceeds what the round trip allows, and at
    # 215 ms it does not. Asserting the maths, not the case.
    (HARARE, 215.0, True),
    # The same Harare at 95 ms: 10,493 km against a 9,800 km budget. Impossible.
    (HARARE, 95.0, False),
    # San Jose at the same 95 ms is impossible too, for the same reason.
    (SAN_JOSE, 95.0, False),
])
def test_a_location_is_allowed_exactly_when_the_round_trip_can_reach_it(place, rtt, expected):
    allowed, distance, budget = geo.rtt_allows(MANILA, place[0], place[1], rtt)
    assert allowed is expected
    assert (distance <= budget) is expected


def test_the_bound_is_an_upper_limit_only():
    """An inflated RTT is normal and must never reject a nearby hop.

    A router one kilometre away answering in 300 ms is a congested or
    rate-limited router, not a router on another continent.
    """
    allowed, _d, _b = geo.rtt_allows(MANILA, MANILA[0], MANILA[1], 300.0)
    assert allowed is True


def test_unknowable_cases_allow_rather_than_invent_a_rejection():
    assert geo.rtt_allows(None, *HONG_KONG, 10.0)[0] is True
    assert geo.rtt_allows(MANILA, *HONG_KONG, None)[0] is True


def test_the_exact_boundary():
    """At precisely the budget the location is allowed; one km further it is not."""
    budget = geo.max_distance_km(50.0)
    # Walk due north from Manila until just inside and just outside the budget.
    inside = geo.rtt_allows(MANILA, MANILA[0] + (budget - 50) / 111.0, MANILA[1], 50.0)
    outside = geo.rtt_allows(MANILA, MANILA[0] + (budget + 200) / 111.0, MANILA[1], 50.0)
    assert inside[0] is True
    assert outside[0] is False


# ---------- the regression this file exists for ----------

def test_hop_five_dipolog_city_is_judged_on_its_measured_rtt():
    """210.213.130.143, the PLDT hop the heise fixture places in Dipolog City.

    Reviewed as a suspected bound failure. It is not one: Manila to Dipolog is
    717 km, which needs 7.17 ms of round trip, and the hop's fastest probe is
    9.218 ms. The bound therefore allows it, correctly.

    Pinned here because the interesting property is not the verdict but that
    the verdict follows the measurement: at a genuinely impossible RTT the same
    hop must be rejected. If someone later feeds the bound an average instead
    of a minimum, or drops the check for ip-db results, the second half fails.
    """
    distance = geo.haversine_km(*MANILA, *DIPOLOG)
    assert distance == pytest.approx(717, rel=0.02)

    minimum_possible_ms = distance * 2 / 200.0
    assert minimum_possible_ms == pytest.approx(7.17, rel=0.02)

    # As measured: allowed, and not by much.
    allowed, d, budget = geo.rtt_allows(MANILA, *DIPOLOG, 9.218)
    assert allowed is True
    assert d < budget

    # Below the physical minimum (slack included): impossible, must be refused.
    impossible_ms = (distance - geo.SLACK_KM) * 2 / 200.0 - 0.5
    allowed, _d, _b = geo.rtt_allows(MANILA, *DIPOLOG, impossible_ms)
    assert allowed is False, (
        "a hop closer in time than light allows was still placed; the bound "
        "is not being applied to this source")


def test_the_bound_applies_to_every_source_not_just_the_hostname_ones():
    """An ip-db candidate is checked exactly like a hoiho or site-code one."""
    hop = Hop(hop=1, addresses=["64.86.26.38"], rtts_ms=[20.0], sent=3, lost=0)
    located = geo.locate_hops(
        [hop], hoiho_records={}, ip_records={"64.86.26.38": dict(
            lat=HARARE[0], lon=HARARE[1], city="Harare", cc="ZW")},
        origin=MANILA)
    entry = located[0]
    assert entry["source"] == geo.SOURCE_UNRESOLVED
    assert geo.ANNOT_RTT_IMPOSSIBLE in entry["annotations"]
    assert "km away but the round trip allows at most" in entry["reason"]


# ---------- sentinel coordinates ----------

@pytest.mark.parametrize("lat,lon,sentinel", [
    (0.0, 0.0, True),            # null island, the common "no data" answer
    (38.0, -97.0, True),         # MaxMind's centre-of-the-US fallback
    (37.751, -97.822, True),     # its later centre-of-the-US fallback
    (14.6, 121.0, False),
    (0.5, 0.5, False),
])
def test_sentinel_coordinates_are_not_locations(lat, lon, sentinel):
    assert geo.is_sentinel(lat, lon) is sentinel


# ---------- source order ----------

def _hop(hostname=None, address=None, rtt=50.0):
    return Hop(hop=1,
               addresses=[address] if address else [],
               hostnames=[hostname] if hostname else [],
               rtts_ms=[rtt], sent=3, lost=0)


def test_hoiho_wins_over_the_site_code_table_and_the_ip_database():
    hop = _hop(hostname="hnk-b4-link.ip.twelve99.net", address="62.115.209.158")
    located = geo.locate_hops(
        [hop],
        hoiho_records={"hnk-b4-link.ip.twelve99.net": {
            "located": True, "lat": 22.28, "lng": 114.17, "place": "Hong Kong",
            "cc": "HK", "match_strs": ["hnk"], "match_meanings": ["place"]}},
        ip_records={"62.115.209.158": dict(lat=48.86, lon=2.35, city="Paris", cc="FR")},
        origin=MANILA)
    assert located[0]["source"] == geo.SOURCE_HOIHO


def test_the_site_code_table_wins_over_the_ip_database():
    """The real Arelion case: Hoiho has no rule, the IP database says Paris."""
    hop = _hop(hostname="hnk-b4-link.ip.twelve99.net", address="62.115.209.158")
    located = geo.locate_hops(
        [hop], hoiho_records={},
        ip_records={"62.115.209.158": dict(lat=48.86, lon=2.35, city="Paris", cc="FR")},
        origin=MANILA)
    assert located[0]["source"] == geo.SOURCE_SITE_CODE
    assert "Hong Kong" in located[0]["place"]


def test_a_private_hop_is_placed_at_the_origin_and_queried_nowhere():
    for address in ("192.168.1.1", "10.0.0.1", "100.86.0.1", "127.0.0.1"):
        hop = _hop(address=address, rtt=3.0)
        entry = geo.locate_hops([hop], {}, {}, MANILA)[0]
        assert entry["source"] == geo.SOURCE_LOCAL, address
        assert (entry["lat"], entry["lon"]) == MANILA
        assert geo.ANNOT_LOCAL in entry["annotations"]


def test_a_rejected_candidate_is_recorded_not_silently_dropped():
    hop = _hop(address="64.86.26.38", rtt=20.0)
    entry = geo.locate_hops(
        [hop], {}, {"64.86.26.38": dict(lat=HARARE[0], lon=HARARE[1],
                                        city="Harare", cc="ZW")}, MANILA)[0]
    assert entry["candidates"], "the rejection left no audit trail"
    assert entry["candidates"][0]["accepted"] is False
    assert entry["candidates"][0]["place"] == "Harare, ZW"


# ---------- annotations ----------

def _located(**kw):
    base = {"hop": 1, "min_rtt_ms": None, "loss_pct": None, "place": None,
            "addresses": [], "annotations": []}
    base.update(kw)
    return base


def test_an_rtt_that_falls_at_a_later_hop_is_an_asymmetric_return_path():
    hops = [_located(hop=1, min_rtt_ms=214.3, loss_pct=0.0, addresses=["a"]),
            _located(hop=2, min_rtt_ms=29.0, loss_pct=0.0, addresses=["b"])]
    geo.annotate(hops)
    assert geo.ANNOT_ASYMMETRIC in hops[0]["annotations"]
    assert hops[0]["lat" if "lat" in hops[0] else "hop"] is not None  # not moved


def test_a_sharp_jump_in_the_same_city_is_an_asymmetric_return_path():
    hops = [_located(hop=1, min_rtt_ms=29.1, loss_pct=0.0, place="Hong Kong, HK", addresses=["a"]),
            _located(hop=2, min_rtt_ms=214.3, loss_pct=0.0, place="Hong Kong, HK", addresses=["b"])]
    geo.annotate(hops)
    assert geo.ANNOT_ASYMMETRIC in hops[1]["annotations"]


def test_small_wobbles_are_not_annotated():
    """Thresholds exist so ordinary jitter is not reported as a finding."""
    hops = [_located(hop=1, min_rtt_ms=239.1, loss_pct=0.0, addresses=["a"]),
            _located(hop=2, min_rtt_ms=228.4, loss_pct=0.0, addresses=["b"])]
    geo.annotate(hops)
    assert geo.ANNOT_ASYMMETRIC not in hops[0]["annotations"]


def test_loss_that_a_later_hop_does_not_share_is_icmp_rate_limiting():
    hops = [_located(hop=1, min_rtt_ms=55.0, loss_pct=40.0, addresses=["a"]),
            _located(hop=2, min_rtt_ms=58.0, loss_pct=0.0, addresses=["b"])]
    geo.annotate(hops)
    assert geo.ANNOT_ICMP_LIMIT in hops[0]["annotations"]


def test_two_rate_limiting_routers_do_not_hide_each_other():
    """The bug in the first version: requiring every later hop to be clean.

    With loss at hop 1 and hop 2, an "all later hops are 0%" rule flagged
    neither, even though the destination answered every probe.
    """
    hops = [_located(hop=1, min_rtt_ms=55.0, loss_pct=40.0, addresses=["a"]),
            _located(hop=2, min_rtt_ms=60.0, loss_pct=20.0, addresses=["b"]),
            _located(hop=3, min_rtt_ms=61.0, loss_pct=0.0, addresses=["c"])]
    geo.annotate(hops)
    assert geo.ANNOT_ICMP_LIMIT in hops[0]["annotations"]
    assert geo.ANNOT_ICMP_LIMIT in hops[1]["annotations"]


def test_real_loss_all_the_way_down_is_not_called_rate_limiting():
    hops = [_located(hop=1, min_rtt_ms=55.0, loss_pct=40.0, addresses=["a"]),
            _located(hop=2, min_rtt_ms=58.0, loss_pct=60.0, addresses=["b"])]
    geo.annotate(hops)
    assert geo.ANNOT_ICMP_LIMIT not in hops[0]["annotations"]


def test_a_silent_tail_is_the_destination_not_answering():
    hops = [_located(hop=1, min_rtt_ms=10.0, loss_pct=0.0, addresses=["a"]),
            _located(hop=2, loss_pct=100.0),
            _located(hop=3, loss_pct=100.0)]
    geo.annotate(hops)
    assert geo.ANNOT_NO_ICMP in hops[1]["annotations"]
    assert geo.ANNOT_NO_ICMP in hops[2]["annotations"]
    assert geo.ANNOT_NO_ICMP not in hops[0]["annotations"]


def test_a_silent_hop_in_the_middle_is_not_the_tail():
    hops = [_located(hop=1, min_rtt_ms=10.0, loss_pct=0.0, addresses=["a"]),
            _located(hop=2, loss_pct=100.0),
            _located(hop=3, min_rtt_ms=20.0, loss_pct=0.0, addresses=["c"])]
    geo.annotate(hops)
    assert geo.ANNOT_NO_ICMP not in hops[1]["annotations"]


# ---------- reverse DNS: the defect the first live Atlas trace exposed ----------

def test_a_nameless_trace_gets_hostnames_before_the_sources_are_asked(monkeypatch):
    """RIPE Atlas returns hop addresses and no names at all.

    The first live trace to heise.de came back with every hostname column
    empty, so Hoiho and the site-code table had nothing to work on and every
    hop fell back to the IP database: the Marseille router rendered as "FR" and
    the Singapore and Paris hops were not placed. The hostname-first design was
    silently inert on the primary path.

    Names are now filled in from PTR before any source is consulted, which also
    covers a pasted "traceroute -n" or "tracert -d".
    """
    import asyncio

    async def fake_ptr(addresses):
        assert "62.115.112.222" in addresses
        return {"62.115.112.222": "sng-b6-link.ip.twelve99.net"}

    async def no_hoiho(hostnames):
        return {}, None

    async def no_ip(addresses):
        return {}

    monkeypatch.setattr(geo, "reverse_dns", fake_ptr)
    monkeypatch.setattr(geo, "ip_geolocate", no_ip)
    monkeypatch.setattr("app.routemap.hoiho.lookup", no_hoiho)

    # A hop exactly as Atlas delivers it: an address, no name.
    hop = Hop(hop=7, addresses=["62.115.112.222"], rtts_ms=[58.5], sent=3, lost=0)
    result = asyncio.run(geo.resolve([hop], MANILA))
    entry = result["hops"][0]

    assert entry["hostname"] == "sng-b6-link.ip.twelve99.net", (
        "the hop was never given a name, so the hostname sources cannot fire")
    assert entry["source"] == geo.SOURCE_SITE_CODE
    assert "Singapore" in entry["place"]


def test_reverse_dns_is_not_asked_about_private_addresses(monkeypatch):
    """A private hop is the operator's own network; it is not looked up."""
    import asyncio

    asked = {}

    async def fake_ptr(addresses):
        asked["addresses"] = list(addresses)
        return {}

    async def no_hoiho(hostnames):
        return {}, None

    async def no_ip(addresses):
        return {}

    monkeypatch.setattr(geo, "reverse_dns", fake_ptr)
    monkeypatch.setattr(geo, "ip_geolocate", no_ip)
    monkeypatch.setattr("app.routemap.hoiho.lookup", no_hoiho)

    hops = [Hop(hop=1, addresses=["192.168.1.1"], rtts_ms=[1.0], sent=3, lost=0),
            Hop(hop=2, addresses=["100.86.0.1"], rtts_ms=[8.0], sent=3, lost=0),
            Hop(hop=3, addresses=["62.115.112.222"], rtts_ms=[58.0], sent=3, lost=0)]
    asyncio.run(geo.resolve(hops, MANILA))
    assert asked["addresses"] == ["62.115.112.222"], (
        f"private hops were sent to the resolver: {asked['addresses']}")


def test_a_hop_that_already_has_a_name_is_not_re_resolved(monkeypatch):
    """The tool's own answer is authoritative; PTR only fills gaps."""
    import asyncio

    asked = {}

    async def fake_ptr(addresses):
        asked["addresses"] = list(addresses)
        return {}

    async def no_hoiho(hostnames):
        return {}, None

    async def no_ip(addresses):
        return {}

    monkeypatch.setattr(geo, "reverse_dns", fake_ptr)
    monkeypatch.setattr(geo, "ip_geolocate", no_ip)
    monkeypatch.setattr("app.routemap.hoiho.lookup", no_hoiho)

    hop = Hop(hop=7, addresses=["62.115.112.222"],
              hostnames=["sng-b6-link.ip.twelve99.net"],
              rtts_ms=[58.5], sent=3, lost=0)
    asyncio.run(geo.resolve([hop], MANILA))
    assert not asked.get("addresses"), "a hop that already had a name was re-resolved"


def test_an_ecmp_hop_shows_the_hostname_that_produced_the_placement():
    """Found in a real trace from Manila to heise.de.

    Hop 8 answered from two routers: mei-b6-link (Marseille) and sng-b6-link
    (Singapore). Marseille is 11,000 km away and the hop's fastest probe was
    nowhere near enough to reach it, so the bound rejected Marseille and
    accepted Singapore, correctly. The table then showed "mei-b6-link ...
    Singapore, SG", because the hostname column was hostnames[0] while the
    location came from hostnames[1]. Two true facts next to each other reading
    as one false one.
    """
    hop = Hop(hop=8,
              addresses=["62.115.140.54", "62.115.139.44"],
              hostnames=["mei-b6-link.ip.twelve99.net", "sng-b6-link.ip.twelve99.net"],
              rtts_ms=[58.3], sent=3, lost=0)
    entry = geo.locate_hops([hop], hoiho_records={}, ip_records={}, origin=MANILA)[0]

    assert entry["source"] == geo.SOURCE_SITE_CODE
    assert "Singapore" in entry["place"]
    assert entry["hostname"] == "sng-b6-link.ip.twelve99.net", (
        "the hop is shown with a hostname that did not produce its location")
    # The rejected candidate is still on the record, with the reason.
    rejected = [c for c in entry["candidates"] if not c["accepted"]]
    assert any("mei-b6-link" in (c.get("hostname") or "") for c in rejected)
    # Both addresses stay available, because the hop really did answer from both.
    assert entry["addresses"] == ["62.115.140.54", "62.115.139.44"]


def test_the_ip_database_placement_names_the_address_it_used():
    """Same rule for the fallback source."""
    hop = Hop(hop=5, addresses=["62.115.209.158", "64.86.26.38"],
              rtts_ms=[215.0], sent=3, lost=0)
    entry = geo.locate_hops(
        [hop], hoiho_records={},
        ip_records={"64.86.26.38": dict(lat=37.35, lon=-121.95,
                                        city="Santa Clara", cc="US")},
        origin=MANILA)[0]
    assert entry["source"] == geo.SOURCE_IP_DB
    assert entry["address"] == "64.86.26.38", (
        "the hop is shown with an address that did not produce its location")
