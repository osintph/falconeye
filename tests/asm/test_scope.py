"""Scope: CDN-fronted and third-party-CNAME hosts are never port scanned."""
import asyncio

import pytest

from app.asm import cdn, probe


@pytest.fixture
def no_tls(monkeypatch):
    monkeypatch.setattr(probe, "_grab_tls", lambda host, port, ip: None)


@pytest.fixture
def http_ok(monkeypatch):
    async def fake(host):
        return {"status": 200, "title": "", "server": "x", "redirect_chain": [],
                "final_url": "", "fingerprint": [], "sec": {}, "_body": ""}
    monkeypatch.setattr(probe, "_http_probe", fake)


@pytest.fixture
def portscan_spy(monkeypatch):
    calls = []

    async def fake_scan(ip, **kwargs):
        calls.append(ip)
        return [{"port": 443}]
    monkeypatch.setattr(probe.portscan, "scan", fake_scan)
    return calls


def _probe(host):
    sem = asyncio.Semaphore(5)
    return asyncio.run(probe.probe_host(host, "acme.test", sem_ports=sem, port_timeout=1.0))


def test_cdn_fronted_host_is_not_port_scanned(monkeypatch, no_tls, http_ok, portscan_spy):
    monkeypatch.setattr(probe, "_resolve_sync",
                        lambda h: {"A": ["104.16.0.1"], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []})
    monkeypatch.setattr(probe, "resolve_and_check", lambda h: ["104.16.0.1"])
    rec = _probe("cdn.acme.test")
    assert rec["kind"] == "cdn"
    assert rec["cdn_provider"] == "Cloudflare"
    assert portscan_spy == [], "a CDN edge must not be port scanned"


def test_third_party_cname_is_a_reference_and_not_port_scanned(monkeypatch, no_tls, http_ok, portscan_spy):
    monkeypatch.setattr(probe, "_resolve_sync",
                        lambda h: {"A": ["198.51.100.9"], "AAAA": [], "CNAME": ["shops.myshopify.com"],
                                   "MX": [], "NS": [], "TXT": []})
    monkeypatch.setattr(probe, "resolve_and_check", lambda h: ["198.51.100.9"])
    rec = _probe("shop.acme.test")
    assert rec["kind"] == "reference"
    assert rec["is_reference"] == 1
    assert portscan_spy == [], "a third-party CNAME target must not be port scanned"


def test_the_targets_own_host_is_port_scanned(monkeypatch, no_tls, http_ok, portscan_spy):
    monkeypatch.setattr(probe, "_resolve_sync",
                        lambda h: {"A": ["192.0.2.5"], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []})
    monkeypatch.setattr(probe, "resolve_and_check", lambda h: ["192.0.2.5"])
    rec = _probe("api.acme.test")
    assert rec["kind"] == "own"
    assert portscan_spy == ["192.0.2.5"], "the target's own host should be port scanned"


def test_cdn_classify_covers_akamai_by_cname():
    assert cdn.classify_host([], "foo.akamaiedge.net").provider == "Akamai"
    assert cdn.classify_host(["151.101.1.1"], "").provider == "Fastly"
    assert cdn.classify_host(["192.0.2.1"], "self.example.test") is None
