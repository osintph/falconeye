"""MALICIOUS needs a primary source, and well-known infrastructure is capped.

Reported after v3.34.0 shipped: `9.9.9.9` (Quad9's resolver) and
`185.199.110.153` (a GitHub Pages address) both came back **MALICIOUS**, with
the reasoning "Malicious: OTX 50 pulses" and nothing else. Both are addresses
that millions of people use on purpose.

Two distinct defects, and both have to be fixed or the other one still bites:

1. **An OTX pulse count was treated as a verdict.** A pulse is a community
   submission saying "this indicator appeared in something I was looking at".
   Public resolvers and CDN edges appear in enormous numbers of pulses precisely
   because malware resolves DNS and phishing is hosted behind CDNs. OTX is
   corroborating evidence: it tells you a primary finding is not isolated. On its
   own it says an address is popular.

2. **Nothing knew what the address was.** Even with a real primary signal, a
   shared CDN edge or a public resolver is not "a malicious host": the abuse
   reports are about one tenant or one resolver client, and the address is shared
   by everyone else. So a match against a published infrastructure list caps the
   verdict at SUSPICIOUS and says why.

The rule now: MALICIOUS requires AbuseIPDB over its cutoff, VirusTotal over its
cutoff, or a ThreatFox IOC match; **or** OTX pulses plus at least one other
source that saw something. OTX alone is SUSPICIOUS with the count shown.

The tests below are written against the rule rather than against the two
addresses that prompted it: every single-source combination is enumerated, so a
future threshold change cannot quietly reintroduce "one community feed decides".
"""
import os

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import pytest

from app.ip_sources import infrastructure, reputation
from app.ip_sources.base import OK, SourceResult

# The five addresses named in the report, plus what each one is.
QUAD9 = "9.9.9.9"
CLOUDFLARE_DNS = "1.1.1.1"
GOOGLE_DNS = "8.8.8.8"
GITHUB_PAGES = "185.199.110.153"
# AbuseIPDB confidence 100 over 2,965 reports, VirusTotal 13 vendors, when this
# test was written (2026-09-27). Used as "an address with real primary findings".
GENUINELY_BAD = "101.36.116.232"


def _src(name, *, ok=True, state=OK, **data):
    return SourceResult(name, ok, state, data, None).as_dict()


def _sources(*, abuse=0, reports=0, vt=0, pulses=0, threatfox=False):
    return {
        "abuseipdb": _src("abuseipdb", confidence=abuse, total_reports=reports),
        "virustotal": _src("virustotal", malicious=vt),
        "otx": _src("otx", pulse_count=pulses),
        "threatfox": _src("threatfox", matched=threatfox),
        "censys": _src("censys", ports=[]),
    }


def _verdict(ip=None, **kw):
    greynoise = kw.pop("greynoise_malicious", False)
    return reputation.compute_verdict(_sources(**kw), greynoise_malicious=greynoise, ip=ip)


# ---------- OTX alone is not a verdict ----------

@pytest.mark.parametrize("pulses", [3, 17, 50, 200])
def test_otx_pulses_alone_are_suspicious_not_malicious(pulses):
    v = _verdict(pulses=pulses)
    assert v["verdict"] == reputation.SUSPICIOUS, (
        f"{pulses} OTX pulses and nothing else produced {v['verdict']}. A pulse "
        "count is corroboration, not a finding."
    )


def test_the_pulse_count_is_shown_when_otx_is_the_only_signal():
    v = _verdict(pulses=50)
    assert "50" in v["reasoning"], v["reasoning"]
    assert "OTX" in v["reasoning"]
    assert ("Pulses", "50") in {(s["label"], s["value"]) for s in v["signals"]}


def test_the_reasoning_says_otx_was_alone():
    """An operator has to be able to tell this from a corroborated finding."""
    v = _verdict(pulses=50)
    low = v["reasoning"].lower()
    assert "only" in low or "alone" in low or "no other source" in low, v["reasoning"]


# ---------- a primary source still fires on its own ----------

@pytest.mark.parametrize("kwargs,expected_fragment", [
    ({"abuse": 75, "reports": 10}, "AbuseIPDB 75%"),
    ({"abuse": 100, "reports": 2965}, "AbuseIPDB 100%"),
    ({"vt": 3}, "VirusTotal 3"),
    ({"vt": 13}, "VirusTotal 13"),
    ({"threatfox": True}, "ThreatFox"),
])
def test_a_primary_source_over_its_cutoff_is_malicious(kwargs, expected_fragment):
    v = _verdict(**kwargs)
    assert v["verdict"] == reputation.MALICIOUS
    assert expected_fragment in v["reasoning"]


def test_the_cutoffs_themselves_are_unchanged():
    assert reputation.ABUSEIPDB_MALICIOUS == 75
    assert reputation.ABUSEIPDB_SUSPICIOUS == 25
    assert reputation.VT_MALICIOUS == 3
    assert reputation.OTX_MALICIOUS_PULSES == 3


# ---------- OTX plus one other source ----------

@pytest.mark.parametrize("extra", [
    {"abuse": 25, "reports": 4},
    {"abuse": 60, "reports": 40},
    {"vt": 1},
    {"vt": 2},
    {"greynoise_malicious": True},
])
def test_otx_plus_another_source_is_malicious(extra):
    v = _verdict(pulses=5, **extra)
    assert v["verdict"] == reputation.MALICIOUS, (
        f"OTX pulses corroborated by {extra} produced {v['verdict']}"
    )
    assert "OTX" in v["reasoning"]


def test_otx_below_its_cutoff_plus_another_source_is_still_only_suspicious():
    """Corroboration cuts both ways: two weak signals are not a strong one."""
    v = _verdict(pulses=2, abuse=30, reports=5)
    assert v["verdict"] == reputation.SUSPICIOUS


@pytest.mark.parametrize("kwargs", [
    {"abuse": 25, "reports": 3},
    {"abuse": 74, "reports": 30},
    {"vt": 1},
    {"vt": 2},
    {"pulses": 1},
    {"pulses": 2},
    {"greynoise_malicious": True},
])
def test_no_single_sub_threshold_signal_reaches_malicious(kwargs):
    """The bug class, stated directly: one source below its cutoff never decides."""
    v = _verdict(**kwargs)
    assert v["verdict"] == reputation.SUSPICIOUS, kwargs


def test_nothing_at_all_is_still_clean():
    v = _verdict()
    assert v["verdict"] == reputation.CLEAN


# ---------- the infrastructure allowlist ----------

@pytest.mark.parametrize("ip,label", [
    (GOOGLE_DNS, "Google Public DNS"),
    ("8.8.4.4", "Google Public DNS"),
    ("2001:4860:4860::8888", "Google Public DNS"),
    (CLOUDFLARE_DNS, "Cloudflare"),
    ("1.0.0.1", "Cloudflare"),
    ("1.1.1.2", "Cloudflare"),
    ("2606:4700:4700::1111", "Cloudflare"),
    (QUAD9, "Quad9"),
    ("149.112.112.112", "Quad9"),
    ("9.9.9.10", "Quad9"),
    ("2620:fe::fe", "Quad9"),
    ("208.67.222.222", "OpenDNS"),
    ("208.67.220.220", "OpenDNS"),
])
def test_published_resolver_addresses_are_recognised(ip, label):
    match = infrastructure.classify(ip)
    assert match is not None, f"{ip} is not recognised as infrastructure"
    assert label in match["label"]
    assert match["kind"] == "resolver"


@pytest.mark.parametrize("ip,label", [
    (GITHUB_PAGES, "GitHub Pages"),
    ("185.199.108.153", "GitHub Pages"),
    ("2606:50c0:8000::153", "GitHub Pages"),
    ("104.16.0.1", "Cloudflare"),
    ("172.64.0.1", "Cloudflare"),
    ("151.101.1.69", "Fastly"),
    ("199.232.0.1", "Fastly"),
])
def test_published_cdn_ranges_are_recognised(ip, label):
    match = infrastructure.classify(ip)
    assert match is not None, f"{ip} is not recognised as infrastructure"
    assert label in match["label"]
    assert match["kind"] == "cdn"


@pytest.mark.parametrize("ip", [
    GENUINELY_BAD,
    "51.195.242.234",
    "45.148.10.242",
    "203.0.113.5",
    "",
    None,
    "not-an-ip",
])
def test_an_ordinary_address_is_not_infrastructure(ip):
    assert infrastructure.classify(ip) is None


def test_every_entry_cites_where_its_addresses_came_from():
    """An allowlist that silences findings has to say who published it."""
    for entry in infrastructure.ENTRIES:
        assert entry["source"].startswith("https://"), entry["label"]
        assert entry["verified"], f"{entry['label']} has no verification date"


def test_the_source_urls_are_in_the_module_text():
    src = open("app/ip_sources/infrastructure.py", encoding="utf-8").read()
    for entry in infrastructure.ENTRIES:
        assert entry["source"] in src


# ---------- the cap ----------

@pytest.mark.parametrize("ip", [GOOGLE_DNS, CLOUDFLARE_DNS, QUAD9, GITHUB_PAGES])
def test_infrastructure_caps_a_malicious_verdict_at_suspicious(ip):
    """Real primary findings, on an address shared by millions."""
    v = _verdict(ip=ip, abuse=100, reports=900, vt=13, pulses=50)
    assert v["verdict"] == reputation.SUSPICIOUS, (
        f"{ip} was reported as {v['verdict']}; a shared resolver or CDN edge is "
        "not a malicious host"
    )
    assert v["infrastructure"]["capped"] is True
    assert "widely-used infrastructure" in v["reasoning"].lower()
    # The evidence is still on the card: capping is not hiding.
    assert "AbuseIPDB 100%" in v["reasoning"]


@pytest.mark.parametrize("ip", [GOOGLE_DNS, CLOUDFLARE_DNS, QUAD9, GITHUB_PAGES])
def test_the_five_reported_addresses_are_never_malicious_on_pulses_alone(ip):
    v = _verdict(ip=ip, pulses=50)
    assert v["verdict"] == reputation.SUSPICIOUS
    assert v["infrastructure"] is not None


def test_a_genuinely_bad_address_is_still_malicious():
    v = _verdict(ip=GENUINELY_BAD, abuse=100, reports=2965, vt=13, pulses=17)
    assert v["verdict"] == reputation.MALICIOUS
    assert v["infrastructure"] is None
    assert "AbuseIPDB 100%" in v["reasoning"] and "VirusTotal 13" in v["reasoning"]


def test_the_cap_never_raises_a_verdict():
    """A resolver with nothing against it is CLEAN, not SUSPICIOUS."""
    v = _verdict(ip=GOOGLE_DNS)
    assert v["verdict"] == reputation.CLEAN
    assert v["infrastructure"] is not None
    assert v["infrastructure"]["capped"] is False


def test_the_infrastructure_note_names_what_the_address_is():
    v = _verdict(ip=QUAD9, pulses=50)
    note = v["infrastructure"]
    assert "Quad9" in note["label"]
    assert note["kind"] == "resolver"
    assert note["source"].startswith("https://")


def test_without_an_ip_nothing_is_capped():
    """compute_verdict is called from tests and tooling without an address."""
    v = _verdict(abuse=100, reports=900)
    assert v["verdict"] == reputation.MALICIOUS
    assert v["infrastructure"] is None


def test_an_incomplete_verdict_still_carries_the_infrastructure_note():
    sources = _sources(pulses=0)
    sources["virustotal"] = _src("virustotal", ok=False, state="error")
    v = reputation.compute_verdict(sources, ip=GOOGLE_DNS)
    assert v["verdict"] == reputation.INCOMPLETE
    assert v["infrastructure"] is not None


# ---------- it reaches the endpoint and the page ----------

def test_the_endpoint_passes_the_address_to_the_verdict():
    import inspect

    from app.routers import ip_intel
    src = inspect.getsource(ip_intel)
    assert "ip=validated" in src or "ip=response" in src or 'ip=cached.get("ip")' in src, (
        "the lookup does not tell compute_verdict which address it is, so the "
        "infrastructure allowlist can never fire in production"
    )


def test_assemble_threads_the_address_through():
    block = reputation.assemble(_sources(pulses=50), ip=QUAD9)
    assert block["verdict"]["verdict"] == reputation.SUSPICIOUS
    assert block["verdict"]["infrastructure"]["label"].startswith("Quad9")


def test_the_card_renders_the_infrastructure_note():
    js = open("app/static/app.js", encoding="utf-8").read()
    assert "infrastructure" in js
    assert "widely-used infrastructure" in js.lower()
