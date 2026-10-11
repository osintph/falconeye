"""Source status and the INCOMPLETE rule: a discovery-source failure makes the
run incomplete, never a clean zero."""
from app.asm import report


def test_all_sources_answered_is_complete():
    disc = {"sources": {"ct": {"ok": True}, "passive_dns": {"ok": True}, "wayback": {"ok": True}},
            "asn": {"available": True}}
    status, incomplete = report.asm_source_status(disc)
    assert incomplete is False
    assert {s["source"] for s in status} >= {"crt.sh / Cert Spotter", "Mnemonic", "Wayback Machine", "RIPEstat"}
    assert all(s["status"] in ("answered", "skipped") for s in status)


def test_crtsh_failure_makes_the_run_incomplete():
    disc = {"sources": {"ct": {"ok": False}, "passive_dns": {"ok": True}, "wayback": {"ok": True}},
            "asn": {"available": True}}
    status, incomplete = report.asm_source_status(disc)
    assert incomplete is True
    ct = next(s for s in status if s["source"] == "crt.sh / Cert Spotter")
    assert ct["status"] == "failed"


def test_any_discovery_failure_makes_incomplete():
    for key in ("ct", "passive_dns", "wayback"):
        sources = {"ct": {"ok": True}, "passive_dns": {"ok": True}, "wayback": {"ok": True}}
        sources[key] = {"ok": False}
        _, incomplete = report.asm_source_status({"sources": sources, "asn": {"available": True}})
        assert incomplete is True, f"{key} failure should make the run incomplete"


def test_ripestat_absence_alone_does_not_make_incomplete():
    disc = {"sources": {"ct": {"ok": True}, "passive_dns": {"ok": True}, "wayback": {"ok": True}},
            "asn": {"available": False}}
    status, incomplete = report.asm_source_status(disc)
    assert incomplete is False
    ripe = next(s for s in status if s["source"] == "RIPEstat")
    assert ripe["status"] == "skipped"


def test_ripestat_skip_states_a_reason():
    # A skipped RIPEstat must say why, so the report never shows a bare "skipped".
    disc = {"sources": {"ct": {"ok": True}, "passive_dns": {"ok": True}, "wayback": {"ok": True}},
            "asn": {"available": False, "reason": "all hosts resolve to a CDN edge"}}
    status, _ = report.asm_source_status(disc)
    ripe = next(s for s in status if s["source"] == "RIPEstat")
    assert ripe.get("note")
