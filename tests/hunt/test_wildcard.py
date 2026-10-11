"""Wildcard and registry-landing detection."""
from app.hunt import wildcard


def test_suffix_of():
    assert wildcard.suffix_of("mmdalogin.ph") == "ph"
    assert wildcard.suffix_of("x.com.ph") == "com.ph"
    assert wildcard.suffix_of("a.b.example.com") == "com"


def test_signature_from_resolving_controls_is_a_wildcard():
    answers = [{"ips": ["45.79.222.138"], "cname": ""},
               {"ips": ["45.79.222.138"], "cname": ""}]
    sig = wildcard.signature_from(answers)
    assert sig["wildcard"] is True
    assert "45.79.222.138" in sig["ips"]


def test_signature_from_nxdomain_controls_is_not_a_wildcard():
    sig = wildcard.signature_from([{"ips": [], "cname": ""}, {"ips": [], "cname": ""}])
    assert sig["wildcard"] is False


def test_candidate_matching_the_control_is_a_wildcard_answer():
    sig = wildcard.signature_from([{"ips": ["45.79.222.138"], "cname": ""}])
    # Same IP as the control: the registry catch-all, not a real registration.
    assert wildcard.is_control_answer(["45.79.222.138"], "", sig) is True
    # A domain on its own address is not the catch-all.
    assert wildcard.is_control_answer(["203.0.113.7"], "", sig) is False
    # No wildcard on this TLD: nothing is a control answer.
    nxsig = wildcard.signature_from([{"ips": [], "cname": ""}])
    assert wildcard.is_control_answer(["203.0.113.7"], "", nxsig) is False
