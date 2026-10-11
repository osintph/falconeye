"""Hunt scoring and verdicts, with evidence (v3.38.1 model).

A registered lookalike with a second signal (MX, a phishing keyword, a recent
registration or fresh cert, or brand content) must land in SUSPICIOUS or LIKELY
PHISHING. philhealthgov.ph with MX and mmdalogin.ph with a keyword must not be
UNRELATED. A domain that resolves but could not be fetched is UNKNOWN, never
unrelated.
"""
from app.hunt import score


def _c(**kw):
    base = {"domain": "x.ph", "resolves": True, "fetched": True, "has_mx": False,
            "has_ns": False, "reg_age_days": None, "fresh_cert": False, "brand_markers": 0,
            "ph_indicators": 0, "favicon_match": False, "cloudflare": False, "title": "",
            "parked": False, "evidence": []}
    base.update(kw)
    return base


def test_fresh_impersonation_is_likely_phishing():
    c = score.score_candidate(_c(domain="philhealth-refund.ph", reg_age_days=3, fresh_cert=True,
                                 has_mx=True, brand_markers=2, ph_indicators=3, favicon_match=True),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "likely phishing"
    assert c["score"] >= 70
    assert c["evidence"]


def test_registered_lookalike_with_mx_is_flagged():
    # philhealthgov.ph: uses the brand name (+25) and has MX (+15) => suspicious.
    c = score.score_candidate(_c(domain="philhealthgov.ph", has_mx=True, reg_age_days=200),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] in ("suspicious", "likely phishing")
    assert any("brand name" in e for e in c["evidence"])


def test_keyword_domain_is_flagged():
    # mmdalogin.ph: uses the brand name (+25) and a phishing keyword "login" (+25).
    c = score.score_candidate(_c(domain="mmdalogin.ph", reg_age_days=400),
                              "mmda", "mmda.gov.ph")
    assert c["verdict"] in ("suspicious", "likely phishing")
    assert any("phishing keyword" in e for e in c["evidence"])


def test_old_plain_company_is_unrelated():
    # The brand name alone, on an old domain we fetched and found benign, is not
    # enough to cross a threshold.
    c = score.score_candidate(_c(domain="philhealthcareinc.com", reg_age_days=2000, fetched=True),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "unrelated"


def test_resolving_but_unfetched_is_unknown():
    c = score.score_candidate(_c(domain="randomsite.xyz", fetched=False, reg_age_days=1500),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "unknown"


def test_cloudflare_challenge_is_unknown_not_unrelated():
    c = score.score_candidate(_c(domain="weird.xyz", fetched=False, cloudflare=True),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "unknown"


def test_parking_page_is_parked():
    c = score.score_candidate(_c(domain="philhealth-portal.net", reg_age_days=1000, parked=True),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "parked"


def test_non_resolving_is_unrelated_zero():
    c = score.score_candidate(_c(domain="gone.ph", resolves=False, fetched=False),
                              "philhealth", "")
    assert c["verdict"] == "unrelated" and c["score"] == 0


def test_fresh_close_permutation_is_flagged():
    c = score.score_candidate(_c(domain="philhealh.ph", reg_age_days=20),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] in ("suspicious", "likely phishing")
