"""Hunt scoring and verdicts, with evidence."""
from app.hunt import score


def _c(**kw):
    base = {"domain": "x.ph", "resolves": True, "has_mx": False, "reg_age_days": None,
            "fresh_cert": False, "brand_markers": 0, "ph_indicators": 0, "favicon_match": False,
            "cloudflare": False, "title": "", "parked": False, "evidence": []}
    base.update(kw)
    return base


def test_fresh_impersonation_is_likely_phishing():
    c = score.score_candidate(_c(domain="philhealth-refund.ph", reg_age_days=3, fresh_cert=True,
                                 has_mx=True, brand_markers=2, ph_indicators=3, favicon_match=True),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "likely phishing"
    assert c["score"] >= 70
    assert c["evidence"]


def test_old_plain_domain_is_unrelated():
    c = score.score_candidate(_c(domain="philhealthcareinc.com", reg_age_days=2000),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "unrelated"


def test_parking_page_is_parked():
    c = score.score_candidate(_c(domain="philhealth-portal.net", reg_age_days=1000, parked=True),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "parked"


def test_non_resolving_is_unrelated_zero():
    c = score.score_candidate(_c(domain="gone.ph", resolves=False), "philhealth", "")
    assert c["verdict"] == "unrelated" and c["score"] == 0


def test_close_permutation_adds_suspicion():
    c = score.score_candidate(_c(domain="philhealh.ph", reg_age_days=20),
                              "philhealth", "philhealth.gov.ph")
    # A fresh, close-permutation domain should not read as unrelated.
    assert c["verdict"] in ("suspicious", "likely phishing")
