"""Hunt scoring and verdicts (v3.38.2 model).

LIKELY PHISHING requires a strong signal (favicon match, close title imitation,
hunted-brand content, a known-bad listing, or recent registration with live
non-parked content). Keyword-in-name plus MX alone is SUSPICIOUS at most. Parking,
registry and marketplace landing pages are PARKED. A resolving domain that could
not be fetched is UNKNOWN.
"""
from app.hunt import score


def _c(**kw):
    base = {"domain": "x.ph", "resolves": True, "fetched": True, "has_mx": False,
            "has_ns": False, "reg_age_days": None, "fresh_cert": False, "brand_markers": 0,
            "brand": None, "ph_indicators": 0, "favicon_match": False, "legit_title_sim": 0,
            "known_bad": False, "cloudflare": False, "title": "", "parked": False, "evidence": []}
    base.update(kw)
    return base


def test_real_lookalike_imitating_the_legit_page_is_likely_phishing():
    # Strong signal: favicon match and a close title match to the legitimate site.
    c = score.score_candidate(_c(domain="philhealth-refund.com", favicon_match=True,
                                 legit_title_sim=92, has_mx=True, reg_age_days=20),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "likely phishing"
    assert c["strong"] is True


def test_recent_registration_with_live_content_is_likely_phishing():
    c = score.score_candidate(_c(domain="mmda-verify.com", reg_age_days=5, fetched=True,
                                 parked=False, has_mx=True),
                              "mmda", "mmda.gov.ph")
    assert c["verdict"] == "likely phishing"


def test_keyword_plus_mx_alone_is_suspicious_not_likely():
    # No strong signal: an old domain, fetched but benign, keyword and MX only.
    c = score.score_candidate(_c(domain="mmdalogin.com", has_mx=True, reg_age_days=400,
                                 fetched=True, parked=False),
                              "mmda", "mmda.gov.ph")
    assert c["verdict"] == "suspicious"


def test_registry_or_sale_page_with_payment_logos_is_parked():
    # A for-sale or checkout page listing GCash and Maya logos. assess_content
    # suppresses the brand and PH markers, so here they are already zero and the
    # page is parked: it must read Parked, never likely phishing.
    c = score.score_candidate(_c(domain="mmdaportal.com", parked=True, has_mx=True,
                                 brand_markers=0, ph_indicators=0, reg_age_days=800,
                                 title="this domain is for sale"),
                              "mmda", "mmda.gov.ph")
    assert c["verdict"] == "parked"


def test_old_parked_com_with_mx_and_keyword_is_parked():
    c = score.score_candidate(_c(domain="philhealthlogin.com", parked=True, has_mx=True,
                                 reg_age_days=3000),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "parked"


def test_old_domain_no_content_signal_is_not_likely():
    c = score.score_candidate(_c(domain="philhealthcareinc.com", reg_age_days=2500,
                                 fetched=True, parked=False),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] in ("unrelated", "suspicious")
    assert c["verdict"] != "likely phishing"


def test_known_bad_listing_is_likely_phishing():
    c = score.score_candidate(_c(domain="mmda-login.com", known_bad=True, fetched=True,
                                 reg_age_days=400),
                              "mmda", "mmda.gov.ph")
    assert c["verdict"] == "likely phishing"


def test_resolving_but_unfetched_is_unknown():
    c = score.score_candidate(_c(domain="randomsite.com", fetched=False, reg_age_days=1500),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "unknown"


def test_non_resolving_is_unrelated_zero():
    c = score.score_candidate(_c(domain="gone.com", resolves=False, fetched=False),
                              "philhealth", "")
    assert c["verdict"] == "unrelated" and c["score"] == 0
