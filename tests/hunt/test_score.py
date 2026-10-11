"""Hunt scoring and verdicts (v3.38.6 campaign-aware model).

Likely Phishing when ANY of: brand plus theme term and registered under 90 days;
campaign-cluster membership; an urlscan malicious or phishing label; or page
content imitating the brand. A domain urlscan observed recently that no longer
resolves is possibly taken down, never Unknown.
"""
from app.hunt import score


def _c(**kw):
    base = {"domain": "x.com", "resolves": True, "fetched": True, "has_mx": False,
            "reg_age_days": None, "fresh_cert": False, "brand_markers": 0, "ph_indicators": 0,
            "favicon_match": False, "legit_title_sim": 0, "known_bad": False, "cloudflare": False,
            "title": "", "parked": False, "themes": [], "urlscan": None,
            "campaign_member": False, "page_class": "", "has_cred_form": False,
            "has_payment_form": False, "evidence": []}
    base.update(kw)
    return base


def test_campaign_member_is_likely_phishing():
    c = score.score_candidate(_c(domain="mmda-ltoncap.net", themes=["lto", "ncap"],
                                 campaign_member=True, reg_age_days=20),
                              "mmda", "mmda.gov.ph")
    assert c["verdict"] == "likely phishing"
    assert any("campaign" in e for e in c["evidence"])


def test_theme_plus_recent_registration_is_likely_phishing():
    c = score.score_candidate(_c(domain="mmdancap-ncr.icu", themes=["ncap", "ncr"],
                                 reg_age_days=15),
                              "mmda", "mmda.gov.ph")
    assert c["verdict"] == "likely phishing"


def test_urlscan_malicious_label_is_likely_phishing():
    c = score.score_candidate(_c(domain="emmday.in", themes=[],
                                 urlscan={"labels": ["phishing"], "first_seen": "2026-10-01",
                                          "age_days": 400}),
                              "mmda", "mmda.gov.ph")
    assert c["verdict"] == "likely phishing"  # stronger evidence


def test_theme_without_recent_registration_is_suspicious_not_likely():
    c = score.score_candidate(_c(domain="mmda-ncap-old.com", themes=["ncap"], reg_age_days=1500),
                              "mmda", "mmda.gov.ph")
    assert c["verdict"] in ("suspicious", "unrelated")
    assert c["verdict"] != "likely phishing"


def test_possibly_taken_down_keeps_evidence_not_unknown():
    # urlscan saw it recently but it no longer resolves: not Unknown.
    c = score.score_candidate(_c(domain="mmda-ltoncap.work", resolves=False, fetched=False,
                                 themes=["lto", "ncap"], campaign_member=True,
                                 urlscan={"labels": [], "first_seen": "2026-10-05", "age_days": 30}),
                              "mmda", "mmda.gov.ph")
    assert c["verdict"] != "unknown"
    assert any("taken down" in e for e in c["evidence"])


def test_resolving_unfetched_non_observed_is_unknown():
    c = score.score_candidate(_c(domain="mmda-weird.com", resolves=True, fetched=False,
                                 urlscan=None),
                              "mmda", "mmda.gov.ph")
    assert c["verdict"] == "unknown"


def test_cheap_tld_adds_weight():
    cheap = score.score_candidate(_c(domain="mmda-ncap.sbs", themes=["ncap"], reg_age_days=1500),
                                  "mmda", "mmda.gov.ph")
    assert any("cheap" in e for e in cheap["evidence"])


def test_informational_brand_site_is_not_likely_phishing():
    # An old PhilHealth guide/article site with no forms: brand-referencing, not
    # likely phishing on its name alone.
    c = score.score_candidate(_c(domain="philhealthguide.com", themes=["portal"],
                                 reg_age_days=1500, page_class="informational"),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "brand-referencing"


def test_portal_lookalike_with_login_form_is_likely_phishing():
    c = score.score_candidate(_c(domain="philhealthportal.com", themes=["portal"],
                                 reg_age_days=1500, page_class="phishing", has_cred_form=True),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "likely phishing"


def test_informational_but_urlscan_malicious_is_likely_phishing():
    c = score.score_candidate(_c(domain="philhealthguide.com", themes=["portal"],
                                 reg_age_days=1500, page_class="informational",
                                 urlscan={"labels": ["phishing"]}),
                              "philhealth", "philhealth.gov.ph")
    assert c["verdict"] == "likely phishing"
