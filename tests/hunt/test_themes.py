"""Keyword relevance, brand theme lexicons and cheap-TLD detection."""
from app.hunt import themes


def test_campaign_names_are_relevant():
    # Every NCAP-campaign name is relevant (kept, not dropped as noise).
    for d in ("mmda-ltoncap.net", "mmdaltoncaps.com", "mmdancap-ncr.icu", "ncapmmdar.com",
              "mmdalto-ncap.sbs", "mmda-ltoncap.work", "mmdancaps.surf", "nocpmmda.luxe",
              "mmda-ncaplto.club"):
        assert themes.classify(d, "mmda")["relevant"], f"{d} should be relevant"


def test_themed_campaign_names_carry_a_theme_term():
    # The ones that literally contain ncap/lto seed the campaign cluster.
    for d in ("mmda-ltoncap.net", "mmdaltoncaps.com", "mmdancap-ncr.icu", "ncapmmdar.com",
              "mmdalto-ncap.sbs", "mmda-ltoncap.work", "mmdancaps.surf", "mmda-ncaplto.club"):
        assert themes.classify(d, "mmda")["themes"], f"{d} should carry a theme term"


def test_buried_unrelated_words_are_irrelevant():
    for d in ("stammdaten.de", "hommdays.com", "summday.co.il", "prismmdash.xyz",
              "rammdarbarimpex.com", "mmdancesupplies.com"):
        c = themes.classify(d, "mmda")
        assert c["buried"], f"{d} should be buried"
        assert not c["relevant"] and not c["themes"], f"{d} should be irrelevant"


def test_generic_phish_substring_does_not_keep_a_foreign_word():
    # The German "updaten" contains "update"; it must not make this SAP master-data
    # site relevant to an mmda hunt (a live v3.38.6 false positive).
    c = themes.classify("stammdaten-pflegen-und-updaten.de", "mmda")
    assert not c["relevant"], "a generic phish substring must not keep an unrelated word"


def test_brand_prefix_is_relevant_even_without_theme():
    # philhealth is a long, distinctive prefix: a clear brand token, not buried.
    c = themes.classify("philhealthhelp.com", "philhealth")
    assert c["relevant"] and not c["buried"]


def test_emmday_is_buried():
    # mmda is buried inside emmday; without a theme or a urlscan flag it is noise.
    c = themes.classify("emmday.in", "mmda")
    assert c["buried"] and not c["relevant"]


def test_theme_in_title_counts():
    c = themes.classify("mmda-portal.com", "mmda", title="MMDA NCAP Violation Payment")
    assert "ncap" in c["themes"] and "violation" in c["themes"]


def test_cheap_tld():
    assert themes.cheap_tld("mmda-ltoncap.sbs")
    assert themes.cheap_tld("x.icu") and themes.cheap_tld("y.luxe")
    assert not themes.cheap_tld("mmda.gov.ph")


def test_philhealth_theme_terms_present():
    c = themes.classify("philhealth-member.com", "philhealth")
    assert "member" in c["themes"]


def test_tagalog_lure_terms_match_mmda_on_theme():
    # A Tagalog lure (mayhuli = "there is a catch/apprehension") must match on theme
    # so it clusters by theme, not by shared infrastructure.
    c = themes.classify("mmda-mayhuliks.com", "mmda")
    assert c["relevant"]
    assert "mayhuli" in c["themes"] or "huli" in c["themes"]
    m = themes.classify("mmdamulta.icu", "mmda")
    assert "multa" in m["themes"]


def test_tagalog_terms_in_other_ph_lexicons():
    assert "benepisyo" in themes.classify("philhealth-benepisyo.net", "philhealth")["themes"]
    assert "pensyon" in themes.classify("sss-pensyon.online", "sss")["themes"]
    assert "pabahay" in themes.classify("pagibig-pabahay.site", "pagibig")["themes"]
