"""assess_content: parking and marketplace landing pages are not impersonation,
and brand evidence must relate to the hunted brand, not an unrelated one."""
from app.hunt import candidate


def test_for_sale_page_with_payment_logos_is_parked_not_impersonation():
    body = ("<title>Domain For Sale</title> This domain is for sale. "
            "We accept gcash and maya. Buy this domain now.")
    out = candidate.assess_content(body, "https://mmdaportal.com/", "mmda", "mmda.gov.ph", "")
    assert out["parked"] is True
    assert out["brand_markers"] == 0  # payment logos on a sale page are not impersonation
    assert out["ph_indicators"] == 0


def test_unrelated_brand_is_not_counted_as_impersonation():
    body = "<title>GCash Login</title> gcash mynt please login to your gcash wallet account"
    # Hunting philhealth: a GCash page is not impersonating the hunted brand.
    out = candidate.assess_content(body, "https://x.com/", "philhealth", "philhealth.gov.ph", "")
    assert out["parked"] is False
    assert out["brand_markers"] == 0


def test_hunted_brand_content_is_counted():
    body = "<title>GCash Login</title> gcash mynt please login to your gcash wallet account"
    # Hunting gcash: the brand content now relates to the hunted brand.
    out = candidate.assess_content(body, "https://x.com/", "gcash", "gcash.com", "")
    assert out["brand_markers"] >= 1
    assert out["brand"] == "GCash"


def test_title_imitation_of_the_legit_site_is_detected():
    body = "<title>PhilHealth Member Portal</title> welcome"
    out = candidate.assess_content(body, "https://philhealth-portal.com/", "philhealth",
                                   "philhealth.gov.ph", "PhilHealth Member Portal")
    assert out["legit_title_sim"] >= 70
    assert out["parked"] is False


def test_unrelated_title_does_not_read_as_imitation():
    # A real German SAP site must not match the MMDA title (a live v3.38.6 FP).
    body = "<title>Stammdaten pflegen und updaten</title> SAP master data"
    out = candidate.assess_content(body, "https://stammdaten-pflegen-und-updaten.de/", "mmda",
                                   "mmda.gov.ph", "Metropolitan Manila Development Authority")
    assert out["legit_title_sim"] < 70


def test_short_legit_title_never_triggers_imitation():
    out = candidate.assess_content("<title>Some Random Page</title>", "https://x.com/", "mmda",
                                   "mmda.gov.ph", "MMDA")  # legit title under 8 chars
    assert out["legit_title_sim"] == 0
