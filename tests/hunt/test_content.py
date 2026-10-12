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


def test_copying_the_legit_identity_is_a_clone():
    # A candidate whose title and og:site_name match the legitimate site's is a
    # clone, regardless of whether the brand is in its own host.
    legit_title = "GCash | Buy Load, Pay Bills, Send Money"
    body = (f'<title>{legit_title}</title>'
            '<meta property="og:site_name" content="GCash">'
            '<form><input type="password"></form>')
    out = candidate.assess_content(body, "https://secure-verify-portal.com/", "gcash",
                                   "gcash.com", legit_title,
                                   legit_og_site_name="GCash", legit_og_title=legit_title,
                                   host="secure-verify-portal.com")
    assert out["identity_clone"] is True
    assert out["brand_imitation"] is True
    assert out["page_class"] == "imitation"


def test_og_site_name_match_is_a_clone_even_without_title():
    # og:site_name alone, matching the legit site's, is clone evidence.
    body = ('<title>Member Portal</title>'
            '<meta property="og:site_name" content="PhilHealth">')
    out = candidate.assess_content(body, "https://philhealth-benefits.net/", "philhealth",
                                   "philhealth.gov.ph", "PhilHealth Official Website",
                                   legit_og_site_name="PhilHealth", host="philhealth-benefits.net")
    assert out["identity_clone"] is True
    assert out["brand_imitation"] is True


def test_og_site_name_brand_without_legit_is_imitation():
    # Without a legit signature, og:site_name equal to the bare brand on a host that
    # is not the brand's own is imitation.
    body = '<title>Sign in</title><meta property="og:site_name" content="GCash"> login'
    out = candidate.assess_content(body, "https://gcash-secure-login.com/", "gcash", "",
                                   "", host="gcash-secure-login.com")
    assert out["brand_imitation"] is True


def test_own_label_og_without_legit_is_not_imitation():
    # og:site_name that only echoes the candidate's own host label is not imitation.
    body = '<title>Home</title><meta property="og:site_name" content="GCashb.com">'
    out = candidate.assess_content(body, "https://gcashb.com/", "gcash", "",
                                   "", host="gcashb.com")
    assert out["brand_imitation"] is False


def test_gambling_page_with_register_form_is_not_imitation():
    # A casino naming GCash, with its own registration form, is brand-referencing,
    # not a GCash login imitation.
    body = ("<title>Gcash8 Online Casino - Register Claim Free 100 Gcash Bonus</title>"
            "<form><input type=\"password\"></form> play now casino slots jackpot gcash")
    out = candidate.assess_content(body, "https://gcash8.com/", "gcash", "gcash.com",
                                   "GCash Buy Load Pay Bills Send Money")
    assert out["payment_ref"] is True
    assert out["brand_imitation"] is False
    assert out["page_class"] == "informational"


def test_domain_name_in_title_is_not_imitation():
    # The brand in the title is only the domain's own name echoed back, not an
    # imitation of the brand.
    body = "<title>GCashb.com || Home</title> welcome to our site"
    out = candidate.assess_content(body, "https://gcashb.com/", "gcash", "gcash.com",
                                   "GCash Buy Load Pay Bills Send Money")
    assert out["brand_imitation"] is False


def test_bare_brand_mention_is_not_imitation():
    # A page that merely names the brand in body text (no title or og:site_name, no
    # second non-name marker) is NOT imitation: a single "gcash" mention does not
    # make a clone. This is the gcash.online case.
    body = "<p>This article explains how to use gcash safely. Read more about gcash.</p>"
    out = candidate.assess_content(body, "https://x.com/", "gcash", "gcash.com", "")
    assert out["brand_imitation"] is False


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


def test_search_box_is_not_credential_capture():
    body = '<form role="search"><input type="search" name="s" placeholder="Search the site"></form>'
    out = candidate.assess_content(body, "https://x.com/", "gcash", "gcash.com", "")
    assert out["has_cred_form"] is False
    assert out["has_payment_form"] is False


def test_newsletter_and_contact_fields_are_not_capture():
    body = ('<form><input type="email" name="email" placeholder="Your email">'
            '<input type="text" name="fullname"><textarea name="message"></textarea></form>')
    out = candidate.assess_content(body, "https://x.com/", "gcash", "gcash.com", "")
    assert out["has_cred_form"] is False
    assert out["has_payment_form"] is False


def test_pin_and_otp_fields_are_credential_capture():
    body = '<form><input name="mpin" placeholder="Enter your MPIN"><input name="otp_code"></form>'
    out = candidate.assess_content(body, "https://gcash-login.com/", "gcash", "gcash.com", "")
    assert out["has_cred_form"] is True
    assert out["cred_trigger"]


def test_cvv_and_expiry_are_payment_capture():
    body = ('<form><input name="cardno"><label for="e">Expiry date</label>'
            '<input id="e"><input name="cvv"></form>')
    out = candidate.assess_content(body, "https://x.com/", "gcash", "gcash.com", "")
    assert out["has_payment_form"] is True
    assert out["cred_trigger"] == ""


def test_credential_form_is_detected():
    body = ('<title>PhilHealth Member Login</title><form action="/login">'
            '<input type="password" name="pw"></form>')
    out = candidate.assess_content(body, "https://philhealthportal.com/", "philhealth",
                                   "philhealth.gov.ph", "")
    # The form is detected as a flag; whether it means phishing is decided in
    # scoring (it needs brand imitation or a young domain).
    assert out["has_cred_form"] is True


def test_payment_form_is_detected():
    body = '<form><input name="cardnumber" placeholder="Card Number"><label>CVV</label></form>'
    out = candidate.assess_content(body, "https://x.com/", "gcash", "gcash.com", "")
    assert out["has_payment_form"] is True


def test_informational_page_is_brand_referencing():
    body = ("<title>A Guide to PhilHealth Benefits</title><article>How to claim your "
            "benefits. Read more about contributions.</article>")
    out = candidate.assess_content(body, "https://philhealthguide.com/", "philhealth",
                                   "philhealth.gov.ph", "")
    assert out["has_cred_form"] is False and out["has_payment_form"] is False
    assert out["page_class"] == "informational"
