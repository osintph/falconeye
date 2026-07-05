"""
Unit tests for app/scanner/ph_bank_indicators.py

Each indicator class has at least one positive and one negative test.
Specific regression: gobpi.cc/cancel/6t2w8y4b must match.
"""

from app.scanner.ph_bank_indicators import match_ph_indicators


# ---------------------------------------------------------------------------
# Regression: the case that surfaced this gap
# ---------------------------------------------------------------------------

def test_gobpi_cc_url_matches():
    """gobpi.cc/cancel/6t2w8y4b must hit at least the gobpi domain and /cancel/ path indicators."""
    url = "http://gobpi.cc/cancel/6t2w8y4b"
    matched_ids = {m["id"] for m in match_ph_indicators("", url)}
    assert "dom_gobpi" in matched_ids, "gobpi domain indicator did not fire"
    assert "ph_path_cancel" in matched_ids, "/cancel/ path indicator did not fire"


# ---------------------------------------------------------------------------
# URL path indicators
# ---------------------------------------------------------------------------

def test_path_cancel_matches():
    matched = {m["id"] for m in match_ph_indicators("", "http://evil.cc/cancel/abc123")}
    assert "ph_path_cancel" in matched

def test_path_verify_matches():
    matched = {m["id"] for m in match_ph_indicators("", "https://evil.cc/verify/step1")}
    assert "ph_path_verify" in matched

def test_path_suspended_matches():
    matched = {m["id"] for m in match_ph_indicators("", "https://evil.cc/suspended/")}
    assert "ph_path_suspended" in matched

def test_path_reactivate_matches():
    matched = {m["id"] for m in match_ph_indicators("", "https://evil.cc/reactivate/")}
    assert "ph_path_reactivate" in matched

def test_path_otp_matches():
    matched = {m["id"] for m in match_ph_indicators("", "https://evil.cc/otp/confirm")}
    assert "ph_path_otp" in matched

def test_path_does_not_match_clean_url():
    matched = match_ph_indicators("", "https://bpi.com.ph/personal/login")
    # /cancel/ /verify/ etc are not present — only URL-path indicators could fire, and none match here
    path_ids = {"ph_path_cancel", "ph_path_verify", "ph_path_suspended", "ph_path_reactivate"}
    assert not (path_ids & {m["id"] for m in matched})


# ---------------------------------------------------------------------------
# Domain impersonation indicators
# ---------------------------------------------------------------------------

def test_gobpi_domain():
    matched = {m["id"] for m in match_ph_indicators("", "http://gobpi.cc/login")}
    assert "dom_gobpi" in matched

def test_bpiverify_domain():
    matched = {m["id"] for m in match_ph_indicators("", "https://bpiverify.xyz/step1")}
    assert "dom_bpiverify" in matched

def test_bpi_online_hyphen_domain():
    matched = {m["id"] for m in match_ph_indicators("", "https://bpi-online.cc/")}
    assert "dom_bpi_hyphen" in matched

def test_bdo_online_domain():
    matched = {m["id"] for m in match_ph_indicators("", "https://bdo-online.xyz/")}
    assert "dom_bdo_online" in matched

def test_gcash_verify_domain():
    matched = {m["id"] for m in match_ph_indicators("", "https://gcash-verify.cc/")}
    assert "dom_gcash_verify" in matched

def test_maya_cancel_domain():
    matched = {m["id"] for m in match_ph_indicators("", "https://maya-cancel.info/")}
    assert "dom_maya_cancel" in matched

def test_paymaya_hyphen_domain():
    matched = {m["id"] for m in match_ph_indicators("", "https://paymaya-ph.cc/")}
    assert "dom_paymaya" in matched

def test_legitimate_bpi_domain_does_not_match():
    # Real BPI domain does not contain typosquat patterns
    matched = {m["id"] for m in match_ph_indicators("", "https://bpi.com.ph/login")}
    domain_ids = {"dom_gobpi", "dom_bpiverify", "dom_bpi_hyphen", "dom_bdo_online",
                  "dom_gcash_verify", "dom_maya_cancel"}
    assert not (domain_ids & matched)

def test_legitimate_gcash_domain_does_not_match():
    matched = {m["id"] for m in match_ph_indicators("", "https://gcash.com/login")}
    assert "dom_gcash_verify" not in matched
    assert "dom_gcash_update" not in matched


# ---------------------------------------------------------------------------
# HTML content indicators
# ---------------------------------------------------------------------------

def test_otp_input_name_matches():
    html = '<input type="text" name="otp" placeholder="Enter OTP">'
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_otp_input_name" in matched

def test_otp_input_id_matches():
    html = '<input type="text" id="otp">'
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_otp_input_id" in matched

def test_one_time_password_text_matches():
    html = "<p>Enter your one-time password to continue.</p>"
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_bpi_otp_field" in matched

def test_tin_field_matches():
    html = '<input type="text" name="tin" placeholder="TIN Number">'
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_tin_input" in matched

def test_tin_text_matches():
    html = "<label>Please enter your TIN number:</label>"
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_tin_field" in matched

def test_bpi_brand_in_html_matches():
    html = "<title>Bank of the Philippine Islands – Secure Login</title>"
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_bpi_brand" in matched

def test_bdo_brand_in_html_matches():
    html = "<p>Welcome to Banco de Oro online banking.</p>"
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_bdo_brand" in matched

def test_card_number_field_matches():
    html = '<input type="text" name="card_number" maxlength="16">'
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_card_number_field" in matched

def test_cvv_field_matches():
    html = '<input type="text" name="cvv" maxlength="3">'
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_cvv_field" in matched

def test_submit_php_action_matches():
    html = '<form action="submit.php" method="POST">'
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_submit_php" in matched

def test_process_php_action_matches():
    html = '<form action="process.php" method="POST">'
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_process_php" in matched

def test_clean_login_html_no_indicators():
    html = "<html><body><form><input type='text' name='username'><input type='password' name='password'></form></body></html>"
    matched = {m["id"] for m in match_ph_indicators(html, "https://example.com/login")}
    # Clean form with no PH-banking-specific fields should produce no PH indicator hits
    assert "html_otp_input_name" not in matched
    assert "html_tin_input" not in matched
    assert "html_card_number_field" not in matched


# ---------------------------------------------------------------------------
# HTML structure indicators
# ---------------------------------------------------------------------------

def test_hidden_bank_name_field_matches():
    html = '<input type="hidden" name="bank_name" value="BPI">'
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_hidden_bank_name" in matched

def test_hidden_account_type_matches():
    html = '<input type="hidden" name="account_type" value="savings">'
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_hidden_account_type" in matched

def test_hidden_target_bank_matches():
    html = '<input type="hidden" name="target_bank" value="BDO">'
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_hidden_target_bank" in matched


# ---------------------------------------------------------------------------
# Case-insensitivity
# ---------------------------------------------------------------------------

def test_case_insensitive_url():
    url = "http://GOBPI.CC/CANCEL/ABC"
    matched = {m["id"] for m in match_ph_indicators("", url)}
    assert "dom_gobpi" in matched
    assert "ph_path_cancel" in matched

def test_case_insensitive_html():
    html = '<INPUT TYPE="TEXT" NAME="OTP">'
    matched = {m["id"] for m in match_ph_indicators(html, "")}
    assert "html_otp_input_name" in matched
