"""
Unit tests for app/scanner/cloudflare_detect.py
"""

from app.scanner.cloudflare_detect import detect_cloudflare_challenge

_CF_BLOCKED_HTML = """
<!DOCTYPE html>
<html>
<head><title>Attention Required! | Cloudflare</title></head>
<body>
  <div class="cf-error-details">
    <h1>Sorry, you have been blocked</h1>
    <p>You are unable to access this site.</p>
    <div>Cloudflare Ray ID: 89abcd1234ef0000</div>
  </div>
</body>
</html>
"""

_CF_CHALLENGE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Just a moment...</title></head>
<body>
  <div id="cf-browser-verification">
    <p>Enable JavaScript and cookies to continue</p>
  </div>
</body>
</html>
"""

_LEGITIMATE_HTML = """
<!DOCTYPE html>
<html>
<head><title>BPI Online Banking Login</title></head>
<body>
  <form method="POST" action="/login">
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Log In</button>
  </form>
</body>
</html>
"""

_EMPTY_HTML = ""


def test_detects_cloudflare_blocked_page():
    result = detect_cloudflare_challenge(_CF_BLOCKED_HTML)
    assert result is not None
    assert result["id"] == "cloudflare_bot_protection"
    assert result["severity"] == "medium"


def test_detects_cloudflare_challenge():
    result = detect_cloudflare_challenge(_CF_CHALLENGE_HTML)
    assert result is not None
    assert result["id"] == "cloudflare_bot_protection"


def test_detects_cf_body_signal_alone():
    html = "<html><body>Please enable JavaScript and cookies to continue</body></html>"
    result = detect_cloudflare_challenge(html)
    assert result is not None


def test_detects_attention_required_title():
    html = "<html><head><title>Attention Required! | Cloudflare</title></head><body></body></html>"
    result = detect_cloudflare_challenge(html)
    assert result is not None


def test_detects_cloudflare_ray_id():
    html = "<html><body>Cloudflare Ray ID: abc123</body></html>"
    result = detect_cloudflare_challenge(html)
    assert result is not None


def test_does_not_flag_legitimate_page():
    result = detect_cloudflare_challenge(_LEGITIMATE_HTML)
    assert result is None


def test_does_not_flag_empty_html():
    result = detect_cloudflare_challenge(_EMPTY_HTML)
    assert result is None


def test_does_not_flag_plain_login_page():
    html = "<html><body><form><input type='password'></form></body></html>"
    result = detect_cloudflare_challenge(html)
    assert result is None


def test_case_insensitive_title_match():
    html = "<html><head><title>JUST A MOMENT</title></head><body></body></html>"
    result = detect_cloudflare_challenge(html)
    assert result is not None


def test_indicator_shape_is_complete():
    result = detect_cloudflare_challenge(_CF_BLOCKED_HTML)
    assert result is not None
    for key in ("id", "type", "pattern", "severity", "description", "category"):
        assert key in result, f"Missing key: {key}"
