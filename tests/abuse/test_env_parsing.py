"""
v3.8.2 regression: env values with inline comments must not break credential /
config reads. See docs/regressions.md (v3.8.1) — a `# comment` on the
FALCONEYE_ABUSE_ADMIN_PASS_HASH line reached bcrypt.checkpw and rejected the
correct password.
"""
import bcrypt

from app.utils.env import clean_env_value, getenv_clean


def test_inline_comment_stripped_from_unquoted_value():
    assert clean_env_value("bar  # comment") == "bar"
    assert clean_env_value("eu   # or us") == "eu"
    # no whitespace before '#' → kept (e.g. a URL fragment)
    assert clean_env_value("https://x/y#frag") == "https://x/y#frag"
    # surrounding quotes stripped, contents kept verbatim
    assert clean_env_value('"Sigmund Brandstaetter, OSINT-PH"') == "Sigmund Brandstaetter, OSINT-PH"
    assert clean_env_value(None) == ""


def test_bcrypt_hash_with_inline_comment_is_recovered():
    password = b"correct horse battery staple"
    real_hash = bcrypt.hashpw(password, bcrypt.gensalt()).decode()      # 60 chars
    env_line_value = f"{real_hash}  # bcrypt hash you generate"          # what systemd hands us

    cleaned = clean_env_value(env_line_value)

    assert len(cleaned) == 60
    assert "#" not in cleaned
    assert cleaned == real_hash
    assert bcrypt.checkpw(password, cleaned.encode("utf-8")) is True


def test_getenv_clean_reads_and_cleans(monkeypatch):
    monkeypatch.setenv("FE_TEST_VAR", "value123  # inline note")
    assert getenv_clean("FE_TEST_VAR") == "value123"
    monkeypatch.delenv("FE_TEST_VAR", raising=False)
    assert getenv_clean("FE_TEST_VAR", "fallback") == "fallback"


def test_verify_admin_accepts_hash_that_had_a_comment(monkeypatch):
    """End-to-end: the abuse route's admin check works even if the env hash line
    carried an inline comment."""
    from app.abuse import routes as abuse_routes
    password = "s3cret-pw"
    real_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    monkeypatch.setenv("FALCONEYE_ABUSE_ADMIN_USER", "admin")
    monkeypatch.setenv("FALCONEYE_ABUSE_ADMIN_PASS_HASH", f"{real_hash}  # bcrypt hash you generate")

    assert abuse_routes._verify_admin("admin", password) is None            # success
    assert abuse_routes._verify_admin("admin", "wrong") == "invalid credentials"
