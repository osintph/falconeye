"""Verification: hashed storage, single use, expiry, role allowlist, DNS re-check."""
import asyncio

import pytest

from app.asm import store, verify


def _run(coro):
    return asyncio.run(coro)


def test_dns_token_is_stored_hashed_not_in_the_clear():
    raw = verify.start_dns_verification("example.com", "iphash")
    th = verify.hash_token(raw)
    row = store.get_live_verification(th)
    assert row is not None and row["method"] == "dns"
    # The raw token is never a column value.
    conn = store._connect()
    try:
        hit = conn.execute("SELECT COUNT(*) FROM asm_verifications WHERE token_hash = ?", (raw,)).fetchone()[0]
    finally:
        conn.close()
    assert hit == 0, "the raw token must not be stored; only its hash"


def test_email_verification_is_single_use():
    started = verify.start_email_verification("example.com", "security", "iphash")
    assert started is not None
    raw, addr = started
    assert addr == "security@example.com"
    first = verify.confirm_consume(raw)
    assert first is not None
    second = verify.confirm_consume(raw)
    assert second is None, "a consumed verification cannot be consumed again"


def test_expired_verification_is_not_live():
    raw = verify.start_dns_verification("example.com", "iphash")
    th = verify.hash_token(raw)
    conn = store._connect()
    try:
        conn.execute("UPDATE asm_verifications SET expires_at = ? WHERE token_hash = ?",
                     (store.now() - 10, th))
        conn.commit()
    finally:
        conn.close()
    assert store.get_live_verification(th) is None


@pytest.mark.parametrize("role,ok", [
    ("security", True), ("postmaster", True), ("admin", True), ("administrator", True),
    ("hostmaster", True), ("webmaster", True),
    ("ceo", False), ("info", False), ("sales", False), ("", False),
])
def test_only_role_addresses_are_allowed(role, ok):
    started = verify.start_email_verification("example.com", role, "iphash")
    assert (started is not None) == ok


def test_dns_token_present_matches_published_record(monkeypatch):
    raw = verify.start_dns_verification("example.com", "iphash")
    th = verify.hash_token(raw)

    def fake_txt(name):
        if name == "example.com":
            return [f"{verify.TXT_PREFIX}{raw}"]
        return []
    monkeypatch.setattr(verify, "_txt_values_sync", fake_txt)
    assert _run(verify.dns_token_present("example.com", th)) is True
    assert _run(verify.dns_token_present("example.com", verify.hash_token("other"))) is False


def test_check_dns_consumes_and_pins_the_token(monkeypatch):
    raw = verify.start_dns_verification("example.com", "iphash")

    def fake_txt(name):
        return [raw] if name == "_falconeye.example.com" else []
    monkeypatch.setattr(verify, "_txt_values_sync", fake_txt)

    row = _run(verify.check_dns("example.com"))
    assert row is not None
    dom = store.get_domain("example.com")
    assert dom and dom["dns_token_hash"] == verify.hash_token(raw)
    # Consumed, so a second check finds no live verification to consume.
    assert _run(verify.check_dns("example.com")) is None


def test_grant_cookie_binds_to_one_domain():
    cookie = verify.issue_grant("sub.example.com", "dns", "")
    grant = verify.grant_from_cookie(cookie)
    assert grant is not None
    assert grant["domain"] == "sub.example.com"
    # A subdomain grant is not a parent grant: the bound domain is the subdomain.
    assert grant["domain"] != "example.com"


def test_revoked_grant_is_not_live():
    cookie = verify.issue_grant("example.com", "dns", "")
    assert verify.grant_from_cookie(cookie) is not None
    store.revoke_all_grants("example.com")
    assert verify.grant_from_cookie(cookie) is None
