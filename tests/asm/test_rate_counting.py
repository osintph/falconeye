"""v3.37.2: verification limits count only attempts that issue a token or send an
email, not blocked domains, bad input, or repeated checks."""
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main
from app.asm import store


def _client(ip="203.0.113.8"):
    return TestClient(main.app, base_url="https://testserver", client=(ip, 1))


def test_blocked_domain_does_not_consume_an_attempt():
    _client().post("/api/asm/verify/start", json={"domain": "gmail.com", "method": "dns"})
    assert store.rl_count("vstart_dom", "gmail.com", 86400) == 0
    assert store.rl_count("vstart_ip", "203.0.113.8", 3600) == 0


def test_bad_role_does_not_consume_an_attempt():
    r = _client().post("/api/asm/verify/start",
                       json={"domain": "ok-domain.test", "method": "email", "role": "ceo"})
    assert r.status_code == 400
    assert store.rl_count("vstart_dom", "ok-domain.test", 86400) == 0
    assert store.rl_count("vstart_ip", "203.0.113.8", 3600) == 0
    assert store.rl_count("vemail_dom", "ok-domain.test", 86400) == 0


def test_dns_start_counts_exactly_once():
    _client().post("/api/asm/verify/start", json={"domain": "counts.test", "method": "dns"})
    assert store.rl_count("vstart_dom", "counts.test", 86400) == 1
    assert store.rl_count("vstart_ip", "203.0.113.8", 3600) == 1


def test_email_send_counts_the_email():
    async def fake_send(domain, role_email, link):
        return {"sent": True}
    with patch("app.asm.mailer.configured", return_value=True), \
         patch("app.asm.mailer.send_verification_link", side_effect=fake_send):
        _client().post("/api/asm/verify/start",
                       json={"domain": "mail.test", "method": "email", "role": "security"})
    assert store.rl_count("vemail_dom", "mail.test", 86400) == 1
    assert store.rl_count("vstart_dom", "mail.test", 86400) == 1


def test_mailer_not_configured_does_not_consume_an_attempt():
    with patch("app.asm.mailer.configured", return_value=False):
        r = _client().post("/api/asm/verify/start",
                           json={"domain": "nomail.test", "method": "email", "role": "security"})
    assert r.status_code == 503
    assert store.rl_count("vstart_dom", "nomail.test", 86400) == 0
    assert store.rl_count("vemail_dom", "nomail.test", 86400) == 0


def test_repeated_dns_checks_do_not_accumulate_a_persistent_counter(monkeypatch):
    # A failed check (TXT not found yet) must not fill a persistent limit table,
    # so a user polling while DNS propagates is not locked out of checking.
    monkeypatch.setattr("app.asm.verify.check_dns", _none)
    c = _client("203.0.113.44")
    for _ in range(8):
        r = c.post("/api/asm/verify/check-dns", json={"domain": "poll.test"})
        assert r.status_code == 200 and r.json()["verified"] is False
    # No persistent rows were written for the checks.
    conn = store._connect()
    try:
        total = conn.execute("SELECT COUNT(*) FROM asm_rate_limit WHERE key = ?",
                             ("poll.test",)).fetchone()[0]
    finally:
        conn.close()
    assert total == 0


async def _none(domain):
    return None
