"""v3.37.2: verification links point to the confirm page, and each link failure
has its own message. A signature failure is never reported as rotated or revoked.
"""
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import main
from app.asm import signing, store, verify


def _client():
    return TestClient(main.app, base_url="https://testserver", client=("203.0.113.7", 1))


def test_verification_email_links_to_confirm_not_manage():
    captured = {}

    async def fake_send(domain, role_email, link):
        captured["link"] = link
        return {"sent": True}

    with patch("app.asm.mailer.configured", return_value=True), \
         patch("app.asm.mailer.send_verification_link", side_effect=fake_send):
        r = _client().post("/api/asm/verify/start",
                           json={"domain": "osintph.net", "method": "email", "role": "security"})
    assert r.status_code == 200
    link = captured["link"]
    assert "/asm/confirm?t=" in link, f"verification email must link to confirm, got {link}"
    assert "/asm/manage" not in link


# -------------------------------------------------- confirm link messages ----

def test_confirm_detail_distinguishes_states():
    raw = verify.start_email_verification("a.test", "security", "h")[0]
    th = verify.hash_token(raw)
    assert verify.confirm_detail(raw)[0] == "ok"
    # unknown token
    assert verify.confirm_detail("no-such-token")[0] == "unknown"
    # used
    row = store.get_live_verification(th)
    store.consume_verification(row["id"])
    assert verify.confirm_detail(raw)[0] == "used"


def test_confirm_detail_expired():
    raw = verify.start_email_verification("b.test", "security", "h")[0]
    th = verify.hash_token(raw)
    conn = store._connect()
    try:
        conn.execute("UPDATE asm_verifications SET expires_at = ? WHERE token_hash = ?",
                     (store.now() - 10, th))
        conn.commit()
    finally:
        conn.close()
    assert verify.confirm_detail(raw)[0] == "expired"


@pytest.mark.parametrize("status,needle", [
    ("used", "already been used"), ("expired", "has expired"), ("unknown", "not recognised"),
])
def test_confirm_page_messages_are_distinct(monkeypatch, status, needle):
    # Drive the page by forcing confirm_detail to each status.
    monkeypatch.setattr(verify, "confirm_detail", lambda t: (status, None))
    r = _client().get("/asm/confirm", params={"t": "x"})
    assert r.status_code == 410
    assert needle in r.text


# -------------------------------------------------- manage link messages ----

def test_management_detail_distinguishes_states():
    store.upsert_domain("c.test", "verified", verify_method="email")
    token = signing.sign({"domain": "c.test", "v": 1, "kind": "mgmt"}, signing.MGMT_SALT)
    assert verify.management_detail(token)[0] == "ok"
    # a garbage / tampered token is a SIGNATURE failure, never "rotated"
    assert verify.management_detail("garbage-not-a-token")[0] == "bad"
    # rotating bumps the version, so the old token is "rotated", not "bad"
    store.bump_mgmt_version("c.test")
    assert verify.management_detail(token)[0] == "rotated"
    # a token for a deleted domain
    tok2 = signing.sign({"domain": "gone.test", "v": 1, "kind": "mgmt"}, signing.MGMT_SALT)
    assert verify.management_detail(tok2)[0] == "deleted"


def test_bad_signature_is_not_reported_as_rotated_or_revoked():
    r = _client().get("/asm/manage", params={"t": "clearly-not-a-valid-token"})
    assert r.status_code == 410
    assert "could not be verified" in r.text
    assert "rotated or revoked" not in r.text
    assert "rotated" not in r.text.lower()


def test_rotated_link_says_replaced_not_signature_error():
    store.upsert_domain("d.test", "verified", verify_method="email")
    token = signing.sign({"domain": "d.test", "v": 1, "kind": "mgmt"}, signing.MGMT_SALT)
    store.bump_mgmt_version("d.test")
    r = _client().get("/asm/manage", params={"t": token})
    assert r.status_code == 410
    assert "replaced by a newer one" in r.text
    assert "could not be verified" not in r.text
