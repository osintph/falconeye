"""The block list: who cannot be assessed, under both methods, with one wording."""
import pytest

from app.asm import blocklist


@pytest.mark.parametrize("domain", [
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "yahoo.com.ph", "icloud.com", "proton.me", "protonmail.com",
    "gmx.com", "mail.com", "yandex.com", "yandex.ru", "zoho.com",
])
def test_free_mail_providers_are_blocked(domain):
    reason = blocklist.classify(domain)
    assert reason is not None, f"{domain} should be blocked as free mail"
    assert reason.layer == "freemail"
    assert reason.operator_override is True


@pytest.mark.parametrize("domain", [
    "github.io", "vercel.app", "netlify.app", "herokuapp.com", "blogspot.com",
])
def test_shared_platform_apexes_are_blocked_as_parents(domain):
    reason = blocklist.classify(domain)
    assert reason is not None, f"{domain} should be blocked as a platform apex"
    assert reason.layer == "platform"
    assert reason.operator_override is True


@pytest.mark.parametrize("domain", [
    "acme.github.io", "myapp.vercel.app", "team.netlify.app", "shop.herokuapp.com",
])
def test_a_label_under_a_platform_apex_is_not_blocked(domain):
    # A user may verify their own label; only the apex and its siblings are blocked.
    assert blocklist.classify(domain) is None


@pytest.mark.parametrize("domain", ["com", "com.ph", "gov.ph", "co.uk", "org"])
def test_public_suffixes_are_blocked_and_never_overridable(domain):
    reason = blocklist.classify(domain)
    assert reason is not None, f"{domain} should be blocked as a public suffix"
    assert reason.layer == "public_suffix"
    assert reason.operator_override is False, "a public suffix is never overridable, even by operator mode"


@pytest.mark.parametrize("domain", [
    "example.com", "osintph.info", "acme.io", "corp-on-workspace.ph",
])
def test_ordinary_company_domains_are_allowed(domain):
    # A company domain is allowed regardless of which mail provider hosts its MX;
    # the block is by domain, never by MX record.
    assert blocklist.classify(domain) is None


def test_operator_env_additions_are_blocked(monkeypatch):
    monkeypatch.setattr("app.config.ASM_BLOCKED_DOMAINS", "secret-client.io, another.test")
    assert blocklist.classify("secret-client.io") is not None
    assert blocklist.classify("another.test") is not None


def test_block_message_is_a_single_constant():
    # Every reason funnels to the same wording; nothing reveals which rule matched.
    assert blocklist.BLOCK_MESSAGE == "This domain cannot be assessed here."
