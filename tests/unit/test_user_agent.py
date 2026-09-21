"""Outbound User-Agent strings must name the operator running THIS instance.

Every upstream FalconEye queries sees a User-Agent carrying a contact token, so
that an API with a complaint about our traffic knows who to complain to. Until
v3.33.1 that token was the upstream operator's domain, hardcoded in 18 places.
A self-hoster's traffic to AbuseIPDB, VirusTotal, ransomware.live and the rest
was therefore attributed to someone with no connection to it, and who could not
answer for it.

Two properties:

1. No module hardcodes an operator domain in a User-Agent any more.
2. With the default config the strings are byte-for-byte what they were, so
   upstreams that allowlisted or recognised the old value see no change.
"""
import pathlib
import re

from app import config

APP = pathlib.Path(__file__).resolve().parents[2] / "app"

# Exactly what shipped before the strings were made configurable, so this is a
# regression test against the defaults drifting, not just a shape check.
EXPECTED_DEFAULTS = {
    "FalconEye/3.0 (osintph.info)",
    "FalconEye/3.0 (osintph.info; OSINT research)",
    "FalconEye/3.0 (osintph.info; threat research)",
    "FalconEye/3.6.0 (+https://falconeye.osintph.info)",
    "FalconEye/3.7 (osintph.info; abuse contact lookup)",
    "FalconEye/3.8.0 (+https://falconeye.osintph.info; OSINT username enumeration)",
    "FalconEye/3.9 (osintph.info; IP reputation)",
    "FalconEye/3.16 (osintph.info; ransomware watch, non-commercial, attributed)",
    "FalconEye/3.17 (osintph.info; on-demand lookup)",
    "FalconEye/3.33 (osintph.info; infostealer exposure check)",
}


def _ua_templates():
    """Every f-string User-Agent template in the app tree."""
    found = {}
    for path in APP.rglob("*.py"):
        for m in re.finditer(r'f"(FalconEye/[^"]*)"', path.read_text()):
            found.setdefault(m.group(1), set()).add(str(path.relative_to(APP)))
    return found


def _render(template: str) -> str:
    return (template
            .replace("{OPERATOR_CONTACT_UA}", config.OPERATOR_CONTACT_UA)
            .replace("{OPERATOR_SITE_ORIGIN}", config.OPERATOR_SITE_ORIGIN))


def test_no_user_agent_hardcodes_an_operator_domain():
    """A literal domain in a UA is someone else's abuse contact on a fork."""
    offenders = []
    for path in APP.rglob("*.py"):
        for m in re.finditer(r'"(FalconEye/[^"]*osintph[^"]*)"', path.read_text()):
            # An f-string template is fine; a plain literal is not.
            start = max(0, m.start() - 1)
            if path.read_text()[start] != "f":
                offenders.append(f"{path.relative_to(APP)}: {m.group(1)}")
    assert not offenders, (
        "User-Agent strings still hardcode an operator domain:\n  "
        + "\n  ".join(offenders)
        + "\nUse OPERATOR_CONTACT_UA (or OPERATOR_SITE_ORIGIN for the +URL form)."
    )


def test_defaults_reproduce_the_shipped_user_agents():
    rendered = {_render(t) for t in _ua_templates()}
    assert rendered == EXPECTED_DEFAULTS, (
        "the default User-Agent strings changed.\n"
        f"  unexpected: {sorted(rendered - EXPECTED_DEFAULTS)}\n"
        f"  missing:    {sorted(EXPECTED_DEFAULTS - rendered)}"
    )


def test_setting_the_contact_token_changes_every_bare_form(monkeypatch):
    monkeypatch.setattr(config, "OPERATOR_CONTACT_UA", "acme.example")
    rendered = [_render(t) for t in _ua_templates() if "{OPERATOR_CONTACT_UA}" in t]
    assert rendered, "no User-Agent uses the contact token"
    for ua in rendered:
        assert "acme.example" in ua and "osintph" not in ua


def test_setting_the_site_origin_changes_every_url_form(monkeypatch):
    monkeypatch.setattr(config, "OPERATOR_SITE_ORIGIN", "https://falcon.acme.example")
    rendered = [_render(t) for t in _ua_templates() if "{OPERATOR_SITE_ORIGIN}" in t]
    assert rendered, "no User-Agent uses the site origin"
    for ua in rendered:
        assert "falcon.acme.example" in ua and "osintph" not in ua


def test_every_user_agent_still_carries_a_contact():
    """Attribution is a condition of use for at least one upstream.

    ransomware.live's terms want non-commercial attribution, and its UA says so
    explicitly. A UA with no contact token at all is a regression.
    """
    for template in _ua_templates():
        assert ("{OPERATOR_CONTACT_UA}" in template
                or "{OPERATOR_SITE_ORIGIN}" in template), (
            f"{template!r} carries no contact token"
        )
