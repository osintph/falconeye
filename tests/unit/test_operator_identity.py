"""Operator identity must be configurable, and hiding Contact must really hide it.

Raised by an external self-hoster who asked how to remove the Contact page. The
underlying problem was bigger than the nav entry: the operator's name, inbox,
blog, privacy policy and canonical URLs were baked into the served HTML, and the
contact form posted to the upstream operator's Formspree endpoint, so a
self-hoster's visitors were mailing someone else.

Three properties are checked here:

1. **Defaults change nothing.** The public instance sets none of these, so the
   rendered page must be what it was, modulo the three deliberate additions.
2. **Hiding Contact removes it everywhere.** Not display:none, not an empty
   panel: gone from the HTML, gone from the nav, and GET /contact is a 404.
3. **The licence is not branding.** The AGPL notice and the upstream repository
   link survive every setting, because those are obligations, not identity.
"""
import re

import pytest

from app import config
from app.main import render_index

INDEX = "app/static/index.html"

# What the public instance publishes today. If a default changes, this list is
# where it gets noticed.
PUBLIC_INSTANCE_STRINGS = [
    '<meta name="author" content="OSINT-PH" />',
    '<link rel="canonical" href="https://falconeye.osintph.info/" />',
    '<meta property="og:url" content="https://falconeye.osintph.info/" />',
    '<meta property="og:image" content="https://falconeye.osintph.info/static/og-image.png" />',
    '"author": { "@type": "Organization", "name": "OSINT-PH", "url": "https://blog.osintph.info" }',
    '"sameAs": ["https://github.com/osintph", "https://blog.osintph.info"]',
    '<strong>Operator:</strong> OSINT-PH',
    'mailto:security@osintph.info',
    'mailto:privacy@osintph.info',
    'https://formspree.io/f/mojoezkp',
    '<code class="text-amber-300">falconeye.osintph.info</code>',
]

# Present regardless of operator settings. This is the licence.
LICENCE_STRINGS = [
    "AGPL-3.0",
    "github.com/osintph/falconeye",
]


def _render():
    with open(INDEX, encoding="utf-8") as f:
        return render_index(f.read())


def _self_hoster(monkeypatch, *, contact=False):
    monkeypatch.setattr(config, "OPERATOR_NAME", "Acme Security")
    monkeypatch.setattr(config, "OPERATOR_URL", "https://acme.example")
    monkeypatch.setattr(config, "OPERATOR_PROFILE_URL", "")
    monkeypatch.setattr(config, "OPERATOR_TAGLINE", "")
    monkeypatch.setattr(config, "OPERATOR_CONTACT_EMAIL", "hi@acme.example")
    monkeypatch.setattr(config, "OPERATOR_PRIVACY_EMAIL", "privacy@acme.example")
    monkeypatch.setattr(config, "OPERATOR_SITE_ORIGIN", "https://falcon.acme.example")
    monkeypatch.setattr(config, "CONTACT_ENABLED", contact)
    monkeypatch.setattr(config, "CONTACT_FORM_ACTION", "")


# ---------- 1. defaults reproduce the public instance ----------

def test_defaults_render_the_public_instance_unchanged():
    out = _render()
    for expected in PUBLIC_INSTANCE_STRINGS:
        assert expected in out, (
            f"default render no longer contains {expected!r}. The operator "
            "settings must default to exactly what the public instance serves."
        )


def test_no_unsubstituted_tokens_in_either_configuration(monkeypatch):
    """A missed token would render literal {{BRACES}} on the page."""
    assert not re.search(r"\{\{[A-Z_]+\}\}", _render())
    _self_hoster(monkeypatch)
    assert not re.search(r"\{\{[A-Z_]+\}\}", _render())


def test_contact_enabled_by_default():
    """The public instance keeps its Contact tab; hiding it is opt-in."""
    assert config.CONTACT_ENABLED is True
    assert 'id="tab-contact"' in _render()


# ---------- 2. hiding Contact ----------

def test_hidden_contact_removes_the_panel_from_the_html(monkeypatch):
    _self_hoster(monkeypatch, contact=False)
    out = _render()
    assert 'id="tab-contact"' not in out, (
        "the Contact panel is still in the page source. Hiding it in CSS or "
        "dropping the nav entry alone still publishes the operator's address."
    )
    assert "formspree" not in out
    assert "What we want to hear" not in out


def test_hidden_contact_tells_the_frontend_to_drop_the_nav_entry(monkeypatch):
    _self_hoster(monkeypatch, contact=False)
    assert '"contactEnabled": false' in _render()


def test_visible_contact_tells_the_frontend_to_keep_the_nav_entry():
    assert '"contactEnabled": true' in _render()


def test_nav_entry_is_driven_by_that_flag_and_nothing_else():
    """app.js must gate the Contact nav entry on the injected config.

    The nav, command palette, launcher grid and VALID_TABS all derive from
    ALL_NAV_ENTRIES, so gating the single declaration is what makes #contact
    fall back to home instead of showing a blank panel.
    """
    js = open("app/static/app.js", encoding="utf-8").read()
    assert "CONTACT_ENABLED" in js
    assert re.search(r"CONTACT_ENABLED\s*\?", js), (
        "the contact nav entry is no longer conditional on CONTACT_ENABLED"
    )


def test_hidden_contact_removes_the_footer_contact_link(monkeypatch):
    """The footer link belongs to the tab, so it goes with it.

    The privacy policy keeps a contact address either way, deliberately: a
    policy nobody can reply to is not a policy. Hiding the Contact tab removes
    the form and the footer shortcut, not the operator's obligation to be
    contactable about data.
    """
    _self_hoster(monkeypatch, contact=False)
    out = _render()
    assert ">Contact</a>" not in out, "the footer Contact link survived"
    assert "formspree" not in out and 'id="tab-contact"' not in out
    # Still reachable through the policy, which is the intended behaviour.
    assert "hi@acme.example" in out


def test_visible_contact_keeps_the_footer_contact_link(monkeypatch):
    _self_hoster(monkeypatch, contact=True)
    out = _render()
    assert ">Contact</a>" in out
    assert "mailto:hi@acme.example" in out


# ---------- the route ----------

def _client():
    from app.main import app
    from fastapi.testclient import TestClient
    return TestClient(app)


def test_contact_route_404s_when_hidden(monkeypatch):
    """A hidden page returns 404, not an empty page and not a redirect."""
    monkeypatch.setattr(config, "CONTACT_ENABLED", False)
    res = _client().get("/contact")
    assert res.status_code == 404


def test_contact_route_redirects_to_the_tab_when_enabled(monkeypatch):
    monkeypatch.setattr(config, "CONTACT_ENABLED", True)
    res = _client().get("/contact", follow_redirects=False)
    assert res.status_code == 302
    assert res.headers["location"] == "/#contact"


# ---------- 3. the privacy policy and the licence ----------

def test_privacy_policy_names_the_configured_operator(monkeypatch):
    _self_hoster(monkeypatch)
    out = _render()
    assert "<strong>Operator:</strong> Acme Security" in out
    assert "privacy@acme.example" in out
    assert "falcon.acme.example" in out
    # And must not name the upstream operator anywhere in the policy.
    for stale in ("OSINT-PH", "privacy@osintph.info", "security@osintph.info",
                  "blog.osintph.info", "falconeye.osintph.info"):
        assert stale not in out, f"privacy policy still names {stale!r}"


def test_seo_and_social_tags_follow_the_configured_origin(monkeypatch):
    _self_hoster(monkeypatch)
    out = _render()
    assert '<link rel="canonical" href="https://falcon.acme.example/" />' in out
    assert '<meta property="og:url" content="https://falcon.acme.example/" />' in out
    assert '<meta name="author" content="Acme Security" />' in out


@pytest.mark.parametrize("contact", [True, False])
def test_licence_and_upstream_repo_survive_every_setting(monkeypatch, contact):
    """AGPL attribution is an obligation, not branding. It is never hidden."""
    _self_hoster(monkeypatch, contact=contact)
    out = _render()
    for required in LICENCE_STRINGS:
        assert required in out, (
            f"{required!r} disappeared. The licence notice and the link to the "
            "upstream repository are not affected by operator settings."
        )


def test_operator_values_are_html_escaped(monkeypatch):
    """Operator settings come from .env, but they still land in HTML."""
    monkeypatch.setattr(config, "OPERATOR_NAME", '"><script>alert(1)</script>')
    out = _render()
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out
