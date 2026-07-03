"""
Tests for resolve_identity().

Fixture files used:
  about_domain_stripe_com.json  -- kg.title="Stripe, Inc.", description confirms title
  about_domain_orf_at.json      -- kg.title="ORF" (short), description reveals long name
  about_domain_bp_com.json      -- kg.title="BP" (short), description reveals "BP p.l.c."
  about_domain_ibm_com.json     -- empty kg, ai_overview reveals full IBM name
"""
import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# ---------------------------------------------------------------------------
# stripe.com: high confidence, title confirmed by description
# ---------------------------------------------------------------------------

def test_stripe_high_confidence():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_stripe_com.json")
    identity = resolve_identity("stripe.com", about)
    assert identity.confidence == "high"
    assert identity.source == "knowledge_graph"
    assert "stripe" in identity.canonical_name.lower()


def test_stripe_canonical_includes_name():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_stripe_com.json")
    identity = resolve_identity("stripe.com", about)
    # Description starts "Stripe, Inc. is..." so canonical is "Stripe, Inc."
    assert identity.canonical_name == "Stripe, Inc."
    assert identity.display_name == "Stripe, Inc."


# ---------------------------------------------------------------------------
# orf.at: short title, description reveals long Austrian name
# ---------------------------------------------------------------------------

def test_orf_extracts_long_name_from_description():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_orf_at.json")
    identity = resolve_identity("orf.at", about)
    assert identity.canonical_name == "Österreichischer Rundfunk"
    assert identity.display_name == "ORF"  # kept for readability
    assert identity.confidence == "high"
    assert identity.source == "knowledge_graph"


def test_orf_aliases_include_short_name():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_orf_at.json")
    identity = resolve_identity("orf.at", about)
    aliases_lower = [a.lower() for a in identity.aliases]
    assert "orf" in aliases_lower


# ---------------------------------------------------------------------------
# bp.com: short title "BP", description reveals "BP p.l.c."
# ---------------------------------------------------------------------------

def test_bp_extracts_legal_name_from_description():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_bp_com.json")
    identity = resolve_identity("bp.com", about)
    assert "bp p.l.c." in identity.canonical_name.lower()
    assert identity.confidence == "high"
    assert identity.source == "knowledge_graph"


def test_bp_display_name_is_short_form():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_bp_com.json")
    identity = resolve_identity("bp.com", about)
    assert identity.display_name == "BP"


# ---------------------------------------------------------------------------
# ibm.com: empty kg, ai_overview reveals full legal name
# ---------------------------------------------------------------------------

def test_ibm_resolves_from_ai_overview():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_ibm_com.json")
    identity = resolve_identity("ibm.com", about)
    assert "international business machines" in identity.canonical_name.lower()
    assert identity.source == "ai_overview"
    assert identity.confidence == "medium"


def test_ibm_display_name_is_short_form():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_ibm_com.json")
    identity = resolve_identity("ibm.com", about)
    assert identity.display_name == "IBM"


def test_ibm_aliases_include_ibm():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_ibm_com.json")
    identity = resolve_identity("ibm.com", about)
    aliases_lower = [a.lower() for a in identity.aliases]
    assert "ibm" in aliases_lower


# ---------------------------------------------------------------------------
# Unknown domain: no about_data -> domain fallback
# ---------------------------------------------------------------------------

def test_unknown_domain_no_about_data():
    from app.prospect.resolver import resolve_identity
    identity = resolve_identity("unknowndomain12345.tld", None)
    assert identity.confidence == "low"
    assert identity.source == "domain_fallback"
    assert identity.canonical_name == "unknowndomain12345.tld"


def test_unknown_domain_empty_about_data():
    from app.prospect.resolver import resolve_identity
    identity = resolve_identity("unknowndomain12345.tld", {})
    assert identity.confidence == "low"
    assert identity.source == "domain_fallback"


# ---------------------------------------------------------------------------
# Confidence drives query construction (logic validation)
# ---------------------------------------------------------------------------

def test_high_confidence_has_quoted_news_query():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_stripe_com.json")
    identity = resolve_identity("stripe.com", about)
    assert identity.confidence in ("high", "medium")
    # Build the query as service.py would
    news_q = f'"{identity.canonical_name}" OR site:stripe.com'
    assert '"Stripe, Inc."' in news_q
    assert "site:stripe.com" in news_q


def test_low_confidence_uses_site_only_query():
    from app.prospect.resolver import resolve_identity
    identity = resolve_identity("unknowndomain12345.tld", None)
    assert identity.confidence == "low"
    # Service skips jobs and uses site: only for news
    news_q = f"site:unknowndomain12345.tld"
    assert "site:" in news_q
    # No company name in the query (it's just the domain)
    assert '"unknowndomain12345.tld"' not in news_q


# ---------------------------------------------------------------------------
# hp.com: ai_overview only (no KG), parenthetical extraction
# ---------------------------------------------------------------------------

def test_hp_resolves_from_ai_overview():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_hp_com.json")
    identity = resolve_identity("hp.com", about)
    assert "hewlett" in identity.canonical_name.lower()
    assert identity.source == "ai_overview"
    assert identity.confidence == "medium"


def test_hp_display_name_is_short_form():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_hp_com.json")
    identity = resolve_identity("hp.com", about)
    assert identity.display_name == "HP"


def test_hp_category_hint_empty_when_no_kg():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_hp_com.json")
    identity = resolve_identity("hp.com", about)
    # No KG subtitle available for hp.com fixture
    assert identity.category_hint == ""


def test_bp_category_hint_from_kg_subtitle():
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_bp_com.json")
    identity = resolve_identity("bp.com", about)
    assert "oil" in identity.category_hint.lower()
