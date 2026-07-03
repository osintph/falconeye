"""
Company identity resolver for the Company tab.

Resolution priority:
  1. kg.description: extract name before " is " (most authoritative)
  2. ai_overview paragraphs: parenthetical extraction, then " is " extraction
  3. kg.title if longer than 4 chars
  4. kg.title + " " + kg.subtitle when title is short with subtitle context
  5. Domain fallback (confidence=low)

The resolved CompanyIdentity drives downstream query construction:
  - confidence high/medium: full quoted queries for news and jobs
  - confidence low:         site: news query only; jobs call skipped entirely
"""
import logging
import re
from dataclasses import dataclass, field

log = logging.getLogger("falconeye.prospect.resolver")

# Matches "Company Name is a ..." capturing the name before the verb
_BEFORE_IS_RE = re.compile(r"^(.{4,80}?)\s+is\s+", re.UNICODE)

# Matches "Full Legal Name (ACRONYM) ..." capturing the full name before the parenthetical
_BEFORE_PAREN_RE = re.compile(r"^(.{4,80}?)\s*\(", re.UNICODE)


@dataclass
class CompanyIdentity:
    display_name: str
    canonical_name: str
    aliases: list
    confidence: str   # "high" | "medium" | "low"
    source: str       # "knowledge_graph" | "ai_overview" | "domain_fallback"


def _before_is(text: str):
    """Extract the subject of a sentence in the form 'Subject is ...'."""
    m = _BEFORE_IS_RE.match(text.strip())
    return m.group(1).strip() if m else None


def _before_paren(text: str):
    """Extract the text before a parenthetical like 'Legal Name (ACRONYM)'."""
    m = _BEFORE_PAREN_RE.match(text.strip())
    if m:
        candidate = m.group(1).strip()
        if len(candidate) > 3:
            return candidate
    return None


def resolve_identity(domain: str, about_data: dict) -> CompanyIdentity:
    """Return the best company identity resolvable from an about_domain response."""
    domain_root = domain.split(".")[0]
    domain_root_cap = domain_root.capitalize()

    if not about_data:
        log.info("resolver path=domain_fallback domain=%s reason=no_about_data", domain)
        return CompanyIdentity(
            display_name=domain_root_cap,
            canonical_name=domain,
            aliases=[domain_root_cap],
            confidence="low",
            source="domain_fallback",
        )

    kg = about_data.get("knowledge_graph") or {}
    ai = about_data.get("ai_overview") or {}

    kg_title = (kg.get("title") or "").strip()
    kg_subtitle = (kg.get("subtitle") or "").strip()
    kg_desc = (kg.get("description") or "").strip()

    # ------------------------------------------------------------------
    # Path 1: kg.description sentence extraction
    # ------------------------------------------------------------------
    if kg_desc:
        extracted = _before_is(kg_desc)
        if extracted:
            if len(extracted) > len(kg_title):
                # Description reveals a longer/fuller name than title (e.g. orf.at)
                aliases = []
                if kg_title and kg_title.lower() != extracted.lower():
                    aliases.append(kg_title)
                aliases.append(domain_root_cap)
                log.info(
                    "resolver path=kg_desc_extended domain=%s canonical=%r display=%r",
                    domain, extracted, kg_title or extracted,
                )
                return CompanyIdentity(
                    display_name=kg_title or extracted,
                    canonical_name=extracted,
                    aliases=aliases,
                    confidence="high",
                    source="knowledge_graph",
                )
            # Description confirms the title (e.g. stripe.com: "Stripe, Inc. is an Irish...")
            aliases = [domain_root_cap]
            if kg_subtitle:
                aliases.append(kg_subtitle)
            log.info(
                "resolver path=kg_desc_confirmed domain=%s canonical=%r",
                domain, extracted,
            )
            return CompanyIdentity(
                display_name=extracted,
                canonical_name=extracted,
                aliases=aliases,
                confidence="high",
                source="knowledge_graph",
            )

    # ------------------------------------------------------------------
    # Path 2: ai_overview paragraphs (fallback when KG description absent)
    # ------------------------------------------------------------------
    ai_header = None
    for block in (ai.get("text_blocks") or []):
        btype = block.get("type", "")
        banswer = (block.get("answer") or "").strip()
        if btype == "header":
            ai_header = banswer
        elif btype == "paragraph" and " is " in banswer and len(banswer) > 20:
            extracted = _before_paren(banswer) or _before_is(banswer)
            if extracted and len(extracted) > 4:
                display = ai_header or extracted
                aliases = []
                if ai_header and ai_header.lower() != extracted.lower():
                    aliases.append(ai_header)
                aliases.append(domain_root_cap)
                log.info(
                    "resolver path=ai_overview domain=%s canonical=%r display=%r",
                    domain, extracted, display,
                )
                return CompanyIdentity(
                    display_name=display,
                    canonical_name=extracted,
                    aliases=aliases,
                    confidence="medium",
                    source="ai_overview",
                )

    # ------------------------------------------------------------------
    # Path 3: kg.title when it is long enough to be unambiguous
    # ------------------------------------------------------------------
    if kg_title and len(kg_title) > 4:
        aliases = [domain_root_cap]
        if kg_subtitle:
            aliases.append(kg_subtitle)
        log.info("resolver path=kg_title domain=%s canonical=%r", domain, kg_title)
        return CompanyIdentity(
            display_name=kg_title,
            canonical_name=kg_title,
            aliases=aliases,
            confidence="high",
            source="knowledge_graph",
        )

    # ------------------------------------------------------------------
    # Path 4: short kg.title merged with subtitle for disambiguation
    # ------------------------------------------------------------------
    if kg_title and kg_subtitle:
        canonical = f"{kg_title} {kg_subtitle}"
        log.info(
            "resolver path=kg_title_subtitle domain=%s canonical=%r",
            domain, canonical,
        )
        return CompanyIdentity(
            display_name=kg_title,
            canonical_name=canonical,
            aliases=[kg_title, domain_root_cap],
            confidence="medium",
            source="knowledge_graph",
        )

    # ------------------------------------------------------------------
    # Path 5: domain fallback
    # ------------------------------------------------------------------
    log.info(
        "resolver path=domain_fallback domain=%s reason=insufficient_kg",
        domain,
    )
    return CompanyIdentity(
        display_name=domain_root_cap,
        canonical_name=domain,
        aliases=[domain_root_cap],
        confidence="low",
        source="domain_fallback",
    )
