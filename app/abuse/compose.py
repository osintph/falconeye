"""
Abuse report composition.

Renders a plain-text abuse report from a category-appropriate title and a
shared body template, prefilled with evidence the operator provides. Every
input is sanitized against email-header injection here, in the composition
layer, before it can ever reach the Mailgun send layer.

All templates share one body shape (only the category title changes), so the
"one file per category" idea in the original plan collapses to a single
template plus a category->title map — DRY, and easy to reword in one place.

compose_report() never raises.
"""

# category key -> human title used in the subject line and body
CATEGORY_TITLES = {
    "phishing": "Phishing / Credential Harvesting",
    "spam": "Unsolicited Bulk Email (Spam)",
    "bec": "Business Email Compromise",
    "malware": "Malware Distribution / C2",
    "bruteforce": "Brute-Force Login Attempts",
    "scanning": "Port / Vulnerability Scanning",
    "ddos": "DDoS Participation",
    "crypto_fraud": "Cryptocurrency Fraud Infrastructure",
    "other": "Abusive Activity",
}

VALID_CATEGORIES = tuple(CATEGORY_TITLES.keys())

MAX_EVIDENCE_CHARS = 8000
MAX_TARGET_CHARS = 255

BODY_TEMPLATE = """To Whom It May Concern,

I am reporting abusive activity originating from infrastructure under
your administration. Details below.

Target: {target}
Target type: {target_type}
Activity category: {category_title}
Observed at (UTC): {observed_at_utc}

Evidence:

{evidence_text}

I am reporting this in good faith as an independent OSINT investigator.
Please take appropriate action per your abuse policy and reply to this
email if you require additional information.

Regards,
{reporter_name}
{reporter_email}
"""


def _strip_single_line(value) -> tuple[str, bool]:
    """Remove CR / LF / NUL from a single-line field.

    Returns (cleaned, changed) where `changed` is True if any of those
    characters were present (i.e. an injection attempt was neutralized).
    Surrounding whitespace is trimmed but does not count as a change.
    """
    original = "" if value is None else str(value)
    stripped = original.replace("\r", "").replace("\n", "").replace("\x00", "")
    changed = stripped != original
    return stripped.strip(), changed


def _sanitize_evidence(value) -> tuple[str, bool, bool]:
    """Normalize a multi-line evidence field.

    CRLF and lone CR are folded to LF, NUL is removed, and the result is capped
    at MAX_EVIDENCE_CHARS. Returns (cleaned, changed, truncated).
    """
    original = "" if value is None else str(value)
    cleaned = original.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    changed = cleaned != original
    truncated = False
    if len(cleaned) > MAX_EVIDENCE_CHARS:
        cleaned = cleaned[:MAX_EVIDENCE_CHARS]
        truncated = True
    return cleaned, changed, truncated


def compose_report(
    target: str,
    target_type: str,
    category: str,
    evidence_text: str,
    observed_at_utc: str,
    reporter_name: str,
    reporter_email: str,
) -> dict:
    """Render an abuse report. Never raises; sanitizes all inputs."""
    warnings: list[str] = []

    clean_target, changed = _strip_single_line(target)
    if changed:
        warnings.append("target contained CR/LF or NUL characters; they were stripped")
    if len(clean_target) > MAX_TARGET_CHARS:
        clean_target = clean_target[:MAX_TARGET_CHARS]
        warnings.append(f"target truncated to {MAX_TARGET_CHARS} characters")

    clean_type, _ = _strip_single_line(target_type)
    clean_type = clean_type.lower() or "unspecified"

    clean_category, _ = _strip_single_line(category)
    clean_category = clean_category.lower()
    if clean_category not in CATEGORY_TITLES:
        if clean_category:
            warnings.append(f"unknown category '{clean_category}'; treated as 'other'")
        clean_category = "other"

    clean_name, changed = _strip_single_line(reporter_name)
    if changed:
        warnings.append("reporter_name contained CR/LF or NUL characters; they were stripped")

    clean_email, changed = _strip_single_line(reporter_email)
    if changed:
        warnings.append("reporter_email contained CR/LF or NUL characters; they were stripped")

    clean_observed, changed = _strip_single_line(observed_at_utc)
    if changed:
        warnings.append("observed_at_utc contained CR/LF or NUL characters; they were stripped")

    clean_evidence, ev_changed, ev_truncated = _sanitize_evidence(evidence_text)
    if ev_changed:
        warnings.append("evidence contained CR or NUL characters; line endings normalized")
    if ev_truncated:
        warnings.append(f"evidence truncated to {MAX_EVIDENCE_CHARS} characters")

    category_title = CATEGORY_TITLES[clean_category]

    subject = f"Abuse Report: {category_title} from {clean_target or '(unspecified target)'}"

    # NOTE: str.format substitutes values literally — braces inside the
    # substituted values are NOT re-interpreted — so untrusted evidence
    # containing { } cannot break rendering.
    body_text = BODY_TEMPLATE.format(
        target=clean_target or "(unspecified)",
        target_type=clean_type,
        category_title=category_title,
        observed_at_utc=clean_observed or "(not specified)",
        evidence_text=clean_evidence or "(no evidence provided)",
        reporter_name=clean_name or "(reporter name not set)",
        reporter_email=clean_email or "(reporter email not set)",
    )

    return {
        "subject": subject,
        "body_text": body_text,
        "reporter_name": clean_name,
        "reporter_email": clean_email,
        "category": clean_category,
        "category_title": category_title,
        "target": clean_target,
        "target_type": clean_type,
        "warnings": warnings,
    }
