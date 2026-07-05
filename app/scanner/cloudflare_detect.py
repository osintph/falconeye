"""
Cloudflare challenge / bot-protection page detection.
A Cloudflare challenge page is a real signal for phishing analysts: legitimate
sites rarely challenge OSINT tooling this aggressively, but phishing infra
behind Cloudflare Tunnel or Workers routinely does to prevent automated takedown.

Returns a synthetic indicator dict (same shape as INDICATORS / PH_BANK_INDICATORS)
when the fetched HTML looks like a Cloudflare challenge, or None if it doesn't.
"""

_CF_TITLE_SIGNALS = [
    "attention required! | cloudflare",
    "just a moment",
    "checking your browser",
    "please wait | cloudflare",
]

_CF_BODY_SIGNALS = [
    "sorry, you have been blocked",
    "cf-browser-verification",
    "cf-error-details",
    "enable javascript and cookies to continue",
    "cloudflare ray id",
]

_CF_INDICATOR = {
    "id": "cloudflare_bot_protection",
    "type": "infrastructure",
    "pattern": "(cloudflare challenge page)",
    "severity": "medium",
    "description": (
        "Target is behind Cloudflare bot protection; live rendering required for full "
        "analysis. Phishing infra behind Cloudflare Tunnel/Workers commonly blocks "
        "automated scanners — this is a meaningful signal, not a benign 403."
    ),
    "category": "infrastructure",
}


from typing import Optional


def detect_cloudflare_challenge(html: str) -> Optional[dict]:
    """
    Returns the cloudflare_bot_protection indicator dict if the HTML looks like
    a Cloudflare challenge page, or None if it does not.
    """
    html_lower = html.lower()
    for signal in _CF_TITLE_SIGNALS:
        if signal in html_lower:
            return _CF_INDICATOR
    for signal in _CF_BODY_SIGNALS:
        if signal in html_lower:
            return _CF_INDICATOR
    return None
