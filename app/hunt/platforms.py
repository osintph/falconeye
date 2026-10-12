"""Hosting-platform suffixes whose subdomains anyone can create for free, so a
brand-in-subdomain phishing page (bdo-online-update-account.pages.dev) lives
here, not on a registered lookalike domain. For these the registrable name is the
platform subdomain (PSL private section), there is no per-name RDAP registration
date (the platform owns the apex), and the abuse report goes to the platform's
own channel. Maintained table. No em dashes in this module.
"""
from __future__ import annotations

from app.scanner.scope import registrable

# Platform suffix -> abuse channel. The suffix is matched against the PSL-private
# registrable of a host (foo.pages.dev -> pages.dev). Kept small and specific.
PLATFORM_ABUSE = {
    "pages.dev": "abuse@cloudflare.com",
    "workers.dev": "abuse@cloudflare.com",
    "r2.dev": "abuse@cloudflare.com",
    "vercel.app": "abuse@vercel.com",
    "netlify.app": "abuse@netlify.com",
    "netlify.com": "abuse@netlify.com",
    "github.io": "abuse@github.com",
    "web.app": "https://support.google.com/code/contact/cloud_platform_report",
    "firebaseapp.com": "https://support.google.com/code/contact/cloud_platform_report",
    "blogspot.com": "https://support.google.com/blogger/answer/76315",
    "glitch.me": "abuse@glitch.com",
    "onrender.com": "abuse@render.com",
    "fly.dev": "abuse@fly.io",
    "surge.sh": "abuse@surge.sh",
    "weebly.com": "abuse@weebly.com",
    "wixsite.com": "abuse@wix.com",
    "herokuapp.com": "abuse@heroku.com",
    "repl.co": "abuse@replit.com",
    "replit.app": "abuse@replit.com",
    "azurewebsites.net": "https://msrc.microsoft.com/report/abuse",
    "amplifyapp.com": "abuse@amazonaws.com",
}


def platform_suffix(host: str) -> str | None:
    """The platform suffix a host sits under (pages.dev for x.pages.dev), or None.
    A host that IS the platform apex returns None: the apex is the platform, not a
    candidate."""
    if not host:
        return None
    reg = registrable(host, private=True)
    suffix = reg.split(".", 1)[1] if "." in reg else ""
    if suffix in PLATFORM_ABUSE and reg != suffix:
        return suffix
    return None


def platform_abuse(host: str) -> str | None:
    suffix = platform_suffix(host)
    return PLATFORM_ABUSE.get(suffix) if suffix else None
