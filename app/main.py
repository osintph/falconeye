import json
import logging
import os
from html import escape
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse, RedirectResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app import config
from app.utils.client_ip import get_client_ip_key
from app.routers import crypto, scanner, news, domain_intel, ip_intel, sandbox, threat_pulse, email_header, dork_generator, script_decoder, url_expander, qr_analyzer, sockpuppet
from app.prospect import routes as prospect_routes
from app.image_search import routes as image_routes
from app.abuse import routes as abuse_routes
from app.username import routes as username_routes
from app.telegram import routes as telegram_routes
from app.breach import routes as breach_routes
from app.ransomware import routes as ransomware_routes
from app.prospect.client import SearchAPINotConfigured
from app.image_search.upload import ImageUploadNotConfigured

log = logging.getLogger("falconeye")

limiter = Limiter(key_func=get_client_ip_key)

_show_docs = os.getenv("FALCONEYE_PUBLIC_DOCS", "false").lower() == "true"

app = FastAPI(
    title="FalconEye",
    version="3.33.1",
    openapi_url="/openapi.json" if _show_docs else None,
    docs_url="/api/docs" if _show_docs else None,
    redoc_url=None,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Starlette's own fallback is a PlainTextResponse, which breaks callers the
    # same way an HTML error page does: every client on this API expects JSON.
    log.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


async def _not_configured_handler(request: Request, exc: Exception) -> JSONResponse:
    # A required API key (SEARCHAPI_KEY / IMAGE_UPLOAD_SECRET) is unset. Convert the
    # deep-raised NotConfigured exception into a clean 503 instead of a 500, and,
    # unlike a route-level pre-check, this never fires when the service layer is
    # mocked in tests, only when a real client construction is actually attempted.
    log.warning("Feature not configured on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(status_code=503, content={"detail": "This feature is not configured on the server."})


app.add_exception_handler(SearchAPINotConfigured, _not_configured_handler)
app.add_exception_handler(ImageUploadNotConfigured, _not_configured_handler)

app.include_router(crypto.router)
app.include_router(scanner.router)
app.include_router(news.router)
app.include_router(domain_intel.router)
app.include_router(telegram_routes.router)
app.include_router(ip_intel.router)
app.include_router(sandbox.router)
app.include_router(threat_pulse.router)
app.include_router(email_header.router)
app.include_router(dork_generator.router)
app.include_router(script_decoder.router)
app.include_router(url_expander.router)
app.include_router(qr_analyzer.router)
app.include_router(sockpuppet.router)
app.include_router(prospect_routes.router)
app.include_router(image_routes.router)
app.include_router(abuse_routes.router)
app.include_router(username_routes.router)
app.include_router(breach_routes.router)
app.include_router(ransomware_routes.router)

app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/health")
async def health():
    return {"status": "ok", "version": "3.33.1"}


# Operator identity is substituted into the page server-side rather than patched
# in by JavaScript, because half of it is <meta> and JSON-LD that a crawler reads
# without running scripts. A self-hoster who sets OPERATOR_* must not still be
# advertising the upstream operator's name and inbox in the page source.
#
# Every default equals the public instance's current value, so an existing
# deployment that sets none of these renders byte-for-byte what it did before.
def _bare_host(url: str) -> str:
    """A URL as link text: scheme and trailing slash removed.

    Matches how the public instance renders these today ("blog.osintph.info",
    not "https://blog.osintph.info").
    """
    return url.split("://", 1)[-1].rstrip("/")


_CONTACT_PANEL_START = "<!--CONTACT_PANEL_START-->"
_CONTACT_PANEL_END = "<!--CONTACT_PANEL_END-->"


def _operator_tokens() -> dict:
    """Plain-text substitutions, HTML-escaped on the way in.

    Read from config on every call rather than frozen at import so the tests can
    exercise a self-hoster's settings without reloading the module. Config
    itself is still import-time, so this costs a small dict per request.
    """
    return {
        "{{OPERATOR_NAME}}": config.OPERATOR_NAME,
        "{{OPERATOR_URL}}": config.OPERATOR_URL,
        "{{OPERATOR_URL_LABEL}}": _bare_host(config.OPERATOR_URL),
        "{{OPERATOR_CONTACT_EMAIL}}": config.OPERATOR_CONTACT_EMAIL,
        "{{OPERATOR_PRIVACY_EMAIL}}": config.OPERATOR_PRIVACY_EMAIL,
        "{{SITE_ORIGIN}}": config.OPERATOR_SITE_ORIGIN,
        # The bare hostname, for the privacy policy's "the live instance at
        # <host>" and the contact form's _source, where a scheme would read wrong.
        "{{SITE_HOST}}": _bare_host(config.OPERATOR_SITE_ORIGIN),
        "{{CONTACT_FORM_ACTION}}": config.CONTACT_FORM_ACTION,
        # Rendered as ", <tagline>" so an operator who clears it gets a clean
        # full stop after their name instead of a dangling comma.
        "{{OPERATOR_TAGLINE_CLAUSE}}": (
            f", {config.OPERATOR_TAGLINE}" if config.OPERATOR_TAGLINE else ""),
    }


def _footer_contact() -> str:
    """The footer's Contact link, which belongs to the Contact tab.

    Hiding the tab hides this too, otherwise "hide the contact page" still
    publishes the operator's inbox at the bottom of every page.
    """
    if not (config.CONTACT_ENABLED and config.OPERATOR_CONTACT_EMAIL):
        return ""
    email = escape(config.OPERATOR_CONTACT_EMAIL, quote=True)
    return (f'\u00b7 <a href="mailto:{email}" '
            'class="hover:text-amber-400 transition">Contact</a>')


def _sameas_json() -> str:
    """JSON-LD sameAs. Its quotes must NOT be HTML-escaped: it sits inside
    <script type="application/ld+json">."""
    return json.dumps([u for u in (config.OPERATOR_PROFILE_URL, config.OPERATOR_URL) if u])


def _operator_config_script() -> str:
    """The subset of operator config the frontend needs, as one inline script.

    Only what the page actually renders. It is public information on a public
    page, but it is still built from an explicit dict rather than dumping the
    config module.
    """
    payload = {
        "operatorName": config.OPERATOR_NAME,
        "operatorUrl": config.OPERATOR_URL,
        "contactEmail": config.OPERATOR_CONTACT_EMAIL,
        "privacyEmail": config.OPERATOR_PRIVACY_EMAIL,
        "siteOrigin": config.OPERATOR_SITE_ORIGIN,
        "contactEnabled": config.CONTACT_ENABLED,
    }
    # </script> inside a JSON string would end the block early.
    blob = json.dumps(payload).replace("<", "\\u003c")
    return f'<script>window.FALCONEYE_CONFIG = {blob};</script>'


def render_index(html: str) -> str:
    """Apply every server-side substitution to the index page.

    Separated from the route so the tests can exercise it without a client.
    """
    html = html.replace("<!--SP_COUNTRY_OPTIONS-->", sockpuppet.COUNTRY_OPTIONS_HTML)
    html = html.replace("<!--OPERATOR_CONFIG-->", _operator_config_script())

    # Strip the Contact panel entirely when it is off. Hiding it with CSS or
    # skipping the nav entry would still ship the operator's address in the page
    # source, which is the thing a self-hoster is trying not to publish.
    if not config.CONTACT_ENABLED:
        start = html.find(_CONTACT_PANEL_START)
        end = html.find(_CONTACT_PANEL_END)
        if start != -1 and end != -1 and end > start:
            html = html[:start] + html[end + len(_CONTACT_PANEL_END):]

    # Already-escaped markup and raw JSON, so both go in before the plain-text
    # tokens that do get HTML-escaped.
    html = html.replace("{{FOOTER_CONTACT}}", _footer_contact())
    html = html.replace("{{OPERATOR_SAMEAS}}", _sameas_json())

    for token, value in _operator_tokens().items():
        html = html.replace(token, escape(value, quote=True))
    return html


@app.get("/")
async def serve_index():
    # Read fresh each request (static edits need no restart) and inject the full
    # ISO country <option> list server-side, so the Sock Puppet country picker is
    # in the served HTML and does not depend on a client-side fetch.
    with open("app/static/index.html", encoding="utf-8") as f:
        html = f.read()
    return HTMLResponse(render_index(html))


@app.get("/contact")
async def contact_route():
    """A real route for the Contact tab, so hiding it can return a real 404.

    The tab itself is client-side (#contact), so this exists to give the deep
    link and any crawler an honest answer. Enabled: redirect to the tab.
    Disabled: 404, not an empty page and not a redirect to a tab that is no
    longer there.
    """
    if not config.CONTACT_ENABLED:
        raise HTTPException(status_code=404, detail="Not Found")
    return RedirectResponse(url="/#contact", status_code=302)
