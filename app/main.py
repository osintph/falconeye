import logging
import os
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
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
    version="3.26.3",
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
    # deep-raised NotConfigured exception into a clean 503 instead of a 500 — and,
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
    return {"status": "ok", "version": "3.26.3"}


@app.get("/")
async def serve_index():
    # Read fresh each request (static edits need no restart) and inject the full
    # ISO country <option> list server-side, so the Sock Puppet country picker is
    # in the served HTML and does not depend on a client-side fetch.
    with open("app/static/index.html", encoding="utf-8") as f:
        html = f.read()
    html = html.replace("<!--SP_COUNTRY_OPTIONS-->", sockpuppet.COUNTRY_OPTIONS_HTML)
    return HTMLResponse(html)
