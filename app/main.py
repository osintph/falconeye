import os
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.utils.client_ip import get_client_ip_key
from app.routers import crypto, scanner, news, domain_intel, telegram_inspector, ip_intel, sandbox, threat_pulse, email_header, dork_generator, script_decoder
from app.prospect import routes as prospect_routes
from app.image_search import routes as image_routes

limiter = Limiter(key_func=get_client_ip_key)

_show_docs = os.getenv("FALCONEYE_PUBLIC_DOCS", "false").lower() == "true"

app = FastAPI(
    title="FalconEye",
    version="3.5.2",
    openapi_url="/openapi.json" if _show_docs else None,
    docs_url="/api/docs" if _show_docs else None,
    redoc_url=None,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(crypto.router)
app.include_router(scanner.router)
app.include_router(news.router)
app.include_router(domain_intel.router)
app.include_router(telegram_inspector.router)
app.include_router(ip_intel.router)
app.include_router(sandbox.router)
app.include_router(threat_pulse.router)
app.include_router(email_header.router)
app.include_router(dork_generator.router)
app.include_router(script_decoder.router)
app.include_router(prospect_routes.router)
app.include_router(image_routes.router)

app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/health")
async def health():
    return {"status": "ok", "version": "3.5.2"}


@app.get("/")
async def serve_index():
    return FileResponse("app/static/index.html")
