from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from app.routers import crypto, scanner, news, domain_intel, telegram_inspector

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="FalconEye", version="3.0.0", docs_url="/api/docs", redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(crypto.router)
app.include_router(scanner.router)
app.include_router(news.router)
app.include_router(domain_intel.router)
app.include_router(telegram_inspector.router)

app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/health")
async def health():
    return {"status": "ok", "version": "3.0.0"}


@app.get("/")
async def serve_index():
    return FileResponse("app/static/index.html")
