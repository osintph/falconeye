from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from app.utils.ratelimit import limiter
from app.routers import scanner, scamtext, feeds

app = FastAPI(title="FalconEye", version="2.0.0", docs_url="/api/docs", redoc_url=None)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(scanner.router)
app.include_router(scamtext.router)
app.include_router(feeds.router)

app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/")
async def serve_index():
    return FileResponse("app/static/index.html")


@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0"}
