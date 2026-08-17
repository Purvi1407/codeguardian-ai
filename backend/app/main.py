import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.api.scan import router as scan_router
from app.api.analyze import router as analyze_router
from app.api.validate import router as validate_router
from app.api.stats import router as stats_router
from app.core.logging_config import setup_logging
from app.core.rate_limit import RateLimitMiddleware

setup_logging()

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="CodeGuardian AI",
    description="AI-powered SAST agent — repository processing & parsing service",
    version="0.1.0",
)

# Phase 10: CORS is now configurable via CODEGUARDIAN_CORS_ORIGINS
# (comma-separated), rather than permanently wide open. Defaults to "*"
# to preserve existing behavior for anyone already running this without
# setting it — this app's own browser UI (app/static/index.html) is
# served from the SAME origin as the API, so it never actually needed
# CORS at all; "*" only matters for a separate frontend calling this
# API cross-origin, which is exactly the case where it should be
# restricted to known origins in a real deployment. The comment this
# replaced ("Tighten this before deploying") sat unaddressed since the
# very first version of this file — fixed here, not just re-flagged.
_cors_origins_raw = os.getenv("CODEGUARDIAN_CORS_ORIGINS", "*")
CORS_ORIGINS = ["*"] if _cors_origins_raw == "*" else [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RateLimitMiddleware)

app.include_router(scan_router)
app.include_router(analyze_router)
app.include_router(validate_router)
app.include_router(stats_router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def serve_ui():
    """
    Serves the browser UI. Registered as a plain GET route (not a
    StaticFiles mount) specifically so it can't ever shadow the API
    routes above — those are matched first regardless of registration
    order, but keeping this explicit avoids any ambiguity about it.
    """
    return FileResponse(STATIC_DIR / "index.html")

