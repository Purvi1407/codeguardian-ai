from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.api.scan import router as scan_router
from app.api.analyze import router as analyze_router
from app.api.validate import router as validate_router

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="CodeGuardian AI",
    description="AI-powered SAST agent — repository processing & parsing service",
    version="0.1.0",
)

# Permissive CORS for local dev against a Next.js frontend on a different port.
# Tighten this before deploying.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(analyze_router)
app.include_router(validate_router)


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

