import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
TEMP_DIR = BASE_DIR / "temp"
UPLOADS_DIR = BASE_DIR / "uploads"

TEMP_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

# Safety limits for the MVP so a huge repo can't hang the API
MAX_REPO_SIZE_MB = int(os.getenv("MAX_REPO_SIZE_MB", "200"))
CLONE_TIMEOUT_SECONDS = int(os.getenv("CLONE_TIMEOUT_SECONDS", "60"))

SUPPORTED_EXTENSIONS = {
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
}

# Directories we never want to walk into
IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".next", "site-packages", "migrations",
}
