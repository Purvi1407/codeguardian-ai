import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Optional

from app.core.config import TEMP_DIR, CLONE_TIMEOUT_SECONDS

GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/[\w.-]+/[\w.-]+/?$"
)


class RepoProcessorError(Exception):
    """Raised for any failure while acquiring/validating a repository."""


def validate_github_url(url: str) -> str:
    """Normalize and validate a GitHub URL. Raises RepoProcessorError if invalid."""
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    if not GITHUB_URL_PATTERN.match(url + "/"):
        raise RepoProcessorError(
            f"'{url}' doesn't look like a public GitHub repo URL "
            "(expected https://github.com/<owner>/<repo>)"
        )
    return url


def clone_repository(github_url: str, branch: Optional[str] = None) -> Path:
    """
    Shallow-clone a public GitHub repo into a unique temp directory.
    Returns the local path to the cloned repo.
    """
    url = validate_github_url(github_url)
    dest = TEMP_DIR / f"scan_{uuid.uuid4().hex[:12]}"

    cmd = ["git", "clone", "--depth", "1", "--single-branch"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [f"{url}.git", str(dest)]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        cleanup_repository(dest)
        raise RepoProcessorError(f"Cloning timed out after {CLONE_TIMEOUT_SECONDS}s")

    if result.returncode != 0:
        cleanup_repository(dest)
        raise RepoProcessorError(f"git clone failed: {result.stderr.strip()[:500]}")

    return dest


def get_default_branch(dest: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def cleanup_repository(dest: Path) -> None:
    """Remove a cloned repo's temp directory. Safe to call even if it doesn't exist."""
    shutil.rmtree(dest, ignore_errors=True)
