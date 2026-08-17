import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Optional

from app.core.config import TEMP_DIR, CLONE_TIMEOUT_SECONDS, MAX_REPO_SIZE_MB
from app.core.logging_config import get_logger

logger = get_logger(__name__)

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


def _directory_size_mb(path: Path) -> float:
    """Total size of everything under `path`, in MB. Walks the whole
    tree — for a freshly-cloned, shallow (--depth 1) repo this is just
    the working tree plus a thin .git, so it's cheap relative to the
    clone itself."""
    total_bytes = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    return total_bytes / (1024 * 1024)


def clone_repository(github_url: str, branch: Optional[str] = None) -> Path:
    """
    Shallow-clone a public GitHub repo into a unique temp directory.
    Returns the local path to the cloned repo.

    Enforces MAX_REPO_SIZE_MB (Phase 10, item 83) — checked AFTER the
    clone completes, not before, since there's no reliable way to know
    a repo's checked-out size without actually fetching it (GitHub's
    API-reported repo size is compressed and doesn't account for
    --depth 1's history truncation). This means an oversized repo still
    costs the clone time/bandwidth before being rejected — a real
    limitation, not a silent gap: see README "Phase 10" design notes
    for why a pre-clone check isn't feasible here, and cleanup always
    happens regardless of which check (timeout, clone failure, size)
    is what ultimately rejects it.
    """
    url = validate_github_url(github_url)
    dest = TEMP_DIR / f"scan_{uuid.uuid4().hex[:12]}"
    logger.info("clone start repository=%s branch=%s dest=%s", url, branch or "(default)", dest.name)

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
        logger.warning("clone timeout repository=%s after=%ss", url, CLONE_TIMEOUT_SECONDS)
        cleanup_repository(dest)
        raise RepoProcessorError(f"Cloning timed out after {CLONE_TIMEOUT_SECONDS}s")

    if result.returncode != 0:
        logger.warning("clone failed repository=%s returncode=%s", url, result.returncode)
        cleanup_repository(dest)
        raise RepoProcessorError(f"git clone failed: {result.stderr.strip()[:500]}")

    size_mb = _directory_size_mb(dest)
    if size_mb > MAX_REPO_SIZE_MB:
        logger.warning("clone rejected repository=%s size_mb=%.1f limit_mb=%s", url, size_mb, MAX_REPO_SIZE_MB)
        cleanup_repository(dest)
        raise RepoProcessorError(
            f"Repository is {size_mb:.0f} MB, which exceeds the {MAX_REPO_SIZE_MB} MB limit "
            f"(set via MAX_REPO_SIZE_MB). Try a smaller repo or branch, or raise the limit "
            f"if you're running this yourself."
        )

    logger.info("clone success repository=%s size_mb=%.1f", url, size_mb)
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
