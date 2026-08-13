from fastapi import APIRouter, HTTPException

from app.schemas.scan import ScanRequest, ScanResponse
from app.services.repo_processor import (
    clone_repository, cleanup_repository, get_default_branch, RepoProcessorError,
)
from app.services.scan_service import build_file_metadata
from app.services.finding_filters import filter_files_by_language

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
def scan_repository(request: ScanRequest):
    """
    Clone a public GitHub repo, discover Python/TS/JS files, and parse each
    into functions/classes with line numbers. This is Module 1 + Module 2
    of the pipeline (Repository Processor + Parser) — no vulnerability
    detection yet, that's Module 3.

    `language_filter` (Phase 6) is the only filter field relevant here —
    severity/rule/search filters apply to findings, which this endpoint
    doesn't produce.
    """
    try:
        repo_path = clone_repository(request.github_url, request.branch)
    except RepoProcessorError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        branch = request.branch or get_default_branch(repo_path)
        files = build_file_metadata(repo_path)
        files = filter_files_by_language(files, request.language_filter)
        languages = sorted({f.language for f in files})

        return ScanResponse(
            repository=request.github_url.rstrip("/"),
            branch=branch,
            languages=languages,
            file_count=len(files),
            files=files,
        )
    finally:
        # MVP: always clean up the clone after parsing. Once we add caching
        # for multi-stage analysis (Module 3/4 reusing the same clone), this
        # will move to a TTL-based cleanup instead.
        cleanup_repository(repo_path)
