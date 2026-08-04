from fastapi import APIRouter, HTTPException

from app.schemas.scan import ScanRequest
from app.schemas.findings import AnalyzeResponse
from app.services.repo_processor import (
    clone_repository, cleanup_repository, get_default_branch, RepoProcessorError,
)
from app.services.scan_service import build_file_metadata_and_findings

router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_repository(request: ScanRequest):
    """
    Full Module 1 + 2 + 3 pipeline: clone the repo, parse every supported
    file, and run rule-based security checks against every Python file.

    Findings here are CANDIDATES, not confirmed vulnerabilities — this
    endpoint does no taint tracking and doesn't know whether a flagged
    value actually originates from user input. Module 4 (AI validation)
    is what turns these into the "fewer, higher-confidence" findings the
    product is actually meant to deliver.
    """
    try:
        repo_path = clone_repository(request.github_url, request.branch)
    except RepoProcessorError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        branch = request.branch or get_default_branch(repo_path)
        files, findings = build_file_metadata_and_findings(repo_path)
        languages = sorted({f.language for f in files})

        return AnalyzeResponse(
            repository=request.github_url.rstrip("/"),
            branch=branch,
            languages=languages,
            file_count=len(files),
            finding_count=len(findings),
            files=files,
            findings=findings,
        )
    finally:
        cleanup_repository(repo_path)
