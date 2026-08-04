from fastapi import APIRouter, HTTPException

from app.schemas.scan import ScanRequest
from app.schemas.findings import ValidateResponse
from app.services.repo_processor import (
    clone_repository, cleanup_repository, get_default_branch, RepoProcessorError,
)
from app.services.scan_service import build_file_metadata_and_findings
from app.ai.validator import validate_findings, AIValidationError
from app.ai.client import get_client, AIConfigError

router = APIRouter()


@router.post("/validate", response_model=ValidateResponse)
def validate_repository(request: ScanRequest):
    """
    Full pipeline: clone -> parse (Module 1+2) -> rule-based candidates
    (Module 3) -> AI validation (Module 4). This is the actual product:
    everything before this endpoint produces noisy candidates; this is
    where "fewer, higher-confidence findings" actually happens.

    Fails fast on missing OPENAI_API_KEY, before cloning anything —
    no point spending clone/parse time if we can't finish the pipeline.
    """
    try:
        get_client()
    except AIConfigError as e:
        raise HTTPException(status_code=500, detail=str(e))

    try:
        repo_path = clone_repository(request.github_url, request.branch)
    except RepoProcessorError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        branch = request.branch or get_default_branch(repo_path)
        files, candidate_findings = build_file_metadata_and_findings(repo_path)
        languages = sorted({f.language for f in files})

        try:
            validated = validate_findings(candidate_findings)
        except AIValidationError as e:
            raise HTTPException(status_code=502, detail=str(e))
        except Exception as e:
            # Defense in depth: anything unexpected here still becomes a
            # readable JSON error instead of an opaque 500 with no body.
            # This exact bug happened during testing (an uncaught TypeError
            # from a None API response) — worth keeping this net in place
            # rather than assuming every failure mode has been anticipated.
            raise HTTPException(status_code=500, detail=f"Unexpected error during AI validation: {e}")

        verified = [f for f in validated if f.verified]
        dismissed = [f for f in validated if not f.verified]

        # Sort verified findings so the highest-confidence, highest-severity
        # issues are first — this ordering IS the product philosophy made
        # visible in the API response, not just an implementation detail.
        severity_rank = {"high": 0, "medium": 1, "low": 2}
        confidence_rank = {"high": 0, "medium": 1, "low": 2}
        verified.sort(key=lambda f: (severity_rank.get(f.severity, 3),
                                      confidence_rank.get(f.confidence, 3)))

        return ValidateResponse(
            repository=request.github_url.rstrip("/"),
            branch=branch,
            languages=languages,
            file_count=len(files),
            candidate_finding_count=len(candidate_findings),
            verified_finding_count=len(verified),
            findings=verified,
            dismissed=dismissed,
        )
    finally:
        cleanup_repository(repo_path)
