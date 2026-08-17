from fastapi import APIRouter, HTTPException

from app.schemas.scan import ScanRequest
from app.schemas.findings import ValidateResponse
from app.services.repo_processor import (
    clone_repository, cleanup_repository, get_default_branch, RepoProcessorError,
)
from app.services.scan_service import build_file_metadata_and_findings
from app.services.finding_filters import build_language_lookup, filter_files_by_language, filter_findings
from app.services.dashboard import compute_summary
from app.services import feedback_store
from app.ai.validator import validate_findings, AIValidationError
from app.ai.client import get_client, AIConfigError
from app.core.logging_config import get_logger

logger = get_logger(__name__)
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

    Phase 6: severity_filter / language_filter / rule_filter / search on
    the request are applied to the CANDIDATE findings BEFORE AI
    validation runs, not just to the final response — a finding
    filtered out never costs an API call or a cache write. See README
    "Phase 6" design notes for why that ordering was chosen deliberately.
    """
    try:
        get_client()
    except AIConfigError as e:
        raise HTTPException(status_code=500, detail=str(e))

    try:
        repo_path = clone_repository(request.github_url, request.branch)
    except RepoProcessorError as e:
        logger.warning("validate rejected repository=%s reason=%s", request.github_url, e)
        raise HTTPException(status_code=400, detail=str(e))

    try:
        branch = request.branch or get_default_branch(repo_path)
        files, candidate_findings = build_file_metadata_and_findings(repo_path)
        logger.info("validate candidates repository=%s branch=%s count=%d",
                    request.github_url, branch, len(candidate_findings))

        language_lookup = build_language_lookup(files)
        candidate_findings = filter_findings(
            candidate_findings,
            language_lookup=language_lookup,
            severity=request.severity_filter,
            languages=request.language_filter,
            rules=request.rule_filter,
            search=request.search,
        )
        files = filter_files_by_language(files, request.language_filter)
        languages = sorted({f.language for f in files})

        try:
            validated = validate_findings(candidate_findings)
        except AIValidationError as e:
            logger.error("validate AI failure repository=%s error=%s", request.github_url, e)
            raise HTTPException(status_code=502, detail=str(e))
        except Exception as e:
            # Defense in depth: anything unexpected here still becomes a
            # readable JSON error instead of an opaque 500 with no body.
            # This exact bug happened during testing (an uncaught TypeError
            # from a None API response) — worth keeping this net in place
            # rather than assuming every failure mode has been anticipated.
            logger.exception("validate unexpected AI error repository=%s", request.github_url)
            raise HTTPException(status_code=500, detail=f"Unexpected error during AI validation: {e}")

        verified = [f for f in validated if f.verified]
        dismissed = [f for f in validated if not f.verified]
        logger.info("validate complete repository=%s verified=%d dismissed=%d",
                    request.github_url, len(verified), len(dismissed))

        # Sort verified findings so the highest-confidence, highest-severity
        # issues are first — this ordering IS the product philosophy made
        # visible in the API response, not just an implementation detail.
        severity_rank = {"high": 0, "medium": 1, "low": 2}
        confidence_rank = {"high": 0, "medium": 1, "low": 2}
        verified.sort(key=lambda f: (severity_rank.get(f.severity, 3),
                                      confidence_rank.get(f.confidence, 3)))

        repository = request.github_url.rstrip("/")
        summary = compute_summary(verified)

        # Phase 9: record this scan's verdicts for rule-effectiveness
        # stats and scan history. Best-effort by design (see
        # feedback_store.py's module docstring) — wrapped so a storage
        # problem (e.g. a read-only filesystem) degrades to "this scan's
        # feedback wasn't recorded" rather than failing a request that
        # otherwise completed successfully and that the person is
        # actively waiting on. Now (Phase 10) logged rather than silently
        # swallowed, so a persistent storage problem is at least visible
        # in the logs instead of invisible forever.
        try:
            feedback_store.record_validations(repository, validated)
            feedback_store.record_scan(
                repository, branch,
                candidate_count=len(candidate_findings),
                verified_count=len(verified),
                risk_score=summary.risk_score,
            )
        except Exception:
            logger.warning("feedback store recording failed repository=%s", repository, exc_info=True)

        return ValidateResponse(
            repository=repository,
            branch=branch,
            languages=languages,
            file_count=len(files),
            candidate_finding_count=len(candidate_findings),
            verified_finding_count=len(verified),
            findings=verified,
            dismissed=dismissed,
            summary=summary,
        )
    finally:
        cleanup_repository(repo_path)
