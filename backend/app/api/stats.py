from typing import Optional

from fastapi import APIRouter, Query

from app.schemas.feedback import RuleStatsResponse, ScanHistoryResponse
from app.services import feedback_store

router = APIRouter()


@router.get("/stats/rules", response_model=RuleStatsResponse)
def rule_stats():
    """
    Phase 9: aggregate AI-validation history per rule, across every
    /validate call ever recorded (see app/services/feedback_store.py).

    `needs_review=True` flags a rule whose dismissal rate is high enough,
    over enough samples, to be worth a human looking at — this is a
    signal, not an automatic action. Nothing in this project auto-tunes
    or auto-disables a rule based on this; a person decides what to do
    with it (e.g. tightening the rule, or adding it to
    CODEGUARDIAN_DISABLED_RULES from Phase 4 if it's just not pulling
    its weight).
    """
    return RuleStatsResponse(rules=feedback_store.get_rule_stats())


@router.get("/stats/scans", response_model=ScanHistoryResponse)
def scan_history(
    repository: Optional[str] = Query(default=None, description="Filter to a single repository, e.g. 'https://github.com/org/repo'"),
    limit: int = Query(default=20, ge=1, le=200, description="Max number of scans to return, most recent first"),
):
    """Phase 9: past /validate runs recorded in the feedback store,
    most recent first. Powers historical trend views (e.g. "is this
    repo's risk score trending up or down over time")."""
    return ScanHistoryResponse(scans=feedback_store.get_scan_history(repository=repository, limit=limit))
