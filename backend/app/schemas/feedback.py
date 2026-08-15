from typing import List, Optional

from pydantic import BaseModel


class RuleStat(BaseModel):
    """Aggregate AI-validation history for a single rule_id, across
    every scan that's ever recorded a verdict for it. See
    services/feedback_store.py for how this is computed."""
    rule_id: str
    total_validations: int
    verified_count: int
    dismissed_count: int
    dismissal_rate: float  # 0.0-1.0
    needs_review: bool  # dismissal_rate exceeds threshold AND sample size is large enough to trust it


class RuleStatsResponse(BaseModel):
    rules: List[RuleStat]


class ScanRecord(BaseModel):
    """One past /validate run, as recorded in the feedback store."""
    repository: str
    branch: Optional[str] = None
    candidate_finding_count: int
    verified_finding_count: int
    risk_score: int
    scanned_at: str  # ISO 8601 UTC timestamp


class ScanHistoryResponse(BaseModel):
    scans: List[ScanRecord]
