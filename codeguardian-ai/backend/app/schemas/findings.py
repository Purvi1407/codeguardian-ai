from pydantic import BaseModel, Field
from typing import Optional, List

from app.schemas.scan import FileMetadata


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: str  # "high" | "medium" | "low" — heuristic, pre-AI-validation
    cwe: Optional[str] = None
    file: str
    function: Optional[str] = None
    line: int
    snippet: str
    description: str


class ValidatedFinding(Finding):
    """A Finding after Module 4 AI review. Adds AI judgment on top of the
    rule-based candidate without discarding the original rule metadata —
    so a reviewer can always see both "what the rule flagged" and "what
    the AI concluded"."""
    verified: bool  # did the AI agree this is a real, actionable issue?
    confidence: str  # "high" | "medium" | "low" — AI's confidence in `verified`
    explanation: str  # why this is (or isn't) exploitable, in plain language
    exploit_scenario: str
    patch_suggestion: str
    things_to_verify: List[str] = []


class AnalyzeResponse(BaseModel):
    repository: str
    branch: str
    languages: List[str]
    file_count: int
    finding_count: int
    files: List[FileMetadata]
    findings: List[Finding]


class ValidateResponse(BaseModel):
    repository: str
    branch: str
    languages: List[str]
    file_count: int
    candidate_finding_count: int  # what the rule engine flagged (Module 3)
    verified_finding_count: int   # what the AI actually confirmed (Module 4)
    findings: List[ValidatedFinding]  # verified=True only, sorted by confidence/severity
    dismissed: List[ValidatedFinding]  # verified=False, kept for transparency/debugging

