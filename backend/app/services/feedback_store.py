"""
Phase 9 (Learning & Platform): persists every AI validation verdict
(Module 4) across scans, so rule effectiveness and dismissal rates can
be computed from real historical data rather than a single scan's
in-memory results.

This is the feature multiple earlier phases already named as the right
home for persistent per-finding state, rather than building it
piecemeal each time:
  - Module 4's original design notes (way back before Phase 1) called
    `dismissed` findings "the seed of a future feedback loop (Module
    5+, not built)".
  - Phase 6 explicitly deferred dismiss/resolve/history because they
    "substantially overlap with Phase 9's 'feedback store'... rather
    than build a persistence layer twice... deferring both to be
    designed together."
  - Phase 8's baseline scanning was explicitly the lightweight,
    no-persistence-needed version of a similar idea, precisely because
    this real version didn't exist yet.

SQLite, not a hosted database: consistent with this project's
established "reach for the simplest thing that works" pattern — no
other datastore exists yet, and a single-file embedded database needs
no separate service, connection string, or infrastructure decision to
adopt.

Known limitation, stated plainly rather than glossed over: Render's
default web service filesystem is ephemeral — a redeploy or restart
can wipe this file, exactly like it would wipe Phase 5's cache. This is
fine for the cache (losing it just means re-paying for AI calls, no
correctness impact) but means feedback/statistics accumulated here
won't survive indefinitely on the current deployment without adding a
persistent disk. Noted here rather than assumed away — see README
"Phase 9" design notes for the tradeoff.
"""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional, Sequence

from app.core.config import BASE_DIR
from app.schemas.feedback import RuleStat, ScanRecord
from app.schemas.findings import ValidatedFinding

DEFAULT_DB_FILE = BASE_DIR / "data" / "feedback.db"

# A rule needs at least this many recorded validations before its
# dismissal rate is considered meaningful enough to flag — a rule
# that's fired exactly once and been dismissed once is a 100%
# dismissal rate on a sample size of 1, which says nothing reliable
# yet. Configurable via env var for the same reason Phase 4's rule
# disabling and Phase 5's fallback model are: a deployment-specific
# tuning knob, not a hardcoded assumption. Read fresh via functions
# rather than captured as module constants at import time — the exact
# bug Phase 5's README documents catching in validator.py's fallback
# model applies identically here, and was caught here the same way:
# by a monkeypatch-based test failing unexpectedly during development.
def _min_sample_size() -> int:
    return int(os.getenv("CODEGUARDIAN_MIN_SAMPLE_SIZE", "5"))


def _dismissal_rate_threshold() -> float:
    return float(os.getenv("CODEGUARDIAN_DISMISSAL_THRESHOLD", "0.5"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS validations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    file TEXT NOT NULL,
    function TEXT,
    severity TEXT NOT NULL,
    verified INTEGER NOT NULL,
    confidence TEXT NOT NULL,
    validated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_validations_rule_id ON validations(rule_id);
CREATE INDEX IF NOT EXISTS idx_validations_repository ON validations(repository);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository TEXT NOT NULL,
    branch TEXT,
    candidate_finding_count INTEGER NOT NULL,
    verified_finding_count INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    scanned_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_repository ON scans(repository);
"""


def _db_file() -> Path:
    """Configurable via env var so tests can point at an isolated temp
    file instead of writing into the real project data directory —
    same pattern as Phase 5's ai/cache.py."""
    override = os.getenv("CODEGUARDIAN_DB_FILE")
    return Path(override) if override else DEFAULT_DB_FILE


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    db_path = _db_file()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_validations(repository: str, validated_findings: Sequence[ValidatedFinding]) -> None:
    """Records every validated finding from a /validate call. Best-effort
    by design: called from the API layer wrapped so a storage failure
    never breaks the response the person is actually waiting on — same
    philosophy as Phase 5's cache, which is explicitly "a performance
    optimization, not a correctness requirement". Feedback recording is
    the same category of thing: valuable, but not something a scan
    should fail over."""
    if not validated_findings:
        return
    now = _now_iso()
    with _connection() as conn:
        conn.executemany(
            """INSERT INTO validations
               (repository, rule_id, file, function, severity, verified, confidence, validated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (repository, f.rule_id, f.file, f.function, f.severity, int(f.verified), f.confidence, now)
                for f in validated_findings
            ],
        )


def record_scan(repository: str, branch: str, candidate_count: int, verified_count: int, risk_score: int) -> None:
    """Same best-effort contract as record_validations — see that
    function's docstring."""
    with _connection() as conn:
        conn.execute(
            """INSERT INTO scans
               (repository, branch, candidate_finding_count, verified_finding_count, risk_score, scanned_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (repository, branch, candidate_count, verified_count, risk_score, _now_iso()),
        )


def get_rule_stats() -> List[RuleStat]:
    """One row per rule_id that has ever been validated at least once,
    with total/verified/dismissed counts and a dismissal rate. A rule
    is flagged `needs_review=True` only once it has enough samples
    (MIN_SAMPLE_SIZE_FOR_REVIEW_FLAG) AND its dismissal rate exceeds
    DISMISSAL_RATE_REVIEW_THRESHOLD — the scoped, honest version of the
    "adaptive confidence" idea named (and explicitly not built) back in
    Module 3's original design notes: this doesn't auto-tune anything,
    it surfaces a signal a person can act on, the same "candidate
    generator, not an autonomous decision-maker" philosophy this whole
    project has used from the start."""
    with _connection() as conn:
        rows = conn.execute(
            """SELECT rule_id,
                      COUNT(*) AS total,
                      SUM(verified) AS verified_count
               FROM validations
               GROUP BY rule_id
               ORDER BY rule_id"""
        ).fetchall()

    stats = []
    for rule_id, total, verified_count in rows:
        verified_count = verified_count or 0
        dismissed_count = total - verified_count
        dismissal_rate = dismissed_count / total if total else 0.0
        stats.append(RuleStat(
            rule_id=rule_id,
            total_validations=total,
            verified_count=verified_count,
            dismissed_count=dismissed_count,
            dismissal_rate=round(dismissal_rate, 4),
            needs_review=(total >= _min_sample_size() and dismissal_rate > _dismissal_rate_threshold()),
        ))
    return stats


def get_scan_history(repository: Optional[str] = None, limit: int = 20) -> List[ScanRecord]:
    """Most recent scans first. Filtered to a single repository if
    given, else across all repositories ever scanned."""
    query = "SELECT repository, branch, candidate_finding_count, verified_finding_count, risk_score, scanned_at FROM scans"
    params: list = []
    if repository:
        query += " WHERE repository = ?"
        params.append(repository)
    query += " ORDER BY scanned_at DESC LIMIT ?"
    params.append(limit)

    with _connection() as conn:
        rows = conn.execute(query, params).fetchall()

    return [
        ScanRecord(
            repository=r[0], branch=r[1], candidate_finding_count=r[2],
            verified_finding_count=r[3], risk_score=r[4], scanned_at=r[5],
        )
        for r in rows
    ]
