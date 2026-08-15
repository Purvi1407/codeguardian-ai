"""
Phase 8 (CI/CD & Integration): baseline scanning. Lets a team adopt this
tool on an EXISTING codebase without being immediately overwhelmed by
every pre-existing finding — generate a baseline once, and future runs
only report NEW findings not already in it.

This is deliberately a simpler mechanism than the persistent
dismiss/resolve/history feature deferred back in Phase 6: a baseline is
a single generate-then-compare snapshot a team commits to their repo
(e.g. `.codeguardian-baseline.json`), not a running state store with
its own API and database — no server-side persistence at all, which is
exactly why this was achievable without revisiting the Phase 6/9
persistence-layer decision.
"""
import hashlib
import json
from pathlib import Path
from typing import List, Sequence, Set, TypeVar

from app.schemas.findings import Finding

FindingT = TypeVar("FindingT", bound=Finding)

BASELINE_FORMAT_VERSION = 1


def fingerprint(finding: Finding) -> str:
    """A stable identifier for "this specific finding", deliberately
    NOT including `line` — the same reasoning as Phase 5's AI-validation
    cache key and Phase 6's README notes on why finding identity can't
    be line-based: line numbers shift on nearly every unrelated edit,
    and a baseline that stops matching after someone adds a blank line
    above the flagged code would be actively hostile to adopt. Keyed on
    rule_id + file + function + snippet instead — stable across
    unrelated edits elsewhere in the file, while still being specific
    enough that two different vulnerabilities in the same function
    don't collide."""
    raw = f"{finding.rule_id}:{finding.file}:{finding.function or ''}:{finding.snippet}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_baseline(findings: Sequence[Finding]) -> dict:
    return {
        "format_version": BASELINE_FORMAT_VERSION,
        "fingerprints": sorted({fingerprint(f) for f in findings}),
    }


def write_baseline(findings: Sequence[Finding], path: Path) -> None:
    path.write_text(json.dumps(build_baseline(findings), indent=2) + "\n", encoding="utf-8")


def load_baseline_fingerprints(path: Path) -> Set[str]:
    """Returns an empty set (not an error) for a missing or malformed
    baseline file — a baseline is an opt-in convenience, and a broken
    or absent one should degrade to "no baseline" (report everything),
    not break the scan entirely. A team that genuinely wants to enforce
    the baseline file's presence can check for that in their own CI step
    before invoking the scanner."""
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set()
    if not isinstance(data, dict):
        return set()
    fingerprints = data.get("fingerprints")
    if not isinstance(fingerprints, list):
        return set()
    return {fp for fp in fingerprints if isinstance(fp, str)}


def filter_new_findings(findings: Sequence[FindingT], baseline_path: Path) -> List[FindingT]:
    """Returns only the findings NOT already present in the baseline
    file at `baseline_path`. If the file doesn't exist, returns every
    finding unchanged (equivalent to no baseline being configured)."""
    known = load_baseline_fingerprints(baseline_path)
    if not known:
        return list(findings)
    return [f for f in findings if fingerprint(f) not in known]
