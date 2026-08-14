"""
Phase 7 (Dashboard & UX): computes a summary object — a risk score and
severity/rule distributions — from a list of findings. Pure computation
over data that already exists in a single response, same "stateless,
no persistence needed" shape as Phase 6's filters. Trend-over-time
features (item 58, "vulnerability trends") explicitly need history
across separate scans, which this project doesn't persist yet — see
README "Phase 7" design notes for why that's deferred alongside Phase
6's dismiss/resolve/history, not attempted here.
"""
from collections import Counter
from typing import Sequence

from app.schemas.findings import Finding, ScanSummary

# Weights are deliberately simple and documented, not tuned against any
# real-world calibration data (there isn't any yet — see Phase 5's
# "confidence calibration" deferral for the same reason). The intent is
# a single glanceable number that moves in the right direction — more
# high-severity findings raises it, more low-severity findings raises
# it less — not a precisely calibrated CVSS-style score.
SEVERITY_WEIGHTS = {"high": 10, "medium": 5, "low": 1}

# A raw weighted sum has no natural ceiling (100 findings would dwarf 5),
# which makes the number meaningless to glance at across repos of very
# different sizes. Capping at 100 keeps it interpretable as
# "how much of a 0-100 concern is this" regardless of repo size, at the
# cost of not distinguishing "very bad" from "extremely bad" past the cap.
MAX_RISK_SCORE = 100


def compute_summary(findings: Sequence[Finding]) -> ScanSummary:
    severity_counts = Counter(f.severity.lower() for f in findings)
    rule_counts = Counter(f.rule_id for f in findings)

    raw_score = sum(SEVERITY_WEIGHTS.get(sev, 0) * count for sev, count in severity_counts.items())
    risk_score = min(raw_score, MAX_RISK_SCORE)

    return ScanSummary(
        risk_score=risk_score,
        severity_distribution=dict(severity_counts),
        rule_distribution=dict(rule_counts),
    )
