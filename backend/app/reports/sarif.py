"""
SARIF 2.1.0 output (Phase 8, item 67). SARIF (Static Analysis Results
Interchange Format) is the format GitHub's own code scanning UI, most
IDEs, and most CI security dashboards natively understand — a tool that
speaks SARIF plugs into infrastructure that already exists rather than
needing a bespoke viewer built for it.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Scope: this maps our own `Finding`/`ValidatedFinding` model onto SARIF's
"rules" + "results" structure. It intentionally does NOT try to cover
every optional SARIF field (code flows, related locations, fingerprints
for result-matching across runs) — just enough for GitHub code scanning
and generic SARIF viewers to render something correct and useful.
"""
from typing import Dict, List, Sequence

from app.analyzer.rules import RULES
from app.schemas.findings import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# SARIF's `level` is one of "error" | "warning" | "note" | "none" — not
# the same vocabulary as our own high/medium/low severity, so it needs
# an explicit mapping rather than passing the string through as-is.
SEVERITY_TO_SARIF_LEVEL = {
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _rule_descriptor(rule_id: str) -> dict:
    """One `rules[]` entry per unique rule_id actually present in the
    findings — SARIF wants rule metadata defined once and referenced by
    ID from each result, not repeated per-finding."""
    meta = RULES.get(rule_id, {})
    descriptor = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": meta.get("title", rule_id)},
        "fullDescription": {"text": meta.get("description", "")},
        "helpUri": f"https://cwe.mitre.org/data/definitions/{meta['cwe'].split('-')[-1]}.html" if meta.get("cwe") else "",
        "properties": {
            "tags": [t for t in (meta.get("cwe"), meta.get("owasp")) if t],
        },
    }
    if meta.get("remediation"):
        descriptor["help"] = {"text": meta["remediation"]}
    return descriptor


def _result(finding: Finding) -> dict:
    message_text = finding.description
    # ValidatedFinding (post-AI) carries a richer explanation — prefer
    # it when present, since it's specific to this exact finding rather
    # than the generic rule-level description.
    explanation = getattr(finding, "explanation", None)
    if explanation:
        message_text = explanation

    return {
        "ruleId": finding.rule_id,
        "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity.lower(), "warning"),
        "message": {"text": message_text},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file},
                "region": {"startLine": max(1, finding.line)},
            },
            "logicalLocations": [{"name": finding.function}] if finding.function else [],
        }],
    }


def to_sarif(findings: Sequence[Finding], tool_name: str = "CodeGuardian AI", tool_version: str = "1.0.0") -> Dict:
    """Builds a complete SARIF 2.1.0 log document (dict — caller decides
    whether to json.dumps it, write it to a file, etc.)."""
    seen_rule_ids: List[str] = []
    for f in findings:
        if f.rule_id not in seen_rule_ids:
            seen_rule_ids.append(f.rule_id)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/Purvi1407/codeguardian-ai",
                    "rules": [_rule_descriptor(rid) for rid in seen_rule_ids],
                }
            },
            "results": [_result(f) for f in findings],
        }],
    }
