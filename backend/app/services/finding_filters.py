"""
Phase 6 (Developer Experience): severity/language/rule filters and
free-text search, applied to a scan's results before they're returned.

Implemented as a stateless post-filter over an already-completed
scan/analyze/validate result — no persistence, no new endpoints,
consistent with how /analyze and /validate already work (clone,
process, return, cleanup — nothing kept around between requests).
Roadmap items in this same phase that DO need persistence (dismiss,
resolve, finding history) are deliberately deferred — see README
"Phase 6" design notes for why.
"""
from typing import Dict, List, Optional, Sequence, TypeVar

from app.schemas.scan import FileMetadata
from app.schemas.findings import Finding

FindingT = TypeVar("FindingT", bound=Finding)


def build_language_lookup(files: Sequence[FileMetadata]) -> Dict[str, str]:
    """file path -> language, built from the FULL (unfiltered) file
    list. Callers should build this BEFORE filtering `files` itself, so
    a finding can still be matched to its file's language even after
    the returned `files` list has been narrowed down."""
    return {f.path: f.language for f in files}


def filter_files_by_language(files: Sequence[FileMetadata], languages: Optional[Sequence[str]]) -> List[FileMetadata]:
    if not languages:
        return list(files)
    wanted = {lang.lower() for lang in languages}
    return [f for f in files if f.language.lower() in wanted]


def _matches_search(finding: Finding, query: str) -> bool:
    q = query.lower()
    haystacks = [finding.file, finding.title, finding.description, finding.snippet, finding.rule_id]
    if finding.function:
        haystacks.append(finding.function)
    return any(q in h.lower() for h in haystacks)


def filter_findings(
    findings: Sequence[FindingT],
    language_lookup: Optional[Dict[str, str]] = None,
    severity: Optional[Sequence[str]] = None,
    languages: Optional[Sequence[str]] = None,
    rules: Optional[Sequence[str]] = None,
    search: Optional[str] = None,
) -> List[FindingT]:
    """Applies whichever filters were actually provided (None/empty ==
    no filtering on that dimension) to a list of findings — works for
    both plain `Finding` and `ValidatedFinding`, since it only reads
    fields both share."""
    result: List[FindingT] = list(findings)

    if severity:
        wanted_severity = {s.lower() for s in severity}
        result = [f for f in result if f.severity.lower() in wanted_severity]

    if rules:
        wanted_rules = set(rules)
        result = [f for f in result if f.rule_id in wanted_rules]

    if languages and language_lookup is not None:
        wanted_langs = {lang.lower() for lang in languages}
        result = [
            f for f in result
            if language_lookup.get(f.file, "").lower() in wanted_langs
        ]

    if search:
        result = [f for f in result if _matches_search(f, search)]

    return result
