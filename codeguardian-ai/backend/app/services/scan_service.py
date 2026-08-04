from pathlib import Path
from typing import List, Tuple

from app.parser.discovery import discover_source_files
from app.parser.python_parser import parse_python_file
from app.parser.js_ts_parser import parse_js_ts_file
from app.analyzer.python_rules import analyze_python_file
from app.analyzer.js_ts_rules import analyze_js_ts_file
from app.schemas.scan import FileMetadata
from app.schemas.findings import Finding


def build_file_metadata(repo_path: Path) -> List[FileMetadata]:
    """Discover source files under repo_path and parse each into FileMetadata."""
    results: List[FileMetadata] = []

    for abs_path, language in discover_source_files(repo_path):
        # Always use forward slashes in the API response, regardless of host OS
        # (Windows' Path.relative_to gives backslashes, which would look
        # inconsistent to a reviewer diffing output across machines).
        rel_path = abs_path.relative_to(repo_path).as_posix()

        if language == "Python":
            functions, classes, loc, error = parse_python_file(abs_path)
        else:  # TypeScript / JavaScript
            functions, classes, loc, error = parse_js_ts_file(abs_path)

        results.append(FileMetadata(
            path=rel_path,
            language=language,
            functions=functions,
            classes=classes,
            loc=loc,
            parse_error=error or None,
        ))

    # Deterministic ordering makes the API pleasant to test against
    results.sort(key=lambda f: f.path)
    return results


def build_file_metadata_and_findings(repo_path: Path) -> Tuple[List[FileMetadata], List[Finding]]:
    """
    Same as build_file_metadata, but also runs Module 3 (rule-based analyzer)
    on every Python file. TS/JS analysis isn't implemented yet — same
    documented tradeoff as the TS/JS parser itself.
    """
    files: List[FileMetadata] = []
    all_findings: List[Finding] = []

    for abs_path, language in discover_source_files(repo_path):
        rel_path = abs_path.relative_to(repo_path).as_posix()

        if language == "Python":
            functions, classes, loc, error = parse_python_file(abs_path)
            if not error:  # only run rules on files that parsed cleanly
                all_findings.extend(analyze_python_file(abs_path, rel_path))
        else:
            functions, classes, loc, error = parse_js_ts_file(abs_path)
            if not error:
                all_findings.extend(analyze_js_ts_file(abs_path, rel_path))

        files.append(FileMetadata(
            path=rel_path,
            language=language,
            functions=functions,
            classes=classes,
            loc=loc,
            parse_error=error or None,
        ))

    files.sort(key=lambda f: f.path)
    all_findings.sort(key=lambda f: (f.file, f.line))
    return files, all_findings
