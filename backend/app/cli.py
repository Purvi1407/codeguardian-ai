"""
Phase 8 (CI/CD & Integration): a CLI for scanning a LOCAL directory —
deliberately not another wrapper around cloning a GitHub URL, since a
CI job already has the repo checked out on disk. This is what makes a
GitHub Action (or any CI system) actually able to use this project
without a network clone step, an API key for the basic rule-based scan,
or a running server at all — see .github/workflows/pr-security-scan.yml
for a full worked example of this in a GitHub Actions PR check.

Usage:
    python -m app.cli --path .
    python -m app.cli --path . --format sarif --output results.sarif
    python -m app.cli --path . --fail-on high
    python -m app.cli --path . --changed-only --base-ref origin/main
    python -m app.cli --path . --write-baseline .codeguardian-baseline.json
    python -m app.cli --path . --baseline .codeguardian-baseline.json

Exit codes:
    0 — scan completed, no gate-triggering findings (or no --fail-on set)
    1 — scan completed, at least one finding at/above --fail-on severity
    2 — couldn't complete the scan (bad path, git error, etc.)
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Set

from app.schemas.findings import Finding
from app.services.scan_service import build_file_metadata_and_findings
from app.reports.sarif import to_sarif
from app.services.baseline import write_baseline, filter_new_findings

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def get_changed_files(repo_dir: Path, base_ref: str) -> Set[str]:
    """Relative (POSIX-style) paths changed between `base_ref` and the
    current working tree, per `git diff`. Raises CalledProcessError if
    git itself fails (e.g. base_ref doesn't exist / not a git repo) —
    the CLI catches this and exits 2 with a clear message rather than a
    raw traceback."""
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
        cwd=repo_dir, capture_output=True, text=True, check=True,
    )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def filter_to_changed_files(findings: List[Finding], changed_files: Set[str]) -> List[Finding]:
    """Note on scope: this narrows which findings are REPORTED to ones
    in changed files, not which files get parsed/analyzed — the scan
    itself still visits every file in `--path`. Filtering after the
    fact is simpler and correct; it does not reduce scan TIME the way
    only-parsing-changed-files would. Named explicitly rather than
    implied, since "PR scanning" could otherwise be read as a speed
    claim it isn't making."""
    return [f for f in findings if f.file in changed_files]


def format_text(findings: List[Finding]) -> str:
    if not findings:
        return "No findings.\n"
    lines = []
    for f in findings:
        func = f" ({f.function})" if f.function else ""
        lines.append(f"{f.file}:{f.line}{func} [{f.severity}] {f.rule_id} — {f.title}")
    lines.append(f"\n{len(findings)} finding(s).")
    return "\n".join(lines) + "\n"


def gate_triggered(findings: List[Finding], fail_on: Optional[str]) -> bool:
    if not fail_on:
        return False
    threshold = SEVERITY_RANK.get(fail_on.lower(), 0)
    return any(SEVERITY_RANK.get(f.severity.lower(), 0) >= threshold for f in findings)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codeguardian",
        description="Scan a local directory for security findings (Modules 1-3, rule-based — no API key needed).",
    )
    parser.add_argument("--path", required=True, help="Directory to scan (e.g. '.' for the current checkout)")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="Output format")
    parser.add_argument("--output", help="Write output to this file instead of stdout")
    parser.add_argument("--fail-on", choices=["low", "medium", "high"], default=None,
                         help="Exit 1 if any finding at or above this severity is present")
    parser.add_argument("--baseline", help="Suppress findings already present in this baseline file")
    parser.add_argument("--write-baseline", help="Write a baseline snapshot of current findings to this file and exit")
    parser.add_argument("--changed-only", action="store_true",
                         help="Only report findings in files changed vs --base-ref (requires a git repo)")
    parser.add_argument("--base-ref", default="origin/main", help="Git ref to diff against for --changed-only")
    return parser


def run(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    repo_path = Path(args.path).resolve()
    if not repo_path.is_dir():
        print(f"error: --path '{args.path}' is not a directory", file=sys.stderr)
        return 2

    try:
        _files, findings = build_file_metadata_and_findings(repo_path)
    except Exception as e:  # pragma: no cover - defensive: parser/analyzer already fail-soft internally
        print(f"error: scan failed: {e}", file=sys.stderr)
        return 2

    if args.write_baseline:
        write_baseline(findings, Path(args.write_baseline))
        print(f"Baseline written to {args.write_baseline} ({len(findings)} finding(s) recorded).")
        return 0

    if args.baseline:
        findings = filter_new_findings(findings, Path(args.baseline))

    if args.changed_only:
        try:
            changed = get_changed_files(repo_path, args.base_ref)
        except subprocess.CalledProcessError as e:
            print(f"error: git diff against '{args.base_ref}' failed: {e.stderr.strip()}", file=sys.stderr)
            return 2
        findings = filter_to_changed_files(findings, changed)

    if args.format == "json":
        output = json.dumps([f.model_dump() for f in findings], indent=2)
    elif args.format == "sarif":
        output = json.dumps(to_sarif(findings), indent=2)
    else:
        output = format_text(findings)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")

    return 1 if gate_triggered(findings, args.fail_on) else 0


def main():
    sys.exit(run())


if __name__ == "__main__":
    main()
