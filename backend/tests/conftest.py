from pathlib import Path
from typing import Dict, List

import pytest

from app.analyzer.python_rules import analyze_python_file
from app.analyzer.js_ts_rules import analyze_js_ts_file
from app.schemas.findings import Finding

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def analyze_fixture(filename: str) -> List[Finding]:
    """Run the Python rule engine against a fixture file and return all
    findings. `filename` is relative to tests/fixtures/."""
    path = FIXTURES_DIR / filename
    return analyze_python_file(path, filename)


def analyze_js_ts_fixture(filename: str) -> List[Finding]:
    """Same idea as analyze_fixture, for the JS/TS/TSX rule engine."""
    path = FIXTURES_DIR / filename
    return analyze_js_ts_file(path, filename)


def findings_by_function(findings: List[Finding]) -> Dict[str, List[Finding]]:
    """Group findings by enclosing function name for easy per-function
    assertions, independent of line numbers."""
    grouped: Dict[str, List[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.function, []).append(f)
    return grouped


@pytest.fixture(scope="module")
def vulnerable_findings() -> List[Finding]:
    return analyze_fixture("vulnerable_python.py")


@pytest.fixture(scope="module")
def vulnerable_by_function(vulnerable_findings) -> Dict[str, List[Finding]]:
    return findings_by_function(vulnerable_findings)


@pytest.fixture(scope="module")
def safe_findings() -> List[Finding]:
    return analyze_fixture("safe_python.py")


@pytest.fixture(scope="module")
def safe_by_function(safe_findings) -> Dict[str, List[Finding]]:
    return findings_by_function(safe_findings)


@pytest.fixture(scope="module")
def vulnerable_js_findings() -> List[Finding]:
    return analyze_js_ts_fixture("vulnerable_js.js")


@pytest.fixture(scope="module")
def vulnerable_js_by_function(vulnerable_js_findings) -> Dict[str, List[Finding]]:
    return findings_by_function(vulnerable_js_findings)


@pytest.fixture(scope="module")
def safe_js_findings() -> List[Finding]:
    return analyze_js_ts_fixture("safe_js.js")


@pytest.fixture(scope="module")
def safe_js_by_function(safe_js_findings) -> Dict[str, List[Finding]]:
    return findings_by_function(safe_js_findings)


@pytest.fixture(scope="module")
def vulnerable_ts_findings() -> List[Finding]:
    return analyze_js_ts_fixture("vulnerable_ts.ts")


@pytest.fixture(scope="module")
def vulnerable_ts_by_function(vulnerable_ts_findings) -> Dict[str, List[Finding]]:
    return findings_by_function(vulnerable_ts_findings)
