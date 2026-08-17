from pathlib import Path
from typing import Dict, List
import os

import pytest

from app.analyzer.python_rules import analyze_python_file
from app.analyzer.js_ts_rules import analyze_js_ts_file
from app.schemas.findings import Finding

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True, scope="session")
def _generous_rate_limit_for_tests():
    """Phase 10's rate-limiting middleware (app/core/rate_limit.py)
    holds its request counters in memory for the lifetime of the app
    instance — and since `app.main` is imported once and cached by
    Python for the whole pytest session, that same instance (and its
    counters) persists across every test file that does
    `from app.main import app`. Without this fixture, the cumulative
    request volume across the WHOLE test suite (many tests across many
    files POST to /scan, /analyze, /validate) would trip the default
    10-requests/minute production limit partway through a full run —
    a test-isolation problem, not a bug in the rate limiter itself.

    Set once, session-wide, high enough that no plausible test-suite
    volume trips it. Tests that specifically exercise rate limiting
    (see test_rate_limit.py) explicitly monkeypatch this lower for
    their own isolated, freshly-`importlib.reload`-ed app instance,
    which correctly takes precedence over this session-wide default
    during that test's scope."""
    os.environ["CODEGUARDIAN_RATE_LIMIT_PER_MINUTE"] = "100000"


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
