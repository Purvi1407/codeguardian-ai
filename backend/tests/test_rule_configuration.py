"""
Tests for Phase 4's rule configuration mechanism: disabling specific
rule_ids via the CODEGUARDIAN_DISABLED_RULES environment variable.
Covers both analyzers, since each implements its own
_disabled_rule_ids() (see design notes in python_rules.py / js_ts_rules.py
for why this wasn't shared code).
"""
import os
from pathlib import Path

import pytest

from app.analyzer.python_rules import analyze_python_file
from app.analyzer.js_ts_rules import analyze_js_ts_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def clean_env():
    """Ensure CODEGUARDIAN_DISABLED_RULES doesn't leak between tests —
    each test sets exactly what it needs and this fixture guarantees a
    clean slate before and after."""
    original = os.environ.pop("CODEGUARDIAN_DISABLED_RULES", None)
    yield
    if original is None:
        os.environ.pop("CODEGUARDIAN_DISABLED_RULES", None)
    else:
        os.environ["CODEGUARDIAN_DISABLED_RULES"] = original


class TestPythonRuleDisabling:
    def test_disabled_rule_produces_no_findings(self):
        os.environ["CODEGUARDIAN_DISABLED_RULES"] = "weak-crypto-hash"
        findings = analyze_python_file(FIXTURES_DIR / "vulnerable_python.py", "vulnerable_python.py")
        assert all(f.rule_id != "weak-crypto-hash" for f in findings)

    def test_other_rules_still_fire_when_only_one_is_disabled(self):
        os.environ["CODEGUARDIAN_DISABLED_RULES"] = "weak-crypto-hash"
        findings = analyze_python_file(FIXTURES_DIR / "vulnerable_python.py", "vulnerable_python.py")
        assert any(f.rule_id == "sql-injection-string-build" for f in findings)

    def test_multiple_disabled_rules_comma_separated(self):
        os.environ["CODEGUARDIAN_DISABLED_RULES"] = "weak-crypto-hash,hardcoded-secret"
        findings = analyze_python_file(FIXTURES_DIR / "vulnerable_python.py", "vulnerable_python.py")
        fired_rules = {f.rule_id for f in findings}
        assert "weak-crypto-hash" not in fired_rules
        assert "hardcoded-secret" not in fired_rules
        assert "sql-injection-string-build" in fired_rules

    def test_no_env_var_set_behaves_normally(self):
        findings = analyze_python_file(FIXTURES_DIR / "vulnerable_python.py", "vulnerable_python.py")
        assert any(f.rule_id == "weak-crypto-hash" for f in findings)

    def test_disabling_a_rule_that_seeds_cross_function_taint_still_works(self):
        """Disabling sql-injection-string-build must also suppress the
        cross-function-seeded (Phase 3) variant of the same rule, not
        just the direct one — both passes share the same disabled set."""
        os.environ["CODEGUARDIAN_DISABLED_RULES"] = "sql-injection-string-build"
        findings = analyze_python_file(
            FIXTURES_DIR / "cross_function_python.py", "cross_function_python.py"
        )
        assert findings == []


class TestJsTsRuleDisabling:
    def test_disabled_rule_produces_no_findings(self):
        os.environ["CODEGUARDIAN_DISABLED_RULES"] = "weak-crypto-hash"
        findings = analyze_js_ts_file(FIXTURES_DIR / "vulnerable_js.js", "vulnerable_js.js")
        assert all(f.rule_id != "weak-crypto-hash" for f in findings)

    def test_other_rules_still_fire_when_only_one_is_disabled(self):
        os.environ["CODEGUARDIAN_DISABLED_RULES"] = "weak-crypto-hash"
        findings = analyze_js_ts_file(FIXTURES_DIR / "vulnerable_js.js", "vulnerable_js.js")
        assert any(f.rule_id == "sql-injection-string-build" for f in findings)

    def test_no_env_var_set_behaves_normally(self):
        findings = analyze_js_ts_file(FIXTURES_DIR / "vulnerable_js.js", "vulnerable_js.js")
        assert any(f.rule_id == "weak-crypto-hash" for f in findings)

    def test_disabling_a_rule_that_seeds_cross_function_taint_still_works(self):
        os.environ["CODEGUARDIAN_DISABLED_RULES"] = "sql-injection-string-build"
        findings = analyze_js_ts_file(
            FIXTURES_DIR / "cross_function_js.js", "cross_function_js.js"
        )
        assert findings == []
