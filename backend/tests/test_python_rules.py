"""
Rule-by-rule regression coverage for app/analyzer/python_rules.py.

Two fixture files drive this:
  - fixtures/vulnerable_python.py: one function per rule that MUST fire
    that rule (true positives).
  - fixtures/safe_python.py: benign or tricky-but-safe functions that
    MUST NOT fire any rule (false positive regressions).

Assertions are keyed on function name, not line number, so editing the
fixture files (adding a comment, reordering functions) doesn't break the
suite — only an actual behavior change does.
"""
import pytest

from app.analyzer.rules import RULES

# Every function in vulnerable_python.py, mapped to the rule_id it must
# trigger. If a function name here doesn't exist in the fixture, or a
# fixture function isn't listed here, test_all_rules_have_coverage below
# will fail loudly rather than silently passing with a gap.
EXPECTED_TRIGGERS = {
    "sql_injection_string_build__fstring": "sql-injection-string-build",
    "sql_injection_string_build__concat": "sql-injection-string-build",
    "sql_injection_string_build__format_call": "sql-injection-string-build",
    "sql_injection_string_build__via_variable": "sql-injection-string-build",
    "command_injection_shell_true__run": "command-injection-shell-true",
    "command_injection_shell_true__popen": "command-injection-shell-true",
    "command_injection_os_system__dynamic_arg": "command-injection-os-system",
    "command_injection_os_system__variable": "command-injection-os-system",
    "hardcoded_secret__password": "hardcoded-secret",
    "hardcoded_secret__api_key": "hardcoded-secret",
    "insecure_deserialization_pickle__load": "insecure-deserialization-pickle",
    "insecure_deserialization_pickle__loads": "insecure-deserialization-pickle",
    "insecure_deserialization_yaml__no_loader": "insecure-deserialization-yaml",
    "insecure_deserialization_yaml__unsafe_loader": "insecure-deserialization-yaml",
    "dangerous_eval_exec__eval_variable": "dangerous-eval-exec",
    "dangerous_eval_exec__exec_variable": "dangerous-eval-exec",
    "weak_crypto_hash__md5": "weak-crypto-hash",
    "weak_crypto_hash__sha1": "weak-crypto-hash",
    "debug_mode_enabled__flask_app": "debug-mode-enabled",
    "tls_verification_disabled__get": "tls-verification-disabled",
    "tls_verification_disabled__post": "tls-verification-disabled",
}

# Every function in safe_python.py — all must produce zero findings.
SAFE_FUNCTIONS = [
    "safe_sql_parameterized_qmark",
    "safe_sql_parameterized_named",
    "safe_sql_static_string_only",
    "safe_subprocess_no_shell",
    "safe_subprocess_shell_explicit_false",
    "safe_os_system_literal",
    "safe_secret_from_env",
    "safe_secret_from_getenv",
    "safe_secret_empty_placeholder",
    "safe_deserialization_json",
    "safe_deserialization_yaml_safe_loader",
    "safe_deserialization_yaml_safe_load",
    "safe_eval_literal_argument",
    "safe_eval_is_actually_a_method",
    "safe_crypto_sha256",
    "safe_crypto_hmac_with_sha1_for_signing",
    "safe_debug_false",
    "safe_debug_not_specified",
    "safe_tls_verify_true",
    "safe_tls_verify_omitted",
    "safe_call_target_not_name_or_attribute",
]


class TestVulnerableFixturesFireExpectedRule:
    """Each of these is a true-positive check: the rule engine must catch
    the vulnerability it's designed to catch."""

    @pytest.mark.parametrize("function_name,expected_rule_id", EXPECTED_TRIGGERS.items())
    def test_function_triggers_expected_rule(self, vulnerable_by_function, function_name, expected_rule_id):
        matches = vulnerable_by_function.get(function_name, [])
        assert matches, (
            f"Expected '{function_name}' to trigger rule '{expected_rule_id}', "
            f"but it produced no findings at all."
        )
        fired_rule_ids = {f.rule_id for f in matches}
        assert expected_rule_id in fired_rule_ids, (
            f"Expected '{function_name}' to trigger '{expected_rule_id}', "
            f"but it triggered {fired_rule_ids} instead."
        )

    def test_no_unexpected_functions_are_silent(self, vulnerable_by_function):
        """Guards against a rule silently breaking: every function we
        claim is vulnerable must appear as a key with findings."""
        missing = [
            name for name in EXPECTED_TRIGGERS
            if not vulnerable_by_function.get(name)
        ]
        assert not missing, f"These vulnerable fixtures produced NO findings: {missing}"


class TestSafeFixturesProduceNoFindings:
    """False-positive regression checks: code that looks similar to a
    vulnerable pattern, or uses a safe variant of a risky API, must not
    be flagged."""

    @pytest.mark.parametrize("function_name", SAFE_FUNCTIONS)
    def test_safe_function_has_no_findings(self, safe_by_function, function_name):
        matches = safe_by_function.get(function_name, [])
        assert not matches, (
            f"'{function_name}' is meant to be safe but triggered: "
            f"{[m.rule_id for m in matches]}"
        )


class TestCoverageIsComplete:
    """Meta-tests: catch drift between the fixture files, this test
    file's expectations, and the actual rule set in analyzer/rules.py."""

    def test_every_rule_has_a_vulnerable_fixture(self):
        # command-injection-js-exec, xss-innerhtml-assignment,
        # insecure-cors-wildcard, jwt-none-algorithm are JS/TS-only rules
        # (see analyzer/js_ts_rules.py) and have no Python fixture.
        js_only_rules = {
            "command-injection-js-exec",
            "xss-innerhtml-assignment",
            "insecure-cors-wildcard",
            "jwt-none-algorithm",
        }
        python_rules = set(RULES.keys()) - js_only_rules
        covered_rules = set(EXPECTED_TRIGGERS.values())
        missing = python_rules - covered_rules
        assert not missing, (
            f"These Python rules have no vulnerable_python.py fixture: {missing}. "
            f"Add a case so a future rule regression can't go unnoticed."
        )

    def test_every_vulnerable_fixture_function_is_asserted(self, vulnerable_by_function):
        """Catches the opposite drift: someone adds a new function to
        vulnerable_python.py but forgets to add an assertion for it."""
        fixture_functions = set(vulnerable_by_function.keys())
        asserted_functions = set(EXPECTED_TRIGGERS.keys())
        unasserted = fixture_functions - asserted_functions
        assert not unasserted, (
            f"These functions in vulnerable_python.py have no assertion "
            f"in EXPECTED_TRIGGERS: {unasserted}"
        )
