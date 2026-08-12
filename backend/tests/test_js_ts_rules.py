"""
Rule-by-rule regression coverage for app/analyzer/js_ts_rules.py.

Mirrors tests/test_python_rules.py in structure and philosophy — see
that file's module docstring for the reasoning behind asserting by
function name instead of line number, and the meta-tests that catch
fixture/assertion drift.
"""
import pytest

from app.analyzer.rules import RULES

# Python-only rules — everything else in RULES is fair game for a JS/TS
# fixture. Deriving from RULES.keys() (rather than a hand-maintained
# positive list, which is what this used to be) means a new rule added
# to rules.py is caught by TestJsTsCoverageIsComplete below automatically,
# the same way test_python_rules.py's equivalent check already worked —
# this was a real gap: the old hardcoded JS_TS_RULE_IDS set silently
# stayed valid even when new rules were added to rules.py without a
# fixture, because it never referenced RULES at all.
PYTHON_ONLY_RULE_IDS = {
    "command-injection-shell-true",
    "command-injection-os-system",
    "insecure-deserialization-pickle",
    "insecure-deserialization-yaml",
    "debug-mode-enabled",
    "tls-verification-disabled",
    "path-traversal-open",
    "flask-cookie-missing-secure-flag",
}
JS_TS_RULE_IDS = set(RULES.keys()) - PYTHON_ONLY_RULE_IDS

EXPECTED_TRIGGERS = {
    "sql_injection_string_build__template": "sql-injection-string-build",
    "sql_injection_string_build__concat": "sql-injection-string-build",
    "sql_injection_string_build__via_variable": "sql-injection-string-build",
    "command_injection_js_exec__child_process": "command-injection-js-exec",
    "command_injection_js_exec__bare_via_variable": "command-injection-js-exec",
    "dangerous_eval_exec__eval_variable": "dangerous-eval-exec",
    "dangerous_eval_exec__new_function": "dangerous-eval-exec",
    "xss_innerhtml_assignment__parameter": "xss-innerhtml-assignment",
    "xss_innerhtml_assignment__template": "xss-innerhtml-assignment",
    "weak_crypto_hash__md5": "weak-crypto-hash",
    "weak_crypto_hash__sha1": "weak-crypto-hash",
    "insecure_cors_wildcard__set_header": "insecure-cors-wildcard",
    "insecure_cors_wildcard__origin_config": "insecure-cors-wildcard",
    "jwt_none_algorithm__algorithms_array": "jwt-none-algorithm",
    "hardcoded_secret__password": "hardcoded-secret",
    "hardcoded_secret__api_key": "hardcoded-secret",
    "sql_injection_string_build__arrow_function": "sql-injection-string-build",
    "sql_injection_string_build__class_method": "sql-injection-string-build",
    "sql_injection_string_build__chained_member": "sql-injection-string-build",
    "jwt_none_algorithm__singular_key": "jwt-none-algorithm",
    "path_traversal_fs__readfile_template": "path-traversal-fs",
    "path_traversal_fs__via_variable": "path-traversal-fs",
    "insecure_random_token__direct": "insecure-random-token",
    "insecure_random_token__password": "insecure-random-token",
    "cookie_missing_secure_flag__no_options": "cookie-missing-secure-flag",
    "cookie_missing_secure_flag__only_httponly": "cookie-missing-secure-flag",
}

SAFE_FUNCTIONS = [
    "safe_sql_parameterized",
    "safe_sql_static_string_only",
    "safe_regex_exec_literal_pattern",
    "safe_regex_exec_named_variable",
    "safe_eval_literal_argument",
    "safe_eval_is_actually_a_method",
    "safe_innerhtml_literal",
    "safe_crypto_sha256",
    "safe_cors_specific_origin",
    "safe_cors_origin_config_specific",
    "safe_jwt_proper_algorithm",
    "safe_secret_from_env",
    "safe_secret_empty_placeholder",
    "safe_arrow_function_no_issue",
    "lookup",  # SafeService.lookup — a safe class method
    "safe_taint_cleared_on_reassignment",
    "safe_destructured_declaration",
    "known_gap_require_child_process_exec_not_detected",
    "safe_readfile_literal_path",
    "safe_random_token_uses_crypto_module",
    "safe_math_random_non_secret_variable",
    "safe_cookie_with_both_flags",
]


class TestVulnerableJsFixturesFireExpectedRule:
    @pytest.mark.parametrize("function_name,expected_rule_id", EXPECTED_TRIGGERS.items())
    def test_function_triggers_expected_rule(self, vulnerable_js_by_function, function_name, expected_rule_id):
        matches = vulnerable_js_by_function.get(function_name, [])
        assert matches, (
            f"Expected '{function_name}' to trigger rule '{expected_rule_id}', "
            f"but it produced no findings at all."
        )
        fired_rule_ids = {f.rule_id for f in matches}
        assert expected_rule_id in fired_rule_ids, (
            f"Expected '{function_name}' to trigger '{expected_rule_id}', "
            f"but it triggered {fired_rule_ids} instead."
        )

    def test_no_unexpected_functions_are_silent(self, vulnerable_js_by_function):
        missing = [
            name for name in EXPECTED_TRIGGERS
            if not vulnerable_js_by_function.get(name)
        ]
        assert not missing, f"These vulnerable JS fixtures produced NO findings: {missing}"

    def test_finding_attributes_correct_enclosing_function(self, vulnerable_js_by_function):
        """The AST rewrite's headline improvement over regex: findings
        now carry a real enclosing function name, including through
        arrow functions and class methods — not just `function`
        declarations. This is the specific regression check for that."""
        arrow_findings = vulnerable_js_by_function.get("sql_injection_string_build__arrow_function", [])
        assert arrow_findings and arrow_findings[0].function == "sql_injection_string_build__arrow_function"

        method_findings = vulnerable_js_by_function.get("sql_injection_string_build__class_method", [])
        assert method_findings and method_findings[0].function == "sql_injection_string_build__class_method"

    def test_chained_member_expression_still_resolves_root_object(self, vulnerable_js_by_function):
        """`this.db.query(...)` — a multi-hop member expression, not
        just single-hop `db.query(...)`. Exercises the while-loop in
        _member_root_identifier that walks up through each
        member_expression hop to find the base identifier."""
        matches = vulnerable_js_by_function.get("sql_injection_string_build__chained_member", [])
        assert matches and matches[0].rule_id == "sql-injection-string-build"


class TestSafeJsFixturesProduceNoFindings:
    @pytest.mark.parametrize("function_name", SAFE_FUNCTIONS)
    def test_safe_function_has_no_findings(self, safe_js_by_function, function_name):
        matches = safe_js_by_function.get(function_name, [])
        assert not matches, (
            f"'{function_name}' is meant to be safe but triggered: "
            f"{[m.rule_id for m in matches]}"
        )

    def test_regexp_exec_never_confused_with_child_process_exec(self, safe_js_findings):
        """The exact false positive the old regex version had to
        special-case by hand with a negative lookbehind (see git history
        for js_ts_rules.py before Phase 2). The AST version resolves it
        structurally: RegExp.prototype.exec() is always a
        member_expression, so it can never match the bare-identifier
        command-injection branch."""
        command_injection_findings = [
            f for f in safe_js_findings if f.rule_id == "command-injection-js-exec"
        ]
        assert command_injection_findings == []

    def test_taint_tracking_clears_on_reassignment_to_a_safe_literal(self, safe_js_by_function):
        """A variable tainted by a dynamic-string assignment, then
        reassigned to a plain literal, must not still be treated as
        tainted at the point it's used — same semantics as
        python_rules.py's equivalent clearing behavior."""
        matches = safe_js_by_function.get("safe_taint_cleared_on_reassignment", [])
        assert matches == []

    def test_destructuring_declarator_does_not_crash_analysis(self, safe_js_by_function):
        """`const { query } = require(...)` — name_node.type is
        'object_pattern', not 'identifier'. Must be safely ignored by
        the secret/taint tracking checks, not raise."""
        matches = safe_js_by_function.get("safe_destructured_declaration", [])
        assert matches == []


class TestVulnerableTsFixturesFireExpectedRule:
    """Confirms the TS grammar path works end to end, through
    TypeScript-specific syntax (type annotations, access modifiers,
    interfaces) that the plain JS grammar doesn't have."""

    def test_typed_function_param_still_detected(self, vulnerable_ts_by_function):
        matches = vulnerable_ts_by_function.get("sql_injection_string_build__typed_param", [])
        assert matches and matches[0].rule_id == "sql-injection-string-build"

    def test_typed_class_method_still_detected(self, vulnerable_ts_by_function):
        matches = vulnerable_ts_by_function.get("weak_crypto_hash__typed_method", [])
        assert matches and matches[0].rule_id == "weak-crypto-hash"

    def test_safe_typed_function_has_no_findings(self, vulnerable_ts_by_function):
        assert vulnerable_ts_by_function.get("safe_sql_typed_param", []) == []

    def test_safe_typed_method_has_no_findings(self, vulnerable_ts_by_function):
        assert vulnerable_ts_by_function.get("safe_typed_method", []) == []


class TestJsTsCoverageIsComplete:
    def test_every_js_ts_rule_has_a_vulnerable_fixture(self):
        covered_rules = set(EXPECTED_TRIGGERS.values())
        missing = JS_TS_RULE_IDS - covered_rules
        assert not missing, (
            f"These JS/TS rules have no vulnerable_js.js fixture: {missing}. "
            f"Add a case so a future rule regression can't go unnoticed."
        )

    def test_every_vulnerable_js_fixture_function_is_asserted(self, vulnerable_js_by_function):
        fixture_functions = set(vulnerable_js_by_function.keys())
        asserted_functions = set(EXPECTED_TRIGGERS.keys())
        unasserted = fixture_functions - asserted_functions
        assert not unasserted, (
            f"These functions in vulnerable_js.js have no assertion "
            f"in EXPECTED_TRIGGERS: {unasserted}"
        )

    def test_rule_ids_referenced_in_this_file_exist_in_rules_py(self):
        for rule_id in EXPECTED_TRIGGERS.values():
            assert rule_id in RULES, f"'{rule_id}' is asserted in tests but not defined in analyzer/rules.py"
