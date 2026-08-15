"""
Tests for app/reports/sarif.py. No network access needed or used — the
real SARIF JSON schema wasn't reachable from this environment to
validate against directly (consistent with this project's established
pattern of fully offline, deterministic tests), so these assert
structural compliance with the SARIF 2.1.0 spec's required fields
directly: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
import json

from app.reports.sarif import to_sarif, SEVERITY_TO_SARIF_LEVEL
from app.schemas.findings import Finding, ValidatedFinding


def make_finding(**overrides):
    defaults = dict(
        rule_id="sql-injection-string-build",
        title="SQL query built with string formatting",
        severity="high",
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        file="app.py",
        function="handler",
        line=10,
        snippet="cursor.execute(query)",
        description="A SQL query is built dynamically.",
        remediation="Use parameterized queries.",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def make_validated_finding(**overrides):
    finding_kwargs = {k: v for k, v in overrides.items() if k in Finding.model_fields}
    base = make_finding(**finding_kwargs)
    return ValidatedFinding(
        **base.model_dump(),
        verified=True,
        confidence="high",
        explanation="This is exploitable via the id query parameter.",
        exploit_scenario="An attacker sends id=1 OR 1=1 to dump the table.",
        patch_suggestion="Use a parameterized query.",
        things_to_verify=[],
    )


class TestTopLevelStructure:
    def test_has_required_top_level_fields(self):
        sarif = to_sarif([make_finding()])
        assert sarif["$schema"]
        assert sarif["version"] == "2.1.0"
        assert isinstance(sarif["runs"], list)
        assert len(sarif["runs"]) == 1

    def test_output_is_json_serializable(self):
        sarif = to_sarif([make_finding()])
        json.dumps(sarif)  # raises if anything non-serializable snuck in

    def test_empty_findings_list_still_produces_valid_structure(self):
        sarif = to_sarif([])
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


class TestToolDriver:
    def test_driver_has_required_fields(self):
        sarif = to_sarif([make_finding()])
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"]
        assert driver["version"]

    def test_custom_tool_name_and_version(self):
        sarif = to_sarif([make_finding()], tool_name="MyTool", tool_version="9.9.9")
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "MyTool"
        assert driver["version"] == "9.9.9"


class TestRulesArray:
    def test_one_rule_entry_per_unique_rule_id(self):
        findings = [
            make_finding(rule_id="sql-injection-string-build", file="a.py"),
            make_finding(rule_id="sql-injection-string-build", file="b.py"),
            make_finding(rule_id="weak-crypto-hash", file="c.py"),
        ]
        sarif = to_sarif(findings)
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        assert rule_ids == ["sql-injection-string-build", "weak-crypto-hash"]  # order preserved, no dupes

    def test_rule_descriptor_pulls_from_rules_py_metadata(self):
        sarif = to_sarif([make_finding(rule_id="sql-injection-string-build")])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["shortDescription"]["text"] == "SQL query built with string formatting"
        assert "CWE-89" in rule["properties"]["tags"]
        assert "A03:2021-Injection" in rule["properties"]["tags"]

    def test_rule_descriptor_includes_cwe_help_uri(self):
        sarif = to_sarif([make_finding(rule_id="sql-injection-string-build")])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "89" in rule["helpUri"]

    def test_unknown_rule_id_does_not_crash(self):
        """Defensive: a rule_id not in RULES (shouldn't happen in
        practice, but must degrade gracefully, not KeyError)."""
        sarif = to_sarif([make_finding(rule_id="totally-made-up-rule")])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["id"] == "totally-made-up-rule"


class TestResults:
    def test_one_result_per_finding(self):
        findings = [make_finding(line=1), make_finding(line=2), make_finding(line=3)]
        sarif = to_sarif(findings)
        assert len(sarif["runs"][0]["results"]) == 3

    def test_result_has_required_fields(self):
        sarif = to_sarif([make_finding()])
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "sql-injection-string-build"
        assert result["level"] in ("error", "warning", "note", "none")
        assert result["message"]["text"]
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 10

    def test_line_zero_or_negative_clamped_to_1(self):
        """SARIF's startLine is 1-indexed and must be >= 1 — defensive
        clamp in case a finding ever has line=0 (shouldn't happen, but
        producing invalid SARIF for a viewer to choke on is worse than
        clamping)."""
        sarif = to_sarif([make_finding(line=0)])
        assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1

    def test_function_becomes_a_logical_location(self):
        sarif = to_sarif([make_finding(function="my_handler")])
        result = sarif["runs"][0]["results"][0]
        assert result["locations"][0]["logicalLocations"][0]["name"] == "my_handler"

    def test_no_function_gives_empty_logical_locations_not_none(self):
        sarif = to_sarif([make_finding(function=None)])
        result = sarif["runs"][0]["results"][0]
        assert result["locations"][0]["logicalLocations"] == []


class TestSeverityLevelMapping:
    def test_high_maps_to_error(self):
        sarif = to_sarif([make_finding(severity="high")])
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_medium_maps_to_warning(self):
        sarif = to_sarif([make_finding(severity="medium")])
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_low_maps_to_note(self):
        sarif = to_sarif([make_finding(severity="low")])
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_unknown_severity_defaults_to_warning_not_crash(self):
        sarif = to_sarif([make_finding(severity="critical")])
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_mapping_is_case_insensitive(self):
        sarif = to_sarif([make_finding(severity="HIGH")])
        assert sarif["runs"][0]["results"][0]["level"] == "error"


class TestValidatedFindingPrefersAIExplanation:
    def test_uses_ai_explanation_over_rule_description_when_present(self):
        validated = make_validated_finding()
        sarif = to_sarif([validated])
        message = sarif["runs"][0]["results"][0]["message"]["text"]
        assert message == validated.explanation
        assert message != validated.description

    def test_plain_finding_without_explanation_uses_rule_description(self):
        finding = make_finding()
        sarif = to_sarif([finding])
        message = sarif["runs"][0]["results"][0]["message"]["text"]
        assert message == finding.description
