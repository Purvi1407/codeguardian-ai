"""
Tests for Phase 3's bounded, one-hop cross-function parameter taint
tracking in analyzer/js_ts_rules.py. Mirrors test_cross_function_python.py
in structure — see that file's docstring for the full rationale, which
applies identically here.
"""
from pathlib import Path

from app.analyzer.js_ts_rules import analyze_js_ts_file

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "cross_function_js.js"


def analyze():
    return analyze_js_ts_file(FIXTURE_PATH, "cross_function_js.js")


class TestOneHopCrossFunctionTaint:
    def test_helper_sink_fires_when_a_caller_passes_dynamic_value(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "runQueryOneHop"]
        assert matches, "runQueryOneHop should fire — it's called with a dynamic value"
        assert matches[0].rule_id == "sql-injection-string-build"

    def test_finding_is_attributed_to_the_sink_not_the_call_site(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "runQueryOneHop"]
        assert len(matches) == 1
        assert matches[0].function == "runQueryOneHop"

    def test_multiple_call_sites_do_not_produce_duplicate_findings(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "runQueryOneHop"]
        assert len(matches) == 1

    def test_finding_description_notes_it_came_via_a_parameter(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "runQueryOneHop"]
        assert "parameter" in matches[0].description.lower()


class TestSafeOnlyCallersNeverSeedFalsePositives:
    def test_helper_called_only_with_static_string_does_not_fire(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "runQueryOnlyCalledSafely"]
        assert matches == []


class TestAliasPropagation:
    def test_renamed_tainted_variable_still_detected(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "aliasChainStillDetected"]
        assert matches and matches[0].rule_id == "sql-injection-string-build"

    def test_taint_cleared_by_reassignment_to_safe_literal(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "aliasClearedBySafeReassignment"]
        assert matches == []


class TestUnprovenParameterDoesNotSeedCallee:
    def test_bare_parameter_with_no_local_taint_does_not_propagate(self):
        """callerPassesUnprovenParameter passes its own bare, untracked
        parameter into runCommandNotSeeded — since that parameter was
        never itself demonstrated to be dynamic within this file, it
        must not cause the callee to be seeded."""
        findings = analyze()
        matches = [f for f in findings if f.function == "runCommandNotSeeded"]
        assert matches == []


class TestOneHopScopeLimit:
    def test_two_hop_chain_is_not_detected(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "hopB"]
        assert matches == []
