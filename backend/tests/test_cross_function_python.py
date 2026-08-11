"""
Tests for Phase 3's bounded, one-hop cross-function parameter taint
tracking in analyzer/python_rules.py. See that module's docstring and
the README "Phase 3" section for the full design writeup — this file
tests the three behaviors that design commits to:
  1. A sink in a helper function fires if ANY caller in the same file
     passes it a dynamically-built value.
  2. A helper called ONLY with safe/static arguments never fires.
  3. Exactly one hop is resolved — a two-hop chain is NOT detected, and
     that's tested explicitly so it stays a documented limitation
     instead of a silent, accidental one.
"""
from pathlib import Path

from app.analyzer.python_rules import analyze_python_file

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "cross_function_python.py"


def analyze():
    return analyze_python_file(FIXTURE_PATH, "cross_function_python.py")


class TestOneHopCrossFunctionTaint:
    def test_helper_sink_fires_when_a_caller_passes_dynamic_value(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "run_query_one_hop"]
        assert matches, "run_query_one_hop should fire — it's called with a dynamic value"
        assert matches[0].rule_id == "sql-injection-string-build"

    def test_finding_is_attributed_to_the_sink_not_the_call_site(self):
        """The finding belongs to the function containing the actual
        execute() call, not the function that happens to call it."""
        findings = analyze()
        matches = [f for f in findings if f.function == "run_query_one_hop"]
        assert len(matches) == 1
        assert matches[0].function == "run_query_one_hop"
        assert matches[0].function not in ("caller_passes_dynamic_via_variable", "caller_passes_dynamic_inline")

    def test_multiple_call_sites_do_not_produce_duplicate_findings(self):
        """run_query_one_hop is called from two different places with a
        dynamic value — the sink itself should still only be reported
        once, not once per call site."""
        findings = analyze()
        matches = [f for f in findings if f.function == "run_query_one_hop"]
        assert len(matches) == 1

    def test_finding_description_notes_it_came_via_a_parameter(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "run_query_one_hop"]
        assert "parameter" in matches[0].description.lower()


class TestSafeOnlyCallersNeverSeedFalsePositives:
    def test_helper_called_only_with_static_string_does_not_fire(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "run_query_only_called_safely"]
        assert matches == []


class TestAliasPropagation:
    def test_renamed_tainted_variable_still_detected(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "alias_chain_still_detected"]
        assert matches and matches[0].rule_id == "sql-injection-string-build"

    def test_taint_cleared_by_reassignment_to_safe_literal(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "alias_cleared_by_safe_reassignment"]
        assert matches == []


class TestOneHopScopeLimit:
    def test_two_hop_chain_is_not_detected(self):
        """Documents the actual, intended scope limit: A -> B -> sink is
        NOT resolved when the taint has to cross two function-call
        boundaries, only one. If this test starts failing because a
        future change adds multi-hop resolution, that's worth updating
        deliberately — not something that should happen by accident."""
        findings = analyze()
        matches = [f for f in findings if f.function == "hop_b"]
        assert matches == []


class TestAliasOfSeededParameter:
    def test_alias_of_a_seeded_parameter_still_fires_with_via_param_note(self):
        findings = analyze()
        matches = [f for f in findings if f.function == "run_query_alias_of_seeded_param"]
        assert matches, "aliasing a seeded parameter should still be detected"
        assert "parameter" in matches[0].description.lower()


class TestCallToNonLocalFunctionIsHarmless:
    def test_calling_a_builtin_with_a_dynamic_argument_does_not_error(self):
        """print() isn't a locally-defined function in this file — the
        call-taint bookkeeping records it anyway (harmless), but it must
        never resolve to a seeded parameter, and analysis must not
        error out over a call to something undefined in this file."""
        findings = analyze()
        # No crash reaching this point is itself the primary assertion;
        # additionally confirm nothing spurious was attributed to a
        # function named "print" (which doesn't exist as a local def).
        assert all(f.function != "print" for f in findings)


class TestSeedParamsCanEndUpEmpty:
    def test_arity_mismatch_call_taint_entry_resolves_to_no_seed(self):
        """A call-taint entry that never maps to an actual parameter
        (arity mismatch) must fall back to pass 1's findings cleanly,
        not error — exercises analyze_python_file's `if not seed_params`
        early return specifically (see fixture module docstring for why
        this needs its own isolated file)."""
        path = Path(__file__).parent / "fixtures" / "cross_function_no_seed_python.py"
        findings = analyze_python_file(path, "cross_function_no_seed_python.py")
        assert findings == []
