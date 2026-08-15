"""
Tests for app/services/baseline.py — pure logic + isolated temp-file I/O,
no network needed.
"""
from app.schemas.findings import Finding
from app.services.baseline import (
    fingerprint,
    build_baseline,
    write_baseline,
    load_baseline_fingerprints,
    filter_new_findings,
)


def make_finding(**overrides):
    defaults = dict(
        rule_id="sql-injection-string-build",
        title="SQL query built with string formatting",
        severity="high",
        cwe="CWE-89",
        file="app.py",
        function="handler",
        line=10,
        snippet="cursor.execute(query)",
        description="A SQL query is built dynamically.",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestFingerprint:
    def test_same_rule_file_function_snippet_gives_same_fingerprint(self):
        f1 = make_finding(line=10)
        f2 = make_finding(line=99)  # only line differs
        assert fingerprint(f1) == fingerprint(f2)

    def test_different_line_alone_does_not_change_fingerprint(self):
        """The whole point of not keying on line: an unrelated edit
        earlier in the file that shifts this finding's line number must
        not make the baseline stop recognizing it."""
        f1 = make_finding(line=10)
        f2 = make_finding(line=11)
        assert fingerprint(f1) == fingerprint(f2)

    def test_different_snippet_gives_different_fingerprint(self):
        f1 = make_finding(snippet="cursor.execute(query)")
        f2 = make_finding(snippet="cursor.execute(other_query)")
        assert fingerprint(f1) != fingerprint(f2)

    def test_different_rule_id_gives_different_fingerprint(self):
        f1 = make_finding(rule_id="sql-injection-string-build")
        f2 = make_finding(rule_id="weak-crypto-hash")
        assert fingerprint(f1) != fingerprint(f2)

    def test_different_file_gives_different_fingerprint(self):
        f1 = make_finding(file="a.py")
        f2 = make_finding(file="b.py")
        assert fingerprint(f1) != fingerprint(f2)

    def test_different_function_gives_different_fingerprint(self):
        f1 = make_finding(function="handler_a")
        f2 = make_finding(function="handler_b")
        assert fingerprint(f1) != fingerprint(f2)

    def test_none_function_does_not_crash(self):
        f = make_finding(function=None)
        assert isinstance(fingerprint(f), str)


class TestBuildBaseline:
    def test_empty_findings_gives_empty_fingerprints(self):
        baseline = build_baseline([])
        assert baseline["fingerprints"] == []
        assert baseline["format_version"] == 1

    def test_duplicate_findings_deduplicated(self):
        f1 = make_finding(line=10)
        f2 = make_finding(line=99)  # same fingerprint as f1
        baseline = build_baseline([f1, f2])
        assert len(baseline["fingerprints"]) == 1

    def test_fingerprints_are_sorted_for_deterministic_diffs(self):
        """A committed baseline file should produce a clean git diff
        when it changes — sorted output means adding one finding only
        changes one line, not the whole file's ordering."""
        findings = [make_finding(rule_id=f"rule-{i}") for i in range(5)]
        baseline = build_baseline(findings)
        assert baseline["fingerprints"] == sorted(baseline["fingerprints"])


class TestWriteAndLoadBaseline:
    def test_write_then_load_roundtrips(self, tmp_path):
        path = tmp_path / "baseline.json"
        findings = [make_finding(rule_id="sql-injection-string-build")]
        write_baseline(findings, path)

        loaded = load_baseline_fingerprints(path)
        assert loaded == {fingerprint(findings[0])}

    def test_missing_file_returns_empty_set_not_error(self, tmp_path):
        path = tmp_path / "does_not_exist.json"
        assert load_baseline_fingerprints(path) == set()

    def test_corrupted_json_returns_empty_set_not_error(self, tmp_path):
        path = tmp_path / "corrupt.json"
        path.write_text("{not valid json", encoding="utf-8")
        assert load_baseline_fingerprints(path) == set()

    def test_json_with_wrong_shape_returns_empty_set(self, tmp_path):
        path = tmp_path / "wrong_shape.json"
        path.write_text('["just", "a", "list"]', encoding="utf-8")
        assert load_baseline_fingerprints(path) == set()

    def test_fingerprints_key_with_wrong_type_returns_empty_set(self, tmp_path):
        path = tmp_path / "bad_fingerprints.json"
        path.write_text('{"format_version": 1, "fingerprints": "not-a-list"}', encoding="utf-8")
        assert load_baseline_fingerprints(path) == set()

    def test_non_string_entries_in_fingerprints_are_dropped(self, tmp_path):
        path = tmp_path / "mixed.json"
        path.write_text('{"format_version": 1, "fingerprints": ["abc", 123, null]}', encoding="utf-8")
        assert load_baseline_fingerprints(path) == {"abc"}


class TestFilterNewFindings:
    def test_no_baseline_file_returns_all_findings(self, tmp_path):
        path = tmp_path / "does_not_exist.json"
        findings = [make_finding()]
        assert filter_new_findings(findings, path) == findings

    def test_finding_in_baseline_is_excluded(self, tmp_path):
        path = tmp_path / "baseline.json"
        findings = [make_finding()]
        write_baseline(findings, path)

        result = filter_new_findings(findings, path)
        assert result == []

    def test_finding_not_in_baseline_is_kept(self, tmp_path):
        path = tmp_path / "baseline.json"
        old_finding = make_finding(rule_id="weak-crypto-hash")
        write_baseline([old_finding], path)

        new_finding = make_finding(rule_id="sql-injection-string-build")
        result = filter_new_findings([old_finding, new_finding], path)
        assert result == [new_finding]

    def test_baseline_matches_regardless_of_line_shift(self, tmp_path):
        """The end-to-end version of the fingerprint-stability tests
        above: a finding baselined at one line is still recognized
        after an edit shifts it to a different line."""
        path = tmp_path / "baseline.json"
        original = make_finding(line=10)
        write_baseline([original], path)

        shifted = make_finding(line=50)  # same rule/file/function/snippet, different line
        result = filter_new_findings([shifted], path)
        assert result == []
