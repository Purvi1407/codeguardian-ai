"""
Tests for app/services/finding_filters.py — pure functions, no network,
no mocking needed.
"""
from app.schemas.findings import Finding
from app.schemas.scan import FileMetadata
from app.services.finding_filters import (
    build_language_lookup,
    filter_files_by_language,
    filter_findings,
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


def make_file(path="app.py", language="Python"):
    return FileMetadata(path=path, language=language)


class TestBuildLanguageLookup:
    def test_maps_path_to_language(self):
        files = [make_file("a.py", "Python"), make_file("b.js", "JavaScript")]
        lookup = build_language_lookup(files)
        assert lookup == {"a.py": "Python", "b.js": "JavaScript"}

    def test_empty_files_list_gives_empty_lookup(self):
        assert build_language_lookup([]) == {}


class TestFilterFilesByLanguage:
    def test_no_filter_returns_all_files_unchanged(self):
        files = [make_file("a.py", "Python"), make_file("b.js", "JavaScript")]
        assert filter_files_by_language(files, None) == files

    def test_empty_list_filter_returns_all_files(self):
        files = [make_file("a.py", "Python")]
        assert filter_files_by_language(files, []) == files

    def test_filters_to_matching_language_only(self):
        files = [make_file("a.py", "Python"), make_file("b.js", "JavaScript")]
        result = filter_files_by_language(files, ["Python"])
        assert [f.path for f in result] == ["a.py"]

    def test_case_insensitive(self):
        files = [make_file("a.py", "Python")]
        result = filter_files_by_language(files, ["python"])
        assert len(result) == 1

    def test_multiple_languages(self):
        files = [make_file("a.py", "Python"), make_file("b.js", "JavaScript"), make_file("c.ts", "TypeScript")]
        result = filter_files_by_language(files, ["Python", "TypeScript"])
        assert {f.path for f in result} == {"a.py", "c.ts"}


class TestFilterFindingsBySeverity:
    def test_no_filter_returns_everything(self):
        findings = [make_finding(severity="high"), make_finding(severity="low")]
        assert filter_findings(findings) == findings

    def test_filters_to_matching_severity(self):
        findings = [make_finding(severity="high"), make_finding(severity="low")]
        result = filter_findings(findings, severity=["high"])
        assert len(result) == 1
        assert result[0].severity == "high"

    def test_case_insensitive(self):
        findings = [make_finding(severity="high")]
        result = filter_findings(findings, severity=["HIGH"])
        assert len(result) == 1

    def test_multiple_severities(self):
        findings = [make_finding(severity="high"), make_finding(severity="medium"), make_finding(severity="low")]
        result = filter_findings(findings, severity=["high", "low"])
        assert {f.severity for f in result} == {"high", "low"}


class TestFilterFindingsByRule:
    def test_filters_to_matching_rule_id(self):
        findings = [make_finding(rule_id="sql-injection-string-build"), make_finding(rule_id="weak-crypto-hash")]
        result = filter_findings(findings, rules=["weak-crypto-hash"])
        assert len(result) == 1
        assert result[0].rule_id == "weak-crypto-hash"

    def test_rule_filter_is_exact_match_not_substring(self):
        findings = [make_finding(rule_id="sql-injection-string-build")]
        result = filter_findings(findings, rules=["sql-injection"])  # partial, must not match
        assert result == []


class TestFilterFindingsByLanguage:
    def test_filters_findings_using_language_lookup(self):
        findings = [make_finding(file="a.py"), make_finding(file="b.js")]
        lookup = {"a.py": "Python", "b.js": "JavaScript"}
        result = filter_findings(findings, language_lookup=lookup, languages=["Python"])
        assert len(result) == 1
        assert result[0].file == "a.py"

    def test_no_language_lookup_provided_skips_language_filtering(self):
        """If the caller forgot to pass language_lookup, filtering by
        language must not crash — it should just not filter (fail open,
        not fail closed, since silently returning zero findings due to
        a caller bug would be worse than not filtering)."""
        findings = [make_finding(file="a.py")]
        result = filter_findings(findings, languages=["Python"])
        assert result == findings

    def test_finding_for_unknown_file_excluded_when_language_filter_active(self):
        findings = [make_finding(file="unknown.py")]
        lookup = {}  # doesn't know about unknown.py
        result = filter_findings(findings, language_lookup=lookup, languages=["Python"])
        assert result == []


class TestFilterFindingsBySearch:
    def test_matches_in_file_path(self):
        findings = [make_finding(file="app/routes/users.py"), make_finding(file="app/routes/admin.py")]
        result = filter_findings(findings, search="users")
        assert len(result) == 1
        assert "users" in result[0].file

    def test_matches_in_description(self):
        findings = [make_finding(description="Uses a weak hash algorithm")]
        result = filter_findings(findings, search="weak hash")
        assert len(result) == 1

    def test_matches_in_snippet(self):
        findings = [make_finding(snippet="hashlib.md5(data)")]
        result = filter_findings(findings, search="md5")
        assert len(result) == 1

    def test_matches_in_rule_id(self):
        findings = [make_finding(rule_id="hardcoded-secret")]
        result = filter_findings(findings, search="hardcoded")
        assert len(result) == 1

    def test_matches_in_function_name(self):
        findings = [make_finding(function="login_handler")]
        result = filter_findings(findings, search="login")
        assert len(result) == 1

    def test_finding_with_no_function_does_not_crash_search(self):
        findings = [make_finding(function=None)]
        result = filter_findings(findings, search="anything")
        assert result == []  # no match, but importantly: no crash

    def test_case_insensitive(self):
        findings = [make_finding(file="Admin.py")]
        result = filter_findings(findings, search="admin")
        assert len(result) == 1

    def test_no_match_returns_empty(self):
        findings = [make_finding(file="app.py")]
        result = filter_findings(findings, search="nonexistent_xyz")
        assert result == []


class TestCombinedFilters:
    def test_multiple_filters_apply_together_as_and(self):
        findings = [
            make_finding(severity="high", rule_id="sql-injection-string-build", file="a.py"),
            make_finding(severity="high", rule_id="weak-crypto-hash", file="a.py"),
            make_finding(severity="low", rule_id="sql-injection-string-build", file="a.py"),
        ]
        result = filter_findings(findings, severity=["high"], rules=["sql-injection-string-build"])
        assert len(result) == 1
        assert result[0].severity == "high"
        assert result[0].rule_id == "sql-injection-string-build"

    def test_all_filters_together(self):
        findings = [
            make_finding(severity="high", rule_id="sql-injection-string-build", file="a.py", description="user id injection"),
            make_finding(severity="high", rule_id="sql-injection-string-build", file="b.js", description="user id injection"),
            make_finding(severity="low", rule_id="sql-injection-string-build", file="a.py", description="user id injection"),
        ]
        lookup = {"a.py": "Python", "b.js": "JavaScript"}
        result = filter_findings(
            findings,
            language_lookup=lookup,
            severity=["high"],
            languages=["Python"],
            rules=["sql-injection-string-build"],
            search="user id",
        )
        assert len(result) == 1
        assert result[0].file == "a.py"
