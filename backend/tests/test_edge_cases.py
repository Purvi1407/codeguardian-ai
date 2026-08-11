"""
Robustness tests: the analyzer and parser must degrade gracefully on
input that isn't clean, well-formed Python — never crash the scan.
"""
from pathlib import Path

from app.analyzer.python_rules import analyze_python_file
from app.analyzer.js_ts_rules import analyze_js_ts_file
from app.parser.python_parser import parse_python_file
from app.parser.js_ts_parser import parse_js_ts_file

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "malformed"


class TestSyntaxErrorHandling:
    def test_analyzer_returns_empty_list_not_exception(self):
        """A file with invalid syntax must not crash the whole scan —
        one bad file shouldn't take down analysis of the rest of the
        repo."""
        path = FIXTURES_DIR / "syntax_error.py"
        findings = analyze_python_file(path, "syntax_error.py")
        assert findings == []

    def test_parser_reports_error_instead_of_raising(self):
        path = FIXTURES_DIR / "syntax_error.py"
        functions, classes, loc, error = parse_python_file(path)
        assert functions == []
        assert classes == []
        assert error != ""
        assert "syntax error" in error.lower()


class TestEmptyFile:
    def test_analyzer_handles_empty_file(self):
        path = FIXTURES_DIR / "empty.py"
        findings = analyze_python_file(path, "empty.py")
        assert findings == []

    def test_parser_handles_empty_file(self):
        path = FIXTURES_DIR / "empty.py"
        functions, classes, loc, error = parse_python_file(path)
        assert functions == []
        assert classes == []
        assert error == ""
        assert loc == 0


class TestCommentsOnlyFile:
    def test_file_with_no_statements_yields_nothing(self):
        path = FIXTURES_DIR / "only_comments.py"
        findings = analyze_python_file(path, "only_comments.py")
        assert findings == []

        functions, classes, loc, error = parse_python_file(path)
        assert functions == []
        assert classes == []
        assert error == ""


class TestUnicodeContent:
    def test_non_ascii_identifiers_and_emoji_dont_crash(self):
        """Non-ASCII function names and emoji in string literals must
        not break parsing or line-number tracking."""
        path = FIXTURES_DIR / "unicode_content.py"
        functions, classes, loc, error = parse_python_file(path)
        assert error == ""
        assert len(functions) == 2

    def test_detection_still_works_alongside_unicode_content(self):
        """A real vulnerability sitting near non-ASCII content must still
        be caught — confirms unicode handling doesn't silently shift
        line numbers or desync the visitor."""
        path = FIXTURES_DIR / "unicode_content.py"
        findings = analyze_python_file(path, "unicode_content.py")
        rule_ids = {f.rule_id for f in findings}
        assert "weak-crypto-hash" in rule_ids


class TestJsTsSyntaxErrorHandling:
    def test_analyzer_returns_empty_list_not_exception(self):
        path = FIXTURES_DIR / "syntax_error.js"
        findings = analyze_js_ts_file(path, "syntax_error.js")
        assert findings == []

    def test_parser_reports_error_instead_of_raising(self):
        path = FIXTURES_DIR / "syntax_error.js"
        functions, classes, loc, error = parse_js_ts_file(path)
        assert functions == []
        assert classes == []
        assert error != ""
        assert "syntax error" in error.lower()


class TestJsTsEmptyFile:
    def test_analyzer_handles_empty_file(self):
        path = FIXTURES_DIR / "empty.js"
        findings = analyze_js_ts_file(path, "empty.js")
        assert findings == []

    def test_parser_handles_empty_file(self):
        path = FIXTURES_DIR / "empty.js"
        functions, classes, loc, error = parse_js_ts_file(path)
        assert functions == []
        assert classes == []
        assert error == ""


class TestJsTsCommentsOnlyFile:
    def test_file_with_no_statements_yields_nothing(self):
        path = FIXTURES_DIR / "only_comments.js"
        findings = analyze_js_ts_file(path, "only_comments.js")
        assert findings == []

        functions, classes, loc, error = parse_js_ts_file(path)
        assert functions == []
        assert classes == []
        assert error == ""


class TestJsTsUnicodeContent:
    def test_non_ascii_identifiers_and_emoji_dont_crash(self):
        path = FIXTURES_DIR / "unicode_content.js"
        functions, classes, loc, error = parse_js_ts_file(path)
        assert error == ""
        assert len(functions) == 2

    def test_detection_still_works_alongside_unicode_content(self):
        path = FIXTURES_DIR / "unicode_content.js"
        findings = analyze_js_ts_file(path, "unicode_content.js")
        rule_ids = {f.rule_id for f in findings}
        assert "weak-crypto-hash" in rule_ids


class TestJsTsNonexistentFile:
    def test_missing_file_reports_error_not_exception(self):
        path = FIXTURES_DIR / "this_file_does_not_exist.js"
        functions, classes, loc, error = parse_js_ts_file(path)
        assert functions == []
        assert classes == []
        assert error != ""

    def test_analyzer_handles_missing_file_gracefully(self):
        path = FIXTURES_DIR / "this_file_does_not_exist.js"
        findings = analyze_js_ts_file(path, "this_file_does_not_exist.js")
        assert findings == []


class TestNonexistentFile:
    def test_missing_file_reports_error_not_exception(self):
        path = FIXTURES_DIR / "this_file_does_not_exist.py"
        functions, classes, loc, error = parse_python_file(path)
        assert functions == []
        assert classes == []
        assert error != ""

    def test_analyzer_handles_missing_file_gracefully(self):
        path = FIXTURES_DIR / "this_file_does_not_exist.py"
        findings = analyze_python_file(path, "this_file_does_not_exist.py")
        assert findings == []
