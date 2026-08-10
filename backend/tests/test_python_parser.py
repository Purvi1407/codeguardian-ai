"""
Tests for app/parser/python_parser.py — function/class discovery and line
number accuracy, independent of the security rule engine.
"""
from pathlib import Path

from app.parser.python_parser import parse_python_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestFunctionExtraction:
    def test_extracts_top_level_and_method_functions(self):
        functions, classes, loc, error = parse_python_file(FIXTURES_DIR / "vulnerable_python.py")
        assert error == ""
        assert len(functions) > 0
        # every function in this fixture is top-level (no classes), so
        # none should be flagged as a method
        assert all(not f.is_method for f in functions)
        assert all(f.parent_class is None for f in functions)

    def test_function_names_match_fixture(self):
        functions, classes, loc, error = parse_python_file(FIXTURES_DIR / "vulnerable_python.py")
        names = {f.name for f in functions}
        assert "sql_injection_string_build__fstring" in names
        assert "weak_crypto_hash__md5" in names

    def test_method_detection_inside_class(self):
        functions, classes, loc, error = parse_python_file(FIXTURES_DIR / "safe_python.py")
        methods = [f for f in functions if f.is_method]
        assert any(m.name == "eval" and m.parent_class == "SandboxedEvaluator" for m in methods)

    def test_class_lists_its_method_names(self):
        functions, classes, loc, error = parse_python_file(FIXTURES_DIR / "safe_python.py")
        sandboxed = next(c for c in classes if c.name == "SandboxedEvaluator")
        assert "eval" in sandboxed.methods

    def test_line_numbers_are_1_indexed_and_ordered(self):
        functions, classes, loc, error = parse_python_file(FIXTURES_DIR / "vulnerable_python.py")
        for f in functions:
            assert f.start_line >= 1
            assert f.end_line >= f.start_line

    def test_loc_counts_all_lines_not_just_code(self):
        functions, classes, loc, error = parse_python_file(FIXTURES_DIR / "malformed" / "only_comments.py")
        assert loc > 0  # comments/docstrings count toward LOC


class TestArgExtraction:
    def test_function_args_are_captured(self):
        functions, classes, loc, error = parse_python_file(FIXTURES_DIR / "vulnerable_python.py")
        fn = next(f for f in functions if f.name == "sql_injection_string_build__fstring")
        assert fn.args == ["conn", "user_id"]
