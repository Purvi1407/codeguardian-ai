"""
Tests for app/parser/js_ts_parser.py — function/class discovery and line
number accuracy, independent of the security rule engine. Mirrors
test_python_parser.py.
"""
from pathlib import Path

from app.parser.js_ts_parser import parse_js_ts_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestFunctionExtraction:
    def test_extracts_function_declarations(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "vulnerable_js.js")
        assert error == ""
        names = {f.name for f in functions}
        assert "sql_injection_string_build__template" in names

    def test_extracts_arrow_function_assigned_to_const(self):
        """The old regex parser could handle this case too (it had a
        dedicated pattern for it) — this confirms the tree-sitter
        rewrite didn't regress it."""
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "vulnerable_js.js")
        arrow_fn = next((f for f in functions if f.name == "sql_injection_string_build__arrow_function"), None)
        assert arrow_fn is not None
        assert arrow_fn.is_method is False

    def test_extracts_class_and_its_methods(self):
        """The old regex parser could NOT do this at all — no method
        extraction, no is_method/parent_class attribution. This is the
        parser-side headline improvement of Phase 2."""
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "vulnerable_js.js")
        cls = next((c for c in classes if c.name == "VulnerableService"), None)
        assert cls is not None
        assert "sql_injection_string_build__class_method" in cls.methods

        method = next(
            (f for f in functions if f.name == "sql_injection_string_build__class_method"), None
        )
        assert method is not None
        assert method.is_method is True
        assert method.parent_class == "VulnerableService"

    def test_line_numbers_are_1_indexed_and_ordered(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "vulnerable_js.js")
        for f in functions:
            assert f.start_line >= 1
            assert f.end_line >= f.start_line

    def test_end_line_is_accurate_not_same_as_start_line(self):
        """The single biggest documented limitation of the old regex
        parser: 'end_line=i, # regex approach can't reliably find the
        closing brace'. This is the direct regression test for that."""
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "vulnerable_js.js")
        fn = next(f for f in functions if f.name == "sql_injection_string_build__template")
        assert fn.end_line > fn.start_line


class TestArgExtraction:
    def test_function_args_are_captured(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "vulnerable_js.js")
        fn = next(f for f in functions if f.name == "sql_injection_string_build__template")
        assert fn.args == ["id"]


class TestExportUnwrapping:
    def test_export_function_is_still_detected(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "vulnerable_ts.ts")
        names = {f.name for f in functions}
        assert "sql_injection_string_build__typed_param" in names


class TestTypeScriptGrammar:
    def test_ts_file_parses_without_error(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "vulnerable_ts.ts")
        assert error == ""

    def test_ts_class_and_typed_method_extracted(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "vulnerable_ts.ts")
        cls = next((c for c in classes if c.name == "TypedService"), None)
        assert cls is not None
        assert "weak_crypto_hash__typed_method" in cls.methods


class TestExportVariants:
    """`export function`, `export default function`, `export const ... =`,
    and `export class` must all unwrap to the same node types a
    non-exported declaration would produce."""

    def test_export_function_declaration(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "parser_features_js.js")
        assert error == ""
        assert "exportedFunction" in {f.name for f in functions}

    def test_export_default_function_declaration(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "parser_features_js.js")
        assert "exportedDefaultFunction" in {f.name for f in functions}

    def test_export_const_arrow_function(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "parser_features_js.js")
        assert "exportedArrow" in {f.name for f in functions}

    def test_export_class(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "parser_features_js.js")
        assert "ExportedClass" in {c.name for c in classes}


class TestParameterVariants:
    def test_default_and_rest_parameters(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "parser_features_js.js")
        fn = next(f for f in functions if f.name == "paramsWithDefaultsAndRest")
        assert fn.args == ["a", "b", "...rest"]

    def test_ts_typed_required_optional_and_default_parameters(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "parser_features_ts.ts")
        assert error == ""
        fn = next(f for f in functions if f.name == "typedParams")
        assert fn.args == ["a", "b", "c"]


class TestClassFieldArrowFunctionMethod:
    """A class field assigned an arrow function (`handleClick = () => {}`)
    is a different node shape (field_definition) than a normal method
    (method_definition) — a very common React pattern that needs its own
    extraction path."""

    def test_arrow_field_is_extracted_as_a_method(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "parser_features_js.js")
        assert error == ""
        fn = next((f for f in functions if f.name == "handleClick"), None)
        assert fn is not None
        assert fn.is_method is True
        assert fn.parent_class == "ComponentWithArrowFieldMethod"
        assert fn.args == ["event"]

    def test_class_lists_the_arrow_field_method_by_name(self):
        functions, classes, loc, error = parse_js_ts_file(FIXTURES_DIR / "parser_features_js.js")
        cls = next(c for c in classes if c.name == "ComponentWithArrowFieldMethod")
        assert "handleClick" in cls.methods
