"""
JS/TS/TSX function and class extraction, using tree-sitter instead of
regex (see git history / README for the prior regex-based version and
why it was replaced).

Scope note: like the Python parser (app/parser/python_parser.py), this
only extracts TOP-LEVEL functions/classes and methods within top-level
classes — not functions nested inside other functions or callbacks
passed to other calls. That's a deliberate scope match with the Python
side, not a limitation specific to JS/TS: FileMetadata is meant to give
a structural overview of a file, not a full symbol table. The analyzer
(js_ts_rules.py) is different — it walks the ENTIRE tree for security
findings, since a vulnerability inside a nested callback is just as real
as one at the top level.
"""
from pathlib import Path
from typing import List, Optional, Tuple

from app.parser.ts_grammars import parse_source
from app.schemas.scan import FunctionInfo, ClassInfo

FUNCTION_NODE_TYPES = {"function_declaration", "generator_function_declaration"}
FUNCTION_VALUE_TYPES = {"arrow_function", "function_expression", "generator_function"}


def _unwrap_export(node):
    """`export function foo() {}` / `export default class X {}` wrap the
    real declaration one level down. Unwrap so callers see the same node
    types whether or not `export` was present."""
    if node.type == "export_statement":
        inner = node.child_by_field_name("declaration")
        if inner is not None:
            return inner
    return node


def _param_name(param_node) -> str:
    """Best-effort name for a single parameter node. Falls back to the
    raw source text for patterns that don't reduce to one clean
    identifier (destructuring, defaults) rather than dropping them."""
    if param_node.type == "identifier":
        return param_node.text.decode("utf-8", errors="replace")
    if param_node.type == "assignment_pattern":
        left = param_node.child_by_field_name("left")
        if left is not None:
            return _param_name(left)
    if param_node.type == "rest_pattern":
        for child in param_node.children:
            if child.type == "identifier":
                return "..." + child.text.decode("utf-8", errors="replace")
    if param_node.type in ("required_parameter", "optional_parameter"):
        # TypeScript-typed parameter: pattern field holds the identifier
        pattern = param_node.child_by_field_name("pattern")
        if pattern is not None:
            return _param_name(pattern)
    # object/array destructuring or anything else: fall back to raw text,
    # truncated so a large destructured param doesn't blow up output
    text = param_node.text.decode("utf-8", errors="replace").strip()
    return text[:60]


def _extract_params(params_node) -> List[str]:
    if params_node is None:
        return []
    names = []
    for child in params_node.children:
        if child.type in ("(", ")", ","):
            continue
        names.append(_param_name(child))
    return names


def _function_info_from_declaration(node, parent_class: Optional[str] = None) -> Optional[FunctionInfo]:
    name_node = node.child_by_field_name("name")
    params_node = node.child_by_field_name("parameters")
    name = name_node.text.decode("utf-8", errors="replace") if name_node else "<anonymous>"
    return FunctionInfo(
        name=name,
        start_line=node.start_point[0] + 1,
        end_line=node.end_point[0] + 1,
        args=_extract_params(params_node),
        is_method=parent_class is not None,
        parent_class=parent_class,
    )


def _function_info_from_variable(declarator_node) -> Optional[FunctionInfo]:
    """Handles `const foo = (a, b) => {...}` / `const foo = function(a) {...}`."""
    name_node = declarator_node.child_by_field_name("name")
    value_node = declarator_node.child_by_field_name("value")
    if name_node is None or value_node is None or value_node.type not in FUNCTION_VALUE_TYPES:
        return None
    params_node = value_node.child_by_field_name("parameters")
    return FunctionInfo(
        name=name_node.text.decode("utf-8", errors="replace"),
        start_line=declarator_node.start_point[0] + 1,
        end_line=declarator_node.end_point[0] + 1,
        args=_extract_params(params_node),
        is_method=False,
        parent_class=None,
    )


def _methods_from_class_body(body_node, class_name: str) -> Tuple[List[FunctionInfo], List[str]]:
    methods: List[FunctionInfo] = []
    method_names: List[str] = []
    for member in body_node.children:
        if member.type == "method_definition":
            info = _function_info_from_declaration(member, parent_class=class_name)
            if info:
                methods.append(info)
                method_names.append(info.name)
        elif member.type == "field_definition":
            # Class field assigned an arrow function, e.g.
            # `handleClick = () => {...}` — a very common React pattern.
            value_node = member.child_by_field_name("value")
            prop_node = member.child_by_field_name("property")
            if value_node is not None and value_node.type in FUNCTION_VALUE_TYPES and prop_node is not None:
                params_node = value_node.child_by_field_name("parameters")
                name = prop_node.text.decode("utf-8", errors="replace")
                methods.append(FunctionInfo(
                    name=name,
                    start_line=member.start_point[0] + 1,
                    end_line=member.end_point[0] + 1,
                    args=_extract_params(params_node),
                    is_method=True,
                    parent_class=class_name,
                ))
                method_names.append(name)
    return methods, method_names


def extract_top_level_function_params(root_node) -> dict:
    """Top-level function/const-arrow name -> its ordered parameter
    names, as plain strings. Used by analyzer/js_ts_rules.py for bounded
    cross-function taint seeding — kept here rather than duplicated in
    the analyzer, since it's the same top-level-declaration walk
    parse_js_ts_file already does, just returning names+params instead
    of full FunctionInfo objects. Takes a tree-sitter root node directly
    (not a file path) since the analyzer already has a parsed tree from
    its own read of the file and doesn't need to re-read/re-parse it."""
    result = {}
    for raw_node in root_node.children:
        node = _unwrap_export(raw_node)

        if node.type in FUNCTION_NODE_TYPES:
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                params_node = node.child_by_field_name("parameters")
                result[name_node.text.decode("utf-8", errors="replace")] = _extract_params(params_node)

        elif node.type in ("lexical_declaration", "variable_declaration"):
            for declarator in node.children:
                if declarator.type != "variable_declarator":
                    continue
                name_node = declarator.child_by_field_name("name")
                value_node = declarator.child_by_field_name("value")
                if name_node is None or value_node is None or value_node.type not in FUNCTION_VALUE_TYPES:
                    continue
                params_node = value_node.child_by_field_name("parameters")
                result[name_node.text.decode("utf-8", errors="replace")] = _extract_params(params_node)

    return result


def parse_js_ts_file(file_path: Path) -> Tuple[List[FunctionInfo], List[ClassInfo], int, str]:
    try:
        source_text = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return [], [], 0, f"could not read file: {e}"

    loc = len(source_text.splitlines())
    suffix = file_path.suffix.lstrip(".")

    try:
        tree = parse_source(source_text.encode("utf-8"), suffix)
    except Exception as e:
        return [], [], loc, f"parse error: {e}"

    if tree.root_node.has_error:
        # tree-sitter is error-tolerant by design — it still produces a
        # tree for invalid syntax, with ERROR nodes marking the bad
        # parts. We don't want to silently analyze a tree built from
        # broken input, so we report it the same way the Python parser
        # reports a SyntaxError, and the analyzer skips files with an
        # error (see scan_service.py).
        return [], [], loc, "syntax error: file contains invalid JS/TS/TSX that tree-sitter could not fully parse"

    functions: List[FunctionInfo] = []
    classes: List[ClassInfo] = []

    for raw_node in tree.root_node.children:
        node = _unwrap_export(raw_node)

        if node.type in FUNCTION_NODE_TYPES:
            info = _function_info_from_declaration(node)
            if info:
                functions.append(info)

        elif node.type in ("lexical_declaration", "variable_declaration"):
            for declarator in node.children:
                if declarator.type == "variable_declarator":
                    info = _function_info_from_variable(declarator)
                    if info:
                        functions.append(info)

        elif node.type == "class_declaration":
            name_node = node.child_by_field_name("name")
            body_node = node.child_by_field_name("body")
            class_name = name_node.text.decode("utf-8", errors="replace") if name_node else "<anonymous>"
            if body_node is not None:
                methods, method_names = _methods_from_class_body(body_node, class_name)
                functions.extend(methods)
                classes.append(ClassInfo(
                    name=class_name,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    methods=method_names,
                ))

    return functions, classes, loc, ""
