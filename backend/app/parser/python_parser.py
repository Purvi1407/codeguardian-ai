import ast
from pathlib import Path
from typing import Tuple, List

from app.schemas.scan import FunctionInfo, ClassInfo


def _get_end_line(node: ast.AST) -> int:
    """Python 3.8+ sets end_lineno directly; fall back to max child lineno otherwise."""
    end = getattr(node, "end_lineno", None)
    if end is not None:
        return end
    max_line = getattr(node, "lineno", 0)
    for child in ast.walk(node):
        max_line = max(max_line, getattr(child, "lineno", 0))
    return max_line


def parse_python_file(file_path: Path) -> Tuple[List[FunctionInfo], List[ClassInfo], int, str]:
    """
    Parse a single Python file with the `ast` module.
    Returns (functions, classes, loc, error). `error` is empty string on success.
    Top-level functions get parent_class=None; methods get parent_class=<ClassName>.
    """
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return [], [], 0, f"could not read file: {e}"

    loc = len(source.splitlines())

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError as e:
        return [], [], loc, f"syntax error: {e.msg} at line {e.lineno}"

    functions: List[FunctionInfo] = []
    classes: List[ClassInfo] = []

    def make_function_info(node, parent_class=None) -> FunctionInfo:
        args = [a.arg for a in node.args.args]
        return FunctionInfo(
            name=node.name,
            start_line=node.lineno,
            end_line=_get_end_line(node),
            args=args,
            is_method=parent_class is not None,
            parent_class=parent_class,
        )

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(make_function_info(node))
        elif isinstance(node, ast.ClassDef):
            method_names = []
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append(make_function_info(child, parent_class=node.name))
                    method_names.append(child.name)
            classes.append(ClassInfo(
                name=node.name,
                start_line=node.lineno,
                end_line=_get_end_line(node),
                methods=method_names,
            ))

    return functions, classes, loc, ""
