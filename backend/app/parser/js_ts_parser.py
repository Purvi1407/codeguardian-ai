import re
from pathlib import Path
from typing import Tuple, List

from app.schemas.scan import FunctionInfo, ClassInfo

# Deliberately simple regex patterns for the MVP. This will under-detect
# (e.g. arrow functions assigned inside objects, class properties as
# functions) but is enough to prove the pipeline end-to-end without pulling
# in tree-sitter. Flagged in README as a known limitation / next step.
FUNCTION_PATTERNS = [
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\("),
    re.compile(r"^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"),
]
CLASS_PATTERN = re.compile(r"^\s*(?:export\s+)?class\s+(\w+)")


def parse_js_ts_file(file_path: Path) -> Tuple[List[FunctionInfo], List[ClassInfo], int, str]:
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return [], [], 0, f"could not read file: {e}"

    lines = source.splitlines()
    loc = len(lines)
    functions: List[FunctionInfo] = []
    classes: List[ClassInfo] = []

    for i, line in enumerate(lines, start=1):
        for pattern in FUNCTION_PATTERNS:
            m = pattern.match(line)
            if m:
                functions.append(FunctionInfo(
                    name=m.group(1),
                    start_line=i,
                    end_line=i,  # regex approach can't reliably find the closing brace
                    args=[],
                    is_method=False,
                    parent_class=None,
                ))
                break
        m = CLASS_PATTERN.match(line)
        if m:
            classes.append(ClassInfo(
                name=m.group(1),
                start_line=i,
                end_line=i,
                methods=[],
            ))

    return functions, classes, loc, ""
