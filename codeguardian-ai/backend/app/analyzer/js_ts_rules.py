"""
JS/TS security rules — regex-based, not AST-based.

This is a deliberate, documented tradeoff: the JS/TS parser itself
(app/parser/js_ts_parser.py) is already regex-based rather than using a
real parser like tree-sitter, so building an AST-quality rule engine on
top of it would be false precision. These rules operate on raw source
text per line, which means:
  - They can't track variables across lines the way the Python analyzer's
    same-function taint tracking does (see python_rules.py).
  - They're more prone to both false positives and false negatives than
    the Python rules.
  - They're still useful as CANDIDATE generators — Module 4 (AI) is what
    filters these down, exactly as it does for Python findings.

If this project gets another pass, swapping this for tree-sitter (which
has mature JS/TS grammars) is the highest-leverage next step, since it
would upgrade both the parser (Module 2) and this analyzer (Module 3) at
once for one integration cost.
"""
import re
from pathlib import Path
from typing import List, Tuple

from app.analyzer.rules import RULES
from app.schemas.findings import Finding

SECRET_NAME_PATTERN = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|"
    r"private[_-]?key|token)",
    re.IGNORECASE,
)

# Each entry: (rule_id, compiled pattern, "requires_dynamic" flag)
# "requires_dynamic" means: only flag if the captured argument looks like
# it's built from a variable (template literal with ${...} or string
# concatenation with +), not a fixed string literal.
SQL_CALL_PATTERN = re.compile(r"\.(query|execute|raw)\s*\(\s*(.+)$")
# Matches child_process.exec(...) / cp.exec(...) explicitly, OR a bare
# exec(...)/execSync(...) call NOT preceded by a dot — the dot exclusion
# matters because `someRegex.exec(str)` (RegExp.prototype.exec, totally
# unrelated to child_process) is extremely common in JS and would
# otherwise false-positive on nearly every file that uses regex.
EXEC_CALL_PATTERN = re.compile(
    r"(?:child_process\.exec|cp\.exec|(?<!\.)\bexec)(?:Sync|File)?\s*\(\s*(.+)$"
)
EVAL_PATTERN = re.compile(r"\beval\s*\(\s*(.+)$")
NEW_FUNCTION_PATTERN = re.compile(r"\bnew\s+Function\s*\(")
INNERHTML_PATTERN = re.compile(r"\.innerHTML\s*=\s*(.+?);?\s*$")
CREATEHASH_PATTERN = re.compile(r"createHash\(\s*['\"](md5|sha1)['\"]", re.IGNORECASE)
CORS_WILDCARD_PATTERN = re.compile(
    r"(Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]"
    r"|origin\s*:\s*['\"]\*['\"])"
)
JWT_NONE_PATTERN = re.compile(r"algorithms?\s*:\s*\[?['\"]none['\"]", re.IGNORECASE)
SECRET_ASSIGN_PATTERN = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*=\s*['\"]([^'\"]{4,})['\"]"
)


def _looks_dynamic(expr: str) -> bool:
    """Heuristic: does this expression look built from a variable rather
    than being a fixed string literal? Mirrors the intent of the Python
    analyzer's _is_dynamic_string, but on raw text instead of an AST."""
    expr = expr.strip()
    if expr.startswith("`") and "${" in expr:
        return True
    if "+" in expr and ("'" in expr or '"' in expr or "`" in expr):
        return True
    # A bare identifier (no quotes at all) being passed/assigned also
    # counts as dynamic — e.g. `.innerHTML = userInput`
    if expr and expr[0] not in "'\"`" and not expr[0].isdigit():
        return True
    return False


def analyze_js_ts_file(file_path: Path, relative_path: str) -> List[Finding]:
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    lines = source.splitlines()
    findings: List[Finding] = []

    def add(rule_id: str, lineno: int, snippet_line: str):
        meta = RULES[rule_id]
        # Small context window, not just the matched line — a multi-line
        # call (e.g. exec(`...`, callback) split across lines) would
        # otherwise starve Module 4 of the context it needs to judge
        # confidently. Same reasoning as the Python analyzer's fix.
        start = max(1, lineno - 1)
        end = min(len(lines), lineno + 5)
        window = "\n".join(lines[start - 1:end])[:600]
        findings.append(Finding(
            rule_id=rule_id,
            title=meta["title"],
            severity=meta["severity"],
            cwe=meta["cwe"],
            file=relative_path,
            function=None,  # regex scanning doesn't reliably track enclosing function
            line=lineno,
            snippet=window,
            description=meta["description"],
        ))

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue  # skip obvious comment lines to cut noise

        m = SQL_CALL_PATTERN.search(line)
        if m and _looks_dynamic(m.group(2)):
            add("sql-injection-string-build", i, line)

        m = EXEC_CALL_PATTERN.search(line)
        if m and _looks_dynamic(m.group(1)):
            add("command-injection-js-exec", i, line)

        m = EVAL_PATTERN.search(line)
        if m and _looks_dynamic(m.group(1)):
            add("dangerous-eval-exec", i, line)

        if NEW_FUNCTION_PATTERN.search(line):
            add("dangerous-eval-exec", i, line)

        m = INNERHTML_PATTERN.search(line)
        if m and _looks_dynamic(m.group(1)):
            add("xss-innerhtml-assignment", i, line)

        if CREATEHASH_PATTERN.search(line):
            add("weak-crypto-hash", i, line)

        if CORS_WILDCARD_PATTERN.search(line):
            add("insecure-cors-wildcard", i, line)

        if JWT_NONE_PATTERN.search(line):
            add("jwt-none-algorithm", i, line)

        m = SECRET_ASSIGN_PATTERN.search(line)
        if m and SECRET_NAME_PATTERN.search(m.group(1)):
            add("hardcoded-secret", i, line)

    return findings
