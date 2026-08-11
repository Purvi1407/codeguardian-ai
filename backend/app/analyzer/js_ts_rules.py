"""
JS/TS/TSX security rules — AST-based via tree-sitter (Phase 2).

This replaces the earlier regex-based version (see git history / README
"Phase 2" section for the full writeup of why and what changed). The
core upgrade: this walks a real parse tree instead of scanning raw
source lines, which means:
  - It tracks same-function variable taint the way the Python analyzer
    does (see `_dynamic_str_vars` below) — a query built into a local
    variable and passed by name is now caught, not just a query built
    directly inline in the call.
  - Findings carry the real enclosing function name (`Finding.function`),
    which the old regex version couldn't determine and always left None.
  - Structural false positives the regex version had to special-case by
    hand (e.g. `someRegex.exec(str)` vs `child_process.exec(cmd)`) are
    now resolved by node type/shape instead of a negative-lookbehind
    regex hack — the AST simply can't confuse a bare identifier call
    with a method call on an object.

Deliberately still pattern-based, not full taint tracking: a rule firing
means "this looks worth a human/AI second look", same philosophy as the
Python analyzer. Cross-function tracking (a tainted value passed as an
argument into another function) is out of scope here too, for the same
reason it's out of scope on the Python side — see python_rules.py.
"""
import re
from pathlib import Path
from typing import List, Optional

from app.analyzer.rules import RULES
from app.parser.ts_grammars import parse_source
from app.schemas.findings import Finding

SECRET_NAME_PATTERN = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|"
    r"private[_-]?key|token)",
    re.IGNORECASE,
)

FUNCTION_SCOPE_TYPES = {
    "function_declaration", "function_expression", "arrow_function",
    "generator_function_declaration", "generator_function", "method_definition",
}

SQL_METHOD_NAMES = {"query", "execute", "raw"}
EXEC_METHOD_NAMES = {"exec", "execSync", "execFile", "execFileSync"}
EXEC_CHILD_PROCESS_OBJECTS = {"child_process", "cp"}
HEADER_SETTER_NAMES = {"setHeader", "header", "set"}


class JsTsSecurityVisitor:
    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source_lines = source.splitlines()
        self.findings: List[Finding] = []
        self._func_stack: List[str] = []
        # Same intent as python_rules.py's _dynamic_str_vars: tracks
        # {var_name: True} for variables assigned a dynamically-built
        # string within the CURRENT function scope, reset on entry to
        # every function/method/arrow function.
        self._dynamic_str_vars: dict = {}
        self._var_scope_stack: List[dict] = []

    # -- generic helpers ----------------------------------------------------

    def _text(self, node) -> str:
        return node.text.decode("utf-8", errors="replace") if node is not None else ""

    def _line_of(self, node) -> int:
        return node.start_point[0] + 1

    def _current_function(self) -> Optional[str]:
        return self._func_stack[-1] if self._func_stack else None

    def _snippet(self, lineno: int) -> str:
        start = max(1, lineno - 1)
        end = min(len(self.source_lines), lineno + 5)
        return "\n".join(self.source_lines[start - 1:end])[:600]

    def _add(self, rule_id: str, lineno: int):
        meta = RULES[rule_id]
        self.findings.append(Finding(
            rule_id=rule_id,
            title=meta["title"],
            severity=meta["severity"],
            cwe=meta["cwe"],
            file=self.file_path,
            function=self._current_function(),
            line=lineno,
            snippet=self._snippet(lineno),
            description=meta["description"],
        ))

    # -- node-shape helpers ---------------------------------------------

    def _member_property(self, node) -> Optional[str]:
        """node.type == 'member_expression' -> the '.prop' name."""
        prop = node.child_by_field_name("property")
        return self._text(prop) if prop is not None else None

    def _member_root_identifier(self, node) -> Optional[str]:
        """Root identifier at the base of a (possibly chained) member
        expression, e.g. `a.b.c` -> 'a'. Returns None if it doesn't
        bottom out in a plain identifier (e.g. `require('x').exec(...)`,
        where the base is a call_expression) — deliberately conservative,
        same tradeoff the old regex made for the same construct."""
        obj = node.child_by_field_name("object")
        while obj is not None and obj.type == "member_expression":
            obj = obj.child_by_field_name("object")
        if obj is not None and obj.type == "identifier":
            return self._text(obj)
        return None

    def _string_literal_value(self, node) -> Optional[str]:
        """If node is a plain string literal, return its inner text (no
        quotes). Returns None for anything else, including template
        strings — a caller that wants to allow template strings with no
        substitutions should check that separately."""
        if node is None or node.type != "string":
            return None
        for c in node.children:
            if c.type == "string_fragment":
                return self._text(c)
        return ""

    def _is_dynamic_string(self, node) -> bool:
        """True if `node` builds a string dynamically: a template
        literal with a `${...}` substitution, or string concatenation
        via `+`. Mirrors python_rules.py's _is_dynamic_string."""
        if node is None:
            return False
        if node.type == "template_string":
            return any(c.type == "template_substitution" for c in node.children)
        if node.type == "binary_expression":
            op = node.child_by_field_name("operator")
            return op is not None and op.type == "+"
        return False

    def _is_literal(self, node) -> bool:
        return node is not None and node.type in (
            "string", "number", "true", "false", "null", "undefined",
        )

    def _looks_dynamic_broad(self, node) -> bool:
        """Deliberately broader than _is_dynamic_string: true for
        anything that isn't a plain literal, including a bare identifier
        with no local taint tracking (e.g. a function parameter used
        directly). Used only for the innerHTML/XSS check.

        Why the asymmetry with SQL/exec (which use the narrower
        `_is_dynamic_string` + `_is_tainted_identifier` check)? Those
        sinks are called constantly with plainly-safe arguments in real
        code (`db.query(SOME_CONSTANT_QUERY)` where the "identifier" is
        actually a module-level constant, `exec(builtCommand)` where
        builtCommand was validated upstream) — flagging every bare
        identifier there would make the rule too noisy to be useful.
        innerHTML doesn't have that problem: assigning ANY non-literal
        value to innerHTML — including a bare parameter — is precisely
        the XSS-relevant question, and `function render(x) { el.innerHTML
        = x; }` is the single most common real-world instance of this
        bug. Matches the older regex version's behavior, which treated
        any unquoted right-hand side as "dynamic" for this same rule.
        """
        return node is not None and not self._is_literal(node)

    def _is_tainted_identifier(self, node) -> bool:
        return (
            node is not None
            and node.type == "identifier"
            and self._text(node) in self._dynamic_str_vars
        )

    def _first_two_args(self, call_node):
        args_node = call_node.child_by_field_name("arguments")
        if args_node is None:
            return []
        return [c for c in args_node.children if c.type not in ("(", ")", ",")]

    def _contains_none_string(self, node) -> bool:
        if node is None:
            return False
        if node.type == "string":
            return (self._string_literal_value(node) or "").lower() == "none"
        if node.type == "array":
            return any(
                self._contains_none_string(c) for c in node.children if c.type == "string"
            )
        return False

    def _function_name(self, node) -> str:
        if node.type == "method_definition":
            name_node = node.child_by_field_name("name")
            return self._text(name_node) if name_node is not None else "<anonymous>"
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return self._text(name_node)
        # Anonymous function/arrow function — infer a name from context,
        # same idea as how a human would describe "the function assigned
        # to handleClick" rather than "an anonymous function".
        parent = node.parent
        if parent is not None:
            if parent.type == "variable_declarator":
                n = parent.child_by_field_name("name")
                if n is not None:
                    return self._text(n)
            if parent.type == "pair":
                k = parent.child_by_field_name("key")
                if k is not None:
                    return self._text(k).strip("'\"")
            if parent.type == "assignment_expression":
                left = parent.child_by_field_name("left")
                if left is not None:
                    return self._text(left)
            if parent.type == "field_definition":
                prop = parent.child_by_field_name("property")
                if prop is not None:
                    return self._text(prop)
        return "<anonymous>"

    # -- traversal ------------------------------------------------------

    def visit(self, node):
        node_type = node.type

        if node_type in FUNCTION_SCOPE_TYPES:
            self._func_stack.append(self._function_name(node))
            self._var_scope_stack.append(self._dynamic_str_vars)
            self._dynamic_str_vars = {}
            for child in node.children:
                self.visit(child)
            self._dynamic_str_vars = self._var_scope_stack.pop()
            self._func_stack.pop()
            return

        if node_type == "variable_declarator":
            self._check_variable_declarator(node)
        elif node_type == "assignment_expression":
            self._check_assignment_expression(node)
        elif node_type == "call_expression":
            self._check_call_expression(node)
        elif node_type == "new_expression":
            self._check_new_expression(node)
        elif node_type == "pair":
            self._check_object_pair(node)

        for child in node.children:
            self.visit(child)

    # -- rule checks ------------------------------------------------------

    def _check_variable_declarator(self, node):
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None or name_node.type != "identifier":
            return
        var_name = self._text(name_node)

        literal = self._string_literal_value(value_node)
        if literal is not None and len(literal) > 3 and SECRET_NAME_PATTERN.search(var_name):
            self._add("hardcoded-secret", self._line_of(node))

        if value_node is not None and self._is_dynamic_string(value_node):
            self._dynamic_str_vars[var_name] = True
        else:
            # Reassigning/declaring with something non-dynamic clears any
            # prior taint on this name — same reasoning as python_rules.py.
            self._dynamic_str_vars.pop(var_name, None)

    def _check_assignment_expression(self, node):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return

        if left.type == "member_expression" and self._member_property(left) == "innerHTML":
            if self._looks_dynamic_broad(right):
                self._add("xss-innerhtml-assignment", self._line_of(node))

        if left.type == "identifier":
            var_name = self._text(left)
            if self._is_dynamic_string(right):
                self._dynamic_str_vars[var_name] = True
            else:
                self._dynamic_str_vars.pop(var_name, None)

    def _check_call_expression(self, node):
        func = node.child_by_field_name("function")
        if func is None:
            return
        arg_nodes = self._first_two_args(node)
        first_arg = arg_nodes[0] if arg_nodes else None

        if func.type == "member_expression":
            prop = self._member_property(func)
            root = self._member_root_identifier(func)

            if prop in SQL_METHOD_NAMES and first_arg is not None:
                if self._is_dynamic_string(first_arg) or self._is_tainted_identifier(first_arg):
                    self._add("sql-injection-string-build", self._line_of(node))

            if prop in EXEC_METHOD_NAMES and root in EXEC_CHILD_PROCESS_OBJECTS and first_arg is not None:
                if self._is_dynamic_string(first_arg) or self._is_tainted_identifier(first_arg):
                    self._add("command-injection-js-exec", self._line_of(node))

            if prop == "createHash" and first_arg is not None:
                lit = self._string_literal_value(first_arg)
                if lit is not None and lit.lower() in ("md5", "sha1"):
                    self._add("weak-crypto-hash", self._line_of(node))

            if prop in HEADER_SETTER_NAMES and len(arg_nodes) >= 2:
                header_name = self._string_literal_value(arg_nodes[0])
                header_val = self._string_literal_value(arg_nodes[1])
                if header_name is not None and header_name.lower() == "access-control-allow-origin" \
                        and header_val == "*":
                    self._add("insecure-cors-wildcard", self._line_of(node))

            if prop == "verify":
                for arg in arg_nodes:
                    if arg.type == "object":
                        self._check_jwt_options_object(arg, node)

        elif func.type == "identifier":
            fname = self._text(func)

            # Bare exec(...)/execSync(...) not reached through a member
            # access. Unlike the old regex version, this AST branch
            # structurally cannot fire for `someRegex.exec(str)` — that
            # is always a member_expression, never a bare identifier
            # call — so no negative-lookbehind hack is needed here.
            if fname in EXEC_METHOD_NAMES and first_arg is not None:
                if self._is_dynamic_string(first_arg) or self._is_tainted_identifier(first_arg):
                    self._add("command-injection-js-exec", self._line_of(node))

            if fname == "eval" and first_arg is not None:
                if self._string_literal_value(first_arg) is None:
                    self._add("dangerous-eval-exec", self._line_of(node))

    def _check_jwt_options_object(self, obj_node, call_node):
        for member in obj_node.children:
            if member.type != "pair":
                continue
            key = member.child_by_field_name("key")
            value = member.child_by_field_name("value")
            key_text = self._text(key).strip("'\"").lower() if key is not None else ""
            if key_text in ("algorithm", "algorithms") and self._contains_none_string(value):
                self._add("jwt-none-algorithm", self._line_of(call_node))

    def _check_new_expression(self, node):
        ctor = node.child_by_field_name("constructor")
        if ctor is not None and ctor.type == "identifier" and self._text(ctor) == "Function":
            self._add("dangerous-eval-exec", self._line_of(node))

    def _check_object_pair(self, node):
        """Standalone `{ origin: '*' }` object literal, independent of
        which call it's passed into — covers `cors({ origin: '*' })`
        style configuration that a setHeader-specific check would miss."""
        key = node.child_by_field_name("key")
        value = node.child_by_field_name("value")
        if key is None or value is None:
            return
        key_text = self._text(key).strip("'\"").lower()
        if key_text == "origin" and self._string_literal_value(value) == "*":
            self._add("insecure-cors-wildcard", self._line_of(node))


def analyze_js_ts_file(file_path: Path, relative_path: str) -> List[Finding]:
    """Parse and run all rules against a single JS/TS/TSX file. Returns
    [] on parse failure (the parser step already reports parse_error
    separately, see app/parser/js_ts_parser.py)."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    suffix = file_path.suffix.lstrip(".")
    try:
        tree = parse_source(source.encode("utf-8"), suffix)
    except Exception:
        return []

    if tree.root_node.has_error:
        return []

    visitor = JsTsSecurityVisitor(relative_path, source)
    visitor.visit(tree.root_node)
    return visitor.findings
