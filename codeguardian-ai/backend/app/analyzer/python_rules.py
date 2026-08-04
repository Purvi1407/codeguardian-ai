import ast
from pathlib import Path
from typing import List, Optional

from app.analyzer.rules import RULES
from app.schemas.findings import Finding

SECRET_NAME_PATTERN = __import__("re").compile(
    r"(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|"
    r"private[_-]?key|token)",
    __import__("re").IGNORECASE,
)

SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}
HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "request"}


class SecurityRuleVisitor(ast.NodeVisitor):
    """
    Walks a single file's AST and yields candidate Finding objects.
    Deliberately pattern-based, not taint-tracking: a rule firing means
    "this looks worth a human/AI second look", not "this is confirmed
    exploitable". That filtering happens in Module 4.
    """

    def __init__(self, file_path: str, source_lines: List[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: List[Finding] = []
        self._func_stack: List[str] = []
        # Tracks {var_name: lineno} for variables assigned a dynamically-built
        # string within the CURRENT function, so `q = f"..."; execute(q)`
        # is caught, not just `execute(f"...")` directly. Reset per function
        # to keep this cheap and avoid false positives across scopes.
        self._dynamic_str_vars: dict = {}

    # -- helpers ----------------------------------------------------------

    def _current_function(self) -> Optional[str]:
        return self._func_stack[-1] if self._func_stack else None

    def _snippet(self, lineno: int) -> str:
        """
        Returns a small window of source around the flagged line, not just
        that one line. Multi-line calls (e.g. subprocess.run(...,
        shell=True) spanning several lines) would otherwise show the AI
        only the opening line — e.g. "res = subprocess.run(" — with the
        actual risky argument and shell=True invisible on the next lines.
        That starves Module 4 of the context it needs to judge confidently,
        and pushes it toward an appropriately cautious but unhelpful
        "not enough context" dismissal even on genuinely real findings.
        """
        start = max(1, lineno - 1)
        end = min(len(self.source_lines), lineno + 5)
        window = self.source_lines[start - 1:end]
        return "\n".join(window)[:600]

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

    def _call_name(self, node: ast.Call) -> Optional[str]:
        """Return the attribute/function name being called, e.g. 'execute' or 'system'."""
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
        return None

    def _call_root(self, node: ast.Call) -> Optional[str]:
        """Return the root object name for a dotted call, e.g. os.system -> 'os'."""
        f = node.func
        while isinstance(f, ast.Attribute):
            f = f.value
        if isinstance(f, ast.Name):
            return f.id
        return None

    def _is_dynamic_string(self, node: ast.AST) -> bool:
        """True if node builds a string dynamically (concat, %, .format(), f-string)."""
        if isinstance(node, ast.JoinedStr):  # f-string
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "format":
            return True
        return False

    def _has_kwarg_true(self, node: ast.Call, name: str) -> bool:
        for kw in node.keywords:
            if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    def _has_kwarg_false(self, node: ast.Call, name: str) -> bool:
        for kw in node.keywords:
            if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return True
        return False

    # -- visitor methods ----------------------------------------------------

    def visit_FunctionDef(self, node):
        self._func_stack.append(node.name)
        prev_dynamic_vars = self._dynamic_str_vars
        self._dynamic_str_vars = {}
        self.generic_visit(node)
        self._dynamic_str_vars = prev_dynamic_vars
        self._func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name) and SECRET_NAME_PATTERN.search(target.id):
                    if len(node.value.value) > 3:  # skip trivial placeholders like ""
                        self._add("hardcoded-secret", node.lineno)
                        break

        # Track `var = <dynamic string expr>` so a later execute(var) call
        # can still be caught, not just execute(<dynamic expr>) directly.
        if self._is_dynamic_string(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._dynamic_str_vars[target.id] = node.lineno
        elif len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            # Reassigning to something non-dynamic clears the taint —
            # keeps this from over-firing on reused variable names.
            self._dynamic_str_vars.pop(node.targets[0].id, None)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        name = self._call_name(node)
        root = self._call_root(node)

        # SQL injection: cursor.execute(<dynamic string>) — either built
        # inline, or built earlier in this function and passed by name.
        if name in {"execute", "executemany", "executescript"} and node.args:
            arg = node.args[0]
            if self._is_dynamic_string(arg):
                self._add("sql-injection-string-build", node.lineno)
            elif isinstance(arg, ast.Name) and arg.id in self._dynamic_str_vars:
                self._add("sql-injection-string-build", node.lineno)

        # subprocess shell=True
        if root == "subprocess" and name in SUBPROCESS_FUNCS:
            if self._has_kwarg_true(node, "shell"):
                self._add("command-injection-shell-true", node.lineno)

        # os.system / os.popen with a dynamic argument
        if root == "os" and name in {"system", "popen"} and node.args:
            if not isinstance(node.args[0], ast.Constant):
                self._add("command-injection-os-system", node.lineno)

        # pickle.load / pickle.loads
        if root == "pickle" and name in {"load", "loads"}:
            self._add("insecure-deserialization-pickle", node.lineno)

        # yaml.load without a safe Loader
        if root == "yaml" and name == "load":
            loader_kw = next((kw for kw in node.keywords if kw.arg == "Loader"), None)
            if loader_kw is None:
                self._add("insecure-deserialization-yaml", node.lineno)
            else:
                loader_val = loader_kw.value
                if isinstance(loader_val, ast.Attribute) and loader_val.attr in {"Loader", "UnsafeLoader"}:
                    self._add("insecure-deserialization-yaml", node.lineno)

        # eval/exec with non-literal argument (must be a bare call, e.g.
        # eval(...) not obj.eval(...) — checking node.func type directly
        # instead of _call_root, since _call_root returns the function's
        # own name for bare calls rather than None).
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"} and node.args:
            if not isinstance(node.args[0], ast.Constant):
                self._add("dangerous-eval-exec", node.lineno)

        # hashlib.md5 / hashlib.sha1
        if root == "hashlib" and name in {"md5", "sha1"}:
            self._add("weak-crypto-hash", node.lineno)

        # .run(debug=True)
        if name == "run" and self._has_kwarg_true(node, "debug"):
            self._add("debug-mode-enabled", node.lineno)

        # requests-style call with verify=False
        if name in HTTP_VERBS and self._has_kwarg_false(node, "verify"):
            self._add("tls-verification-disabled", node.lineno)

        self.generic_visit(node)


def analyze_python_file(file_path: Path, relative_path: str) -> List[Finding]:
    """Parse and run all rules against a single Python file. Returns [] on parse failure
    (the parser step already reports parse_error separately)."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, OSError):
        return []

    visitor = SecurityRuleVisitor(relative_path, source.splitlines())
    visitor.visit(tree)
    return visitor.findings
