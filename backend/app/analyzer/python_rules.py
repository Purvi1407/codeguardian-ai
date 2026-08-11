import ast
from pathlib import Path
from typing import Dict, List, Optional, Set

from app.analyzer.rules import RULES
from app.schemas.findings import Finding

SECRET_NAME_PATTERN = __import__("re").compile(
    r"(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|"
    r"private[_-]?key|token)",
    __import__("re").IGNORECASE,
)

SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}
HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "request"}

CROSS_FUNCTION_NOTE = (
    " Reaches this sink through a parameter — a caller elsewhere in this "
    "file passes a dynamically-built value into it, rather than this "
    "function building the dangerous value itself."
)


def _collect_local_function_params(tree: ast.AST) -> Dict[str, List[str]]:
    """Top-level function name -> its ordered positional parameter names.
    Scoped to top-level functions only, matching the same scope decision
    already made for FunctionInfo extraction elsewhere in this codebase
    (see parser/python_parser.py) — methods and nested functions are not
    included as call-taint targets in this bounded implementation."""
    result: Dict[str, List[str]] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result[node.name] = [a.arg for a in node.args.args]
    return result


class SecurityRuleVisitor(ast.NodeVisitor):
    """
    Walks a single file's AST and yields candidate Finding objects.
    Deliberately pattern-based, not full taint-tracking: a rule firing
    means "this looks worth a human/AI second look", not "this is
    confirmed exploitable". That filtering happens in Module 4.

    Phase 3 adds two things on top of the original same-function
    tracking:
      - Alias propagation: `q2 = q` where `q` is already tracked as a
        dynamically-built string now also taints `q2`, not just direct
        f-string/concat/format assignments.
      - Bounded, one-hop cross-function parameter tracking, driven by
        `seed_params` (see analyze_python_file below for how it's
        computed) — see README "Phase 3" section for the full design
        writeup and its honest limits (single file, one hop, no cycles
        beyond one pass, top-level functions only).
    """

    def __init__(self, file_path: str, source_lines: List[str], seed_params: Optional[Dict[str, Set[str]]] = None):
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: List[Finding] = []
        self._func_stack: List[str] = []
        # Tracks {var_name: lineno} for variables assigned a dynamically-built
        # string within the CURRENT function, so `q = f"..."; execute(q)`
        # is caught, not just `execute(f"...")` directly. Reset per function
        # to keep this cheap and avoid false positives across scopes.
        self._dynamic_str_vars: dict = {}
        # func_name -> set of its parameter names that at least one call
        # site elsewhere in this file passes a dynamically-built value
        # into. Used to pre-seed _dynamic_str_vars on function entry.
        self._seed_params: Dict[str, Set[str]] = seed_params or {}
        # Stack (parallel to _func_stack) of "which currently-tracked
        # dynamic vars in this function came from a seeded parameter,
        # not a local f-string/concat build" — used only to word the
        # finding's description accurately, not to change whether it fires.
        self._cross_taint_stack: List[Set[str]] = []
        # Side output: for each LOCAL function called in this file, which
        # positional argument indices were passed a dynamically-built
        # value at at least one call site. Consumed by analyze_python_file
        # to compute seed_params for a second pass. Always collected
        # (cheap), regardless of whether this particular pass is itself
        # seeded — so a chain of two local calls can, in principle, be
        # resolved by re-running the two-pass process, though this
        # implementation only performs one additional pass (one hop),
        # not a fixpoint iteration — see README for why that's an
        # intentional scope limit, not an oversight.
        self.call_taint: Dict[str, Set[int]] = {}

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

    def _add(self, rule_id: str, lineno: int, via_param: bool = False):
        meta = RULES[rule_id]
        description = meta["description"]
        if via_param:
            description = description + CROSS_FUNCTION_NOTE
        self.findings.append(Finding(
            rule_id=rule_id,
            title=meta["title"],
            severity=meta["severity"],
            cwe=meta["cwe"],
            file=self.file_path,
            function=self._current_function(),
            line=lineno,
            snippet=self._snippet(lineno),
            description=description,
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

    def _record_call_taint(self, node: ast.Call):
        """If this call targets a bare-name function (i.e. one that could
        be a locally-defined function in this file), record which
        argument positions received a dynamically-built value at this
        call site. Harmless no-op for calls to functions that aren't
        actually local — analyze_python_file only looks up entries for
        names it already knows are local."""
        if not isinstance(node.func, ast.Name):
            return
        callee = node.func.id
        for i, arg in enumerate(node.args):
            if self._is_dynamic_string(arg) or (isinstance(arg, ast.Name) and arg.id in self._dynamic_str_vars):
                self.call_taint.setdefault(callee, set()).add(i)

    # -- visitor methods ----------------------------------------------------

    def visit_FunctionDef(self, node):
        self._func_stack.append(node.name)
        prev_dynamic_vars = self._dynamic_str_vars
        seeded = self._seed_params.get(node.name, set())
        self._dynamic_str_vars = {p: node.lineno for p in seeded}
        self._cross_taint_stack.append(set(seeded))
        self.generic_visit(node)
        self._cross_taint_stack.pop()
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
        # Also handles simple aliasing: `var2 = var1` where var1 is
        # already tracked (built locally, or seeded from a caller) —
        # without this, a rename between the taint source and the sink
        # would silently break tracking.
        is_dynamic = self._is_dynamic_string(node.value)
        is_alias_of_tainted = isinstance(node.value, ast.Name) and node.value.id in self._dynamic_str_vars
        if is_dynamic or is_alias_of_tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._dynamic_str_vars[target.id] = node.lineno
                    if is_alias_of_tainted and self._cross_taint_stack and node.value.id in self._cross_taint_stack[-1]:
                        self._cross_taint_stack[-1].add(target.id)
        elif len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            # Reassigning to something non-dynamic clears the taint —
            # keeps this from over-firing on reused variable names. This
            # is also, deliberately, how passing a tainted value through
            # a sanitizer function ends up excluded already: `safe = 
            # some_sanitizer(tainted)` assigns from a Call node that
            # isn't a recognized dynamic-string builder, so it lands in
            # this branch and clears any prior taint on `safe` — no
            # separate sanitizer allowlist needed for that case.
            self._dynamic_str_vars.pop(node.targets[0].id, None)
            if self._cross_taint_stack:
                self._cross_taint_stack[-1].discard(node.targets[0].id)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        name = self._call_name(node)
        root = self._call_root(node)

        self._record_call_taint(node)

        # SQL injection: cursor.execute(<dynamic string>) — either built
        # inline, built earlier in this function and passed by name, or
        # (Phase 3) received as a parameter that a caller elsewhere in
        # this file passes a dynamically-built value into.
        if name in {"execute", "executemany", "executescript"} and node.args:
            arg = node.args[0]
            if self._is_dynamic_string(arg):
                self._add("sql-injection-string-build", node.lineno)
            elif isinstance(arg, ast.Name) and arg.id in self._dynamic_str_vars:
                via_param = bool(self._cross_taint_stack) and arg.id in self._cross_taint_stack[-1]
                self._add("sql-injection-string-build", node.lineno, via_param=via_param)

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


def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """Two passes over the same file (see analyze_python_file) can each
    independently emit the same finding for anything that doesn't depend
    on cross-function seeding — dedupe by the combination that identifies
    "the same thing was flagged", keeping the first (pass 1, unseeded)
    occurrence, which has the plainer, unannotated description."""
    seen = set()
    deduped = []
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def analyze_python_file(file_path: Path, relative_path: str) -> List[Finding]:
    """Parse and run all rules against a single Python file. Returns [] on parse failure
    (the parser step already reports parse_error separately)."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, OSError):
        return []

    source_lines = source.splitlines()

    # Pass 1: normal single-function-scope analysis, exactly as before
    # Phase 3. Also collects call_taint as a side effect — which local
    # functions were called with a dynamically-built argument, and at
    # which position.
    pass1 = SecurityRuleVisitor(relative_path, source_lines)
    pass1.visit(tree)

    if not pass1.call_taint:
        return pass1.findings

    # Bounded cross-function step: for every local function that was
    # called with a dynamic argument somewhere in this file, seed its
    # matching parameter name(s) as pre-tainted, then re-run the full
    # analysis once more. This is intentionally ONE hop, not a fixpoint
    # over a call graph — if A's taint reaches B only through a chain
    # A -> C -> B, this won't resolve C -> B unless C's own taint from A
    # was already visible in pass 1's single traversal (which it is, if
    # C is called with a dynamic value directly). A true multi-hop
    # fixpoint is real taint-tracking territory — out of scope here for
    # the same reason full data-flow analysis is out of scope elsewhere
    # in this codebase (see Module 3 design notes above).
    local_params = _collect_local_function_params(tree)
    seed_params: Dict[str, Set[str]] = {}
    for func_name, arg_indices in pass1.call_taint.items():
        params = local_params.get(func_name)
        if not params:
            continue
        names = {params[i] for i in arg_indices if i < len(params)}
        if names:
            seed_params[func_name] = names

    if not seed_params:
        return pass1.findings

    pass2 = SecurityRuleVisitor(relative_path, source_lines, seed_params=seed_params)
    pass2.visit(tree)

    return _dedupe_findings(pass1.findings + pass2.findings)
