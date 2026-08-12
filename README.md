CodeGuardian AI — Backend (Module 1 + 2)

AI-powered SAST agent. This slice implements:

Module 1 — Repository Processor: validates a GitHub URL, shallow-clones it into a temp dir, cleans up after itself (even on failure).
Module 2 — Parser: walks the repo, finds .py/.ts/.tsx/.js/.jsx files, and extracts functions/classes with line numbers.
Python uses the ast module — accurate line numbers, args, method/class attribution.
TS/JS uses regex for now (documented limitation — see app/parser/js_ts_parser.py). Swap for tree-sitter later if time allows.
Run it
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
Try it
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/pallets/flask"}'

Tested live against pallets/flask (83 files, 0 parse errors) and against invalid/nonexistent repo URLs (clean 400s, no orphaned temp dirs).

What's next (Module 3 + 4)
app/analyzer/ — rule-based static analyzer producing candidate findings from the parsed functions/classes (this is where SQLi/XSS/etc. rules go).
app/ai/ — sends candidate findings to the OpenAI API for validation, severity, explanation, and patch suggestion. This is where the "fewer, higher-confidence findings" philosophy actually gets enforced — the AI step is a filter, not a generator.
Design notes (for defending decisions)
Why ast over regex for Python but regex for TS/JS? ast is stdlib, zero dependencies, and gives exact line numbers for free. Tree-sitter would give the same for TS/JS but adds a build dependency; regex was the pragmatic MVP call under a tight timeline, called out explicitly rather than hidden.
Why always clean up the clone, even on success? Module 1 currently treats each scan as stateless. Once Module 3/4 need to re-open the same repo for deeper analysis, this will change to a short-TTL cache instead of immediate deletion — noted as a TODO in api/scan.py so it doesn't look accidental later.
Why --depth 1 clone? We only need current-state source, not history, and a shallow clone is dramatically faster and safer against large repos.
Module 3 — Rule-Based Analyzer

Added: app/analyzer/rules.py (rule metadata) + app/analyzer/python_rules.py (AST-based detection) + POST /analyze endpoint (full Module 1+2+3 pipeline).

10 rules implemented, each backed by CWE reference:

Rule	Severity	What it catches
sql-injection-string-build	high	execute() called with f-string/concat/.format() — including tracked through a local variable
command-injection-shell-true	high	subprocess.*(shell=True)
command-injection-os-system	high	os.system()/os.popen() with a non-literal argument
hardcoded-secret	medium	password/token/api_key-named variables assigned string literals
insecure-deserialization-pickle	high	pickle.load()/loads()
insecure-deserialization-yaml	high	yaml.load() without Loader=SafeLoader
dangerous-eval-exec	high	eval()/exec() with a non-literal argument
weak-crypto-hash	low	hashlib.md5()/sha1()
debug-mode-enabled	medium	.run(debug=True)
tls-verification-disabled	high	HTTP calls with verify=False

Verified against a deliberately vulnerable test file: 11/11 expected findings fired, 0 false positives on a parameterized-query control function in the same file. Also verified end-to-end against pallets/flask (real 83-file repo): 7 candidate findings, including a genuine example of why Module 4 is necessary — config.py's from_pyfile() uses exec() legitimately to load a trusted local config file, but a pattern-only rule can't distinguish that from a real code-injection bug. That's the exact gap AI validation is meant to close.

Design notes (for defending decisions)
Why pattern-matching, not taint tracking? True taint analysis (tracing whether a value actually originates from user input) needs a data-flow graph across the whole call chain — out of scope for a multi-day MVP. This is explicitly a candidate generator: fast, cheap, and intentionally over-inclusive, with Module 4 doing the precision work. Naming this limitation up front is stronger than pretending the rules are exploit-confirmed.
Why track variables within a function for SQL injection, but not across functions? Cross-function tracking needs call-graph resolution (arguments passed between functions, aliasing, etc.) — the same complexity tradeoff as full taint tracking. Single-function tracking catches the extremely common query = f"..."; cursor.execute(query) pattern cheaply without that complexity.
Why only Python gets analyzer rules right now? The TS/JS parser is already regex-based (documented Module 2 tradeoff) — building a security rule engine on top of an unreliable AST would just compound the imprecision. Sequencing: get Python's rules right first, decide whether tree-sitter is worth adding before extending rules to JS/TS.
Module 4 — AI Validation

Added: app/ai/client.py (OpenAI client + config), app/ai/prompts.py (system prompt + JSON schema), app/ai/validator.py (batching + merge logic), POST /validate endpoint (full Module 1+2+3+4 pipeline).

This is the actual product. Everything before this point produces candidates; /validate is what turns them into the "fewer, higher-confidence findings" the whole philosophy is built around. Response includes both findings (AI-verified) and dismissed (AI-rejected candidates, kept for transparency — useful for tuning rules later).

⚠️ Important — what's tested vs. not

I could not make a real call to the OpenAI API from my environment (network sandbox doesn't allow api.openai.com). What I verified instead, with a mocked API response:

Batch → merge logic correctly maps AI judgments back onto the right findings
A finding the model "drops" from its response fails safe (kept as unverified/low-confidence) instead of silently disappearing
Missing OPENAI_API_KEY fails fast with a clear message, before cloning any repo
Server starts cleanly with all 4 routes registered (/scan, /analyze, /validate, /health)

You need to test the real API call yourself — set OPENAI_API_KEY, hit /validate against a real repo, and sanity-check the responses. Be honest about this in your writeup/demo; claiming something is tested when it wasn't is a much worse look than saying "the OpenAI integration itself needs your key to verify, here's what I did test."

Setup
export OPENAI_API_KEY=sk-...
# optional — defaults to gpt-4o-mini for cost; override for a stronger model
export OPENAI_MODEL=gpt-4o
Design notes (for defending decisions)
Why batch findings into one request instead of one call per finding? Direct cost/latency tradeoff. A repo with 50 candidates would mean 50 separate API calls at ~1s+ each; batching 8 per call cuts that to ~7 calls. Tradeoff: harder to parse (need to map results back by index), which is why structured output (JSON schema, strict: true) is used instead of free-text parsing — reliability without giving up the cost savings.
Why fail-fast on missing API key before cloning? Cloning + parsing a large repo can take real time. No reason to spend that time only to fail at the very last step. This is a small thing, but it's the kind of "did they think about the failure path" detail a reviewer notices.
Why keep dismissed findings in the response instead of just dropping them? Two reasons: (1) transparency — if AI validation seems too aggressive, you can see exactly what it rejected and why; (2) it's the seed of a future feedback loop (Module 5+, not built) where a developer could mark a dismissed finding as "actually valid" to improve rule tuning over time.
Why is the model configurable via OPENAI_MODEL rather than hardcoded? This is explicitly a cost/quality knob the person running the tool should control, not a decision baked into the code.
Known dependency conflict (fixed)

openai==1.51.0 internally passes a proxies argument to httpx.Client(). httpx removed that argument in 0.28.0. If pip install resolves a newer httpx alongside the pinned openai version, every OpenAI client instantiation fails with:

TypeError: Client.__init__() got an unexpected keyword argument 'proxies'

This surfaces as a bare, un-detailed 500 from /validate (the error happens at OpenAI(api_key=...) construction, which is outside the endpoint's own try/except blocks — a good reminder that error handling can only catch what it wraps).

Fix: httpx<0.28 is now pinned in requirements.txt. If you already have a venv from before this fix, run pip install "httpx<0.28" directly.

Using a free provider instead of paid OpenAI credits

If you don't want to add billing to OpenAI, the AI layer is provider-agnostic — it can point at any OpenAI-compatible API via OPENAI_BASE_URL. Groq offers a genuinely free API tier (no card required) that works with this project with no code changes.

Sign up at https://console.groq.com and generate an API key (starts with gsk_)
Set these instead of/in addition to your usual OPENAI_API_KEY:
   export OPENAI_API_KEY=gsk_your_groq_key_here
   export OPENAI_BASE_URL=https://api.groq.com/openai/v1
   export OPENAI_MODEL=openai/gpt-oss-20b

(Windows cmd: set instead of export. PowerShell: $env:VAR="value")
3. Restart the server and hit /validate as normal — no other changes needed.

Design note: this works because app/ai/client.py builds the OpenAI SDK client with an optional base_url override rather than hardcoding api.openai.com. That's a deliberate choice, not a hack — it means the AI validation layer isn't locked to one vendor, which is a reasonable thing to point to if asked "why did you structure the client this way?" One caveat worth knowing: Groq's structured-output mode is stricter than OpenAI's about requiring every schema property to be listed under required — the schema in app/ai/prompts.py already satisfies this, but it's worth knowing if you modify that schema later.

Module 3 extended — TypeScript/JavaScript rules

Added app/analyzer/js_ts_rules.py: 8 regex-based rules for JS/TS (SQL injection, Node command injection, XSS via innerHTML, dangerous eval/Function, weak crypto, insecure CORS wildcard, JWT algorithm confusion, hardcoded secrets). Wired into the same /analyze and /validate pipeline — no new endpoints needed.

Verified two ways:

Against a deliberately vulnerable test file: 8/8 expected findings fired, 0 false positives on parameterized/safe counterpart functions in the same file.
Against a real, unfamiliar repo (appsecco/dvna — Damn Vulnerable NodeJS Application): correctly found its 3 genuine, documented vulnerabilities (SQL injection, command injection via ping, unsafe eval()) with zero noise after two bugs found during this exact test were fixed:
The exec() regex was initially also matching JavaScript's unrelated RegExp.prototype.exec() method — fixed by requiring either explicit child_process.exec or a bare (non-method) exec( call.
Vendor/minified bundles (jquery-3.2.1.min.js) were being scanned as if they were the developer's own code, producing noise on single-line minified files. Fixed by excluding *.min.js/*.min.ts/*.bundle.js from discovery — scanning vendored third-party code a developer can't meaningfully "fix" isn't useful for a SAST tool anyway.
Design notes (for defending decisions)
Why regex instead of upgrading to a real JS/TS parser? The JS/TS parser (Module 2) was already regex-based as a documented MVP tradeoff; building AST-quality rules on top of a regex-quality parser would be false precision. This keeps the limitation consistent and honestly documented rather than half-fixed. If given another month, tree-sitter would upgrade both the parser and this analyzer for one integration cost — noted as the top priority next step.
Why exclude minified/vendor files rather than flag them? A SAST tool exists to help a developer fix code they own. Findings inside a third-party minified bundle aren't actionable — the fix isn't "edit this line," it's "update the dependency," which is a different problem (and better solved by npm audit, not this tool).
The RegExp.exec() false-positive is a good real example of testing value: it only surfaced by running against genuine, unfamiliar code — my own hand-written test file never would have caught it, since I wouldn't have coincidentally used .exec() in a regex context. This is the argument for testing against code you didn't write, not just code you designed to be caught.
Browser UI

Added app/static/index.html — a single-page frontend served at GET /. No build step, no separate frontend deployment: it's plain HTML/CSS/JS, fetch-calling the same /analyze and /validate endpoints, served by the same FastAPI app.

Run it: start the server as usual, open http://localhost:8000/ (not /docs — that's still the API explorer, / is now the actual product UI).

Two modes, exposed as a toggle:

Quick scan → calls /analyze (free, no API key, rule-based candidates only)
Full validate → calls /validate (uses your API key, AI-reviewed, shows verified + dismissed findings)

Verified working: GET / returns 200 with the correct HTML: confirmed /health, /docs, and /analyze all still work correctly and aren't shadowed by the new root route (the UI route is a specific GET /, not a catch-all mount, so it can't intercept other paths).

Not verified: I don't have a way to render and screenshot a browser in my environment, so the visual layout/styling is untested by me beyond reading the CSS carefully. Open it yourself and tell me if anything looks broken, misaligned, or is hard to read — that's the one part of this I genuinely can't confirm without your eyes on it.

Design notes (for defending decisions)
Why no framework (React/Next.js)? Zero build step, zero deployment complexity — the whole UI is one static file the backend already serves. For a 2-endpoint tool with no client-side state beyond "what did the last scan return," a framework would add process without adding capability. This is a legitimate answer if asked "why not React" — not every UI needs one.
The candidates → verified gauge bar is the one deliberately designed element: it visualizes the core product philosophy ("fewer, higher-confidence findings") as an actual number you watch shrink, rather than just stating it in copy.
Dismissed findings are visible but collapsed by default — same reasoning as the API design: transparency without cluttering the primary view.
Deployment

Deployed on Render via the included Dockerfile. Root directory is the repo root (no nested subfolder). Set OPENAI_API_KEY (and optionally OPENAI_BASE_URL / OPENAI_MODEL for the Groq-compatible free tier) as environment variables in the Render service settings — never commit these to the repo.

Phase 1 — Foundation & Safety: automated test suite

Added backend/tests/ — a pytest suite covering the Python rule engine (app/analyzer/python_rules.py) and parser (app/parser/python_parser.py), plus a GitHub Actions workflow that runs it on every push/PR.

61 tests, 100% statement coverage on python_rules.py.

backend/tests/
  fixtures/
    vulnerable_python.py     # one true-positive case per rule (21 functions)
    safe_python.py           # tricky-but-safe / false-positive regressions (21 functions)
    malformed/
      syntax_error.py        # invalid Python
      empty.py                # zero-byte file
      only_comments.py       # parses fine, nothing to walk
      unicode_content.py     # non-ASCII identifiers + emoji near a real finding
  conftest.py                 # shared fixtures: parses each file once per module
  test_python_rules.py        # rule-by-rule true/false-positive assertions
  test_python_parser.py       # function/class extraction, line numbers, args
  test_edge_cases.py          # syntax errors, empty files, unicode, missing files

Run it:

cd backend
pip install -r requirements-dev.txt
pytest tests/ -v --cov=app.analyzer --cov=app.parser --cov-report=term-missing
Design notes (for defending decisions)
Why assert on function name instead of line number? Line-number assertions break every time a fixture file gets a comment added or a case reordered — that's noise, not signal. Every fixture function is named <rule_id>__<variant>, so test_python_rules.py asserts "this function fires this rule" independent of where it sits in the file. Only an actual behavior change in the rule breaks the test.
Why two meta-tests (TestCoverageIsComplete)? To catch drift in both directions: a rule added to analyzer/rules.py with no fixture (silent gap), or a fixture function added with no assertion (silent no-op test). Both failed loudly when I deliberately introduced them while building this — see the "sanity check" note below.
Why is the false-positive fixture the same size as the true-positive one? Because a rule engine that never checks its own precision is only half-tested. safe_python.py includes the exact category of case the AI validation layer is designed to catch by hand (e.g. SandboxedEvaluator.eval() — a method call, not the builtin — mirroring the real mathjs.eval() case from manual DVNA/Flask testing) and an HMAC-signing case mirroring the real Flask false-positive this tool already correctly avoided in manual testing. Encoding those as fixtures means they're now protected by CI, not just by memory of a one-off manual check.
Verified the suite actually catches regressions, not just passes trivially: temporarily disabled the SQL injection rule's trigger condition and confirmed all 4 related tests failed with a clear assertion message, then restored it and confirmed all 61 pass again. This is the difference between "tests exist" and "tests would catch a real bug" — worth checking once, not worth leaving as permanent scaffolding.
Why is JS/TS excluded from this suite? analyzer/js_ts_rules.py is still regex-based (documented limitation above) — writing a rigorous test suite against detection logic that's slated for a tree-sitter rewrite would mean rewriting the tests immediately after. Sequencing: Phase 2 (tree-sitter) lands first, then JS/TS gets the same fixture + test treatment Python has here.
Why does CI only install requirements-dev.txt, not hit the OpenAI API? The test suite intentionally scopes to app.analyzer and app.parser — no network calls, no API key needed in CI. This keeps the pipeline fast, free, and not dependent on secrets being configured correctly in the repo settings. AI validation (app/ai/) getting its own mocked test suite is next.

Copy everything between the two marker lines below and paste it onto the end of your README.md file (after the Phase 1 section, which should currently be the last thing in the file).

---START COPYING BELOW THIS LINE---

Phase 2 — Parsing Engine: tree-sitter for JS/TS/TSX

Replaced the regex-based JS/TS parser and analyzer with tree-sitter. This was the single item both the take-home feedback and this project's own README called out as the highest-leverage next step, since the old approach was already documented as a known limitation on both the parser and analyzer side.

What changed:

app/parser/ts_grammars.py — new: loads the JS/TS/TSX tree-sitter grammars once, shared by the parser and analyzer.
app/parser/js_ts_parser.py — rewritten: walks a real parse tree instead of matching regex per line.
app/analyzer/js_ts_rules.py — rewritten: all 8 JS/TS rules now match on AST node shape instead of raw text, with same-function taint tracking mirroring python_rules.py.
tests/fixtures/vulnerable_js.js, safe_js.js, vulnerable_ts.ts, parser_features_js.js, parser_features_ts.ts, malformed/*.{js,ts} — new fixtures, same true/false-positive + edge-case structure as the Python side.
tests/test_js_ts_rules.py, tests/test_js_ts_parser.py — new, 77 tests, 92% coverage on the rules engine, 94% on the parser.
requirements.txt — added tree-sitter, tree-sitter-javascript, tree-sitter-typescript (pinned versions; prebuilt wheels, no compiler needed on CI or Render).

138 total tests now (61 Python + 77 JS/TS), all passing, verified in a clean venv matching CI exactly.

What actually got fixed, concretely
Accurate end_line. The old parser's own comment said it outright: end_line=i, # regex approach can't reliably find the closing brace. Every function/class now has a real start and end line from the parse tree.
Method and class-field extraction. The old parser could only find top-level function declarations and const x = () => {} arrow functions — it had no concept of a method inside a class at all. It now extracts method_definition nodes AND the common React pattern of a class field assigned an arrow function (handleClick = () => {}), both correctly attributed with is_method=True and parent_class.
Finding.function is no longer always None. The old analyzer's own comment said: function=None,  # regex scanning doesn't reliably track enclosing function. Every JS/TS finding now carries its real enclosing function name — including through arrow functions and class methods, which required inferring a name from the surrounding variable_declarator/pair/field_definition when the function itself is anonymous.
Same-function variable taint tracking, mirroring python_rules.py's _dynamic_str_vars: a query built into a local variable and passed by name is now caught, not just a query built directly inline in the call.
The RegExp.exec() vs child_process.exec() false positive is now resolved structurally, not by regex hack. The old code needed a negative lookbehind ((?<!\.)\bexec) specifically to stop someRegex.exec(str) from being flagged as command injection — a fragile, easy-to-break heuristic. The AST version doesn't need the hack at all: someRegex.exec(str) is structurally a member_expression call, exec(cmd) is structurally a bare identifier call, and the rule only checks the bare-identifier branch for command injection. There's no way for the two to be confused, by construction.
An unexpected, genuinely positive side effect: fewer false-positive candidates sent to AI validation

Re-ran the exact DVNA verification from the Module 3 section above (appsecco/dvna, a real, unfamiliar repo) against the new AST engine. Result: 2 findings, both real (SQL injection, command injection) — down from 3 candidates under the old regex version.

The old regex EVAL_PATTERN (\beval\s*\() had no way to distinguish a bare eval() call from a method call like mathjs.eval(), since it matched on the substring "eval(" regardless of what preceded it — so it flagged mathjs.eval(req.body.eqn) as a candidate, and Module 4's AI validation correctly dismissed it as a sandboxed math evaluator, not the dangerous JS builtin (this was specifically called out as the standout moment in the original feedback on this project). The new AST rule requires the call target to be a bare identifier — func.type == "identifier", not member_expression — which structurally excludes mathjs.eval() from ever becoming a candidate in the first place, for the same reason someRegex.exec() is excluded from the command-injection rule.

This is a genuine tradeoff worth being explicit about, not just a strict improvement: fewer, cheaper AI validation calls (one less finding to batch and reason about), but it also means the AI layer no longer gets to demonstrate that specific piece of contextual judgment on this exact input, since the rule itself is now precise enough not to need it. The underlying philosophy hasn't changed — rules generate candidates, AI still validates the ones that remain — this just moves the precision earlier in the pipeline for the specific class of "obviously not the dangerous function by construction" cases, while leaving genuinely ambiguous cases (does this SQL query concatenation actually reach user input, is this hardcoded string actually a secret vs. a test fixture) for AI validation to reason about, same as before.

Design notes (for defending decisions)
Why keep the SQL/exec rules narrower (only flag locally-tracked dynamic strings) but make the innerHTML rule broader (flag any non-literal, including a bare parameter)? This was a deliberate asymmetry, not an oversight — documented directly in js_ts_rules.py next to _looks_dynamic_broad. db.query(someIdentifier) is extremely common with plainly-safe arguments in real code (constants, already-validated values), so flagging every bare identifier there would make the rule too noisy. el.innerHTML = someIdentifier doesn't have that problem — assigning any non-literal value to innerHTML, including a bare parameter, is precisely the XSS-relevant question, and function render(x) { el.innerHTML = x; } is the single most common real-world instance of this exact bug. This also matches the old regex version's behavior for this specific rule, so it's not a regression, just now implemented as an explicit, named decision instead of an implicit side effect of _looks_dynamic's regex heuristic.
Why does require('child_process').exec(cmd) still go undetected? _member_root_identifier only resolves a member expression's root when it bottoms out in a plain identifier; require('child_process') is a call expression, not an identifier, so the root can't be determined without evaluating what require() returns — real interprocedural reasoning, out of scope here for the same reason full taint tracking is out of scope (see the Module 3 design notes above). This is a pre-existing gap, not a Phase 2 regression — the old regex version couldn't catch this construct either. It's now an explicit test case (known_gap_require_child_process_exec_not_detected in safe_js.js) instead of a silent, undocumented one.
Why prebuilt tree-sitter wheels instead of building grammars from source? tree-sitter-javascript/tree-sitter-typescript ship prebuilt wheels for Linux/macOS/Windows on PyPI — no C compiler needed on Render or in CI, which matters since Render's build environment shouldn't need to be told to install build-essential just to parse JavaScript.
Why is Finding.function inference for anonymous functions (arrow functions, class fields) done by walking .parent rather than passed down explicitly? Tree-sitter doesn't have a built-in concept of "the variable this anonymous function was assigned to" — that relationship only exists one level up in the tree (variable_declarator, pair, assignment_expression, field_definition). Walking up once at the point of entering the function scope is simpler than threading an extra parameter through the whole traversal, and it's the same thing a human reading the code would do: look at what's around the anonymous function to name it.

## Phase 3 — Security Analysis Engine: bounded cross-function taint tracking

Extends the same-function variable tracking both `python_rules.py` and `js_ts_rules.py` already had so it can follow a tainted value **one function-call hop** further — a value built in caller A and passed as an argument to helper B is now caught at the sink inside B, not just when the sink and the dynamic-string-build happen in the same function.

This directly implements what both the original take-home feedback and this project's own earlier design notes called out as the explicit next step after tree-sitter: *"the cross-function taint tracking you mentioned rejecting for scope reasons."* Full interprocedural taint tracking (arbitrary call depth, aliasing across the whole call graph, a real fixpoint algorithm) is still out of scope — this is a deliberately bounded version, and the bound is enforced and tested, not just assumed.

**What changed:**
- `app/analyzer/python_rules.py` — two-pass analysis: pass 1 runs exactly as before (Phase 1 behavior) and, as a side effect, records which locally-defined functions were called with a dynamically-built argument, and at which position. If any were, pass 2 re-runs with those parameters pre-seeded as tainted. Also adds **alias propagation** (`q2 = q1` now taints `q2` too, not just direct f-string/concat assignments).
- `app/analyzer/js_ts_rules.py` — the identical two-pass design, adapted to tree-sitter traversal instead of `ast`.
- `app/parser/js_ts_parser.py` — added `extract_top_level_function_params()`, a small shared helper the analyzer uses to resolve call-site argument positions to actual parameter names.
- `tests/fixtures/cross_function_python.py`, `cross_function_js.js`, `cross_function_no_seed_python.py` — new fixtures covering the one-hop case, safe-only callers, alias propagation, an unproven-parameter case, and the two-hop scope limit.
- `tests/test_cross_function_python.py`, `tests/test_cross_function_js.py` — new, **21 tests**.

**158 total tests now**, all passing, verified in a clean venv matching CI exactly. 100% coverage on `python_rules.py`, 92% on `js_ts_rules.py`.

### How the two-pass design works, concretely

```python
def run_query(query):          # <- sink, no local dynamic-string build
    cursor.execute(query)

def handler(user_id):
    q = f"SELECT * FROM users WHERE id = {user_id}"
    run_query(q)                # <- caller passes a dynamically-built value
```

Before Phase 3: `run_query`'s `cursor.execute(query)` never fired, because `query` is just a parameter — nothing about it looks dynamic from inside `run_query` alone. After Phase 3: pass 1 notices `handler` calls `run_query` with a value that's tracked as dynamic (`q`), records `run_query`'s parameter at that position (`query`) as a taint candidate, and pass 2 re-runs with `query` pre-seeded — so `cursor.execute(query)` now fires, attributed correctly to `run_query` (the actual sink), with a finding description noting it arrived via a parameter rather than being built directly.

### Design notes (for defending decisions)

- **Why exactly one hop, not a fixpoint over the whole call graph?** A real fixpoint (keep re-seeding until nothing new is found, correctly handling cycles) is genuine taint-tracking/data-flow-analysis territory — the same complexity tradeoff this project has documented as out of scope since Module 3. One hop is a bounded, terminating, cheap-to-reason-about extension that catches the single most common real pattern (a thin wrapper function around a sink), tested explicitly with a two-hop case (`hop_a` -> `hop_b` -> sink) that's asserted to NOT fire — so the limit is a documented, tested fact about the tool, not a silent gap someone discovers by surprise.
- **Why does a function only get seeded if a caller passes it a *provably* dynamic value, not just any bare parameter?** Tested directly (`callerPassesUnprovenParameter` in the JS fixtures): if caller A's own parameter is itself untracked (no local taint, not itself seeded), passing it into B does NOT seed B. This avoids a cascade where "any parameter, anywhere" eventually taints everything — taint only flows from a *demonstrated* source (a literal dynamic-string build, ultimately) through however many hops are actually resolved.
- **Why is deduplication now load-bearing, not just a nice-to-have?** Running two full passes over the same file necessarily re-visits and re-flags anything that doesn't depend on cross-function seeding — without dedup by `(rule_id, file, line)`, every existing Phase 1/2 finding would be reported twice whenever cross-function seeding triggers a second pass at all. This was caught by the fixture test suite immediately (an early version of this doubled several findings before dedup was added) — a concrete example of the test suite paying for itself during development, not just after.
- **Why extend the SQL-injection and JS command-injection rules but leave `os.system`/Python's `eval`/`exec` rules unchanged?** Those Python rules already flag *any* non-literal argument (see Module 3 design notes above) — they were already maximally broad before Phase 3, so cross-function seeding has nothing to add for them. The rules that benefit are specifically the ones that require a value to be provably tracked as dynamic (`_dynamic_str_vars` / `_is_tainted_identifier`) rather than just "not a string literal" — extending tracking extends exactly those, and only those, which is why DVNA's and Flask's real-world finding counts are unchanged after this phase: the new capability adds coverage for a pattern (thin sink wrappers) that happens not to appear in either of those two specific codebases, not because the feature doesn't work.
- **Why not add a `confidence` field to the `Finding` schema instead of appending a sentence to `description`?** A schema change cascades into `/validate`, `ai/prompts.py`'s structured-output schema, and any report/UI code reading `Finding` fields — real work, and risk, for a Phase whose actual goal was the tracking logic itself. Appending a plain-language note to `description` gets the same practical benefit (a human or the AI validator reading the finding knows it's one hop removed from the literal dangerous code) with zero schema risk. Worth revisiting if a future phase wants findings sortable/filterable by confidence specifically.
- **Explicitly deferred, not attempted this phase**: constant propagation, formal sanitizer-function recognition (analysis showed most of the value is already captured for free — see the comment next to `_dynamic_str_vars.pop()` in `python_rules.py` — a value reassigned through *any* function call that isn't itself a recognized dynamic-string-builder already clears taint, which covers the common case without a hand-maintained sanitizer allowlist), and a `confidence` scoring field. Named here rather than silently skipped, consistent with how the rest of this README handles scope decisions.

## Phase 4 — Security Rule Engine: 6 new rules, OWASP mapping, remediation guidance, rule configuration

What changed:

app/analyzer/rules.py — every rule (existing and new) now carries an owasp field (OWASP Top 10 2021 category) alongside its existing CWE, plus a remediation field: short, general fix guidance available even from the rule-only /analyze endpoint, before any AI validation runs.
6 new rules, one pair (Python + JS/TS equivalent) each:
Rule	CWE	OWASP	What it catches
path-traversal-open (Python) / path-traversal-fs (JS/TS)	CWE-22	A01:2021-Broken Access Control	open() / fs.readFile(Sync) etc. called with a dynamically-built path
insecure-random-token (both)	CWE-330	A02:2021-Cryptographic Failures	A token/password/secret-named variable assigned from random/Math.random() instead of a CSPRNG
flask-cookie-missing-secure-flag (Python) / cookie-missing-secure-flag (JS/TS)	CWE-614	A05:2021-Security Misconfiguration	set_cookie() / res.cookie() missing secure/httponly flags
app/schemas/findings.py — Finding gains owasp: Optional[str] and remediation: Optional[str], both additive/backward-compatible (existing code reading a Finding doesn't break; anything not setting them just gets None).
Rule configuration (both analyzers): rules can be disabled via a CODEGUARDIAN_DISABLED_RULES environment variable (comma-separated rule IDs), e.g. CODEGUARDIAN_DISABLED_RULES=weak-crypto-hash,hardcoded-secret. Deliberately an env var, not a new config-file format — this project already configures everything else that way (MAX_REPO_SIZE_MB, CLONE_TIMEOUT_SECONDS, the OpenAI settings in core/config.py), so this stays consistent rather than introducing a second, different mechanism for one feature.
New fixtures and 28 new tests: 3 new true/false-positive pairs per language in the existing rule-fixture files, plus tests/test_rule_configuration.py covering the disabling mechanism specifically — including the interaction with Phase 3's cross-function tracking (disabling a rule must suppress it in both the direct and the cross-function-seeded case).

187 total tests now, all passing, verified in a clean venv matching CI exactly. 100% coverage on python_rules.py, 94% on js_ts_rules.py.

A real find while verifying against Flask: the new cookie rule surfaces a genuine false positive, on Flask's own code

Re-ran the same Flask verification from Module 3/Phase 3 with the new rules included. Result: 9 candidates, up from 7 — the two new ones are both flask-cookie-missing-secure-flag, one in a test file and one in src/flask/sessions.py's own save_session method — real production Flask code, not a test fixture.

Looking at the actual line:

python
response.set_cookie(
    name, val, expires=expires,
    httponly=httponly, domain=domain, path=path,
    secure=secure, partitioned=partitioned, samesite=samesite,
)

This is a false positive at the rule level, and an instructive one: secure and httponly genuinely are being set here — just as variables computed from the app's cookie config elsewhere in the method, not as literal True/False. The rule's _has_kwarg_true() check only recognizes a literal ast.Constant equal to True, by design (the same conservative "only count what's provably true" approach _cookie_options_are_secure uses on the JS/TS side) — so a correctly-configured-but-variable-driven call looks identical, from the rule's perspective, to one that's missing the flags entirely.

This is the same category of false positive as the mathjs.eval() and Flask HMAC-SHA1 cases documented in Module 3/4 above: the rule can't see semantic intent, only syntax, so it correctly over-flags rather than silently missing genuinely insecure calls elsewhere — and it's exactly what Module 4's AI validation exists to resolve, by actually reading the surrounding code (this rule's finding includes a 6-line snippet window, which is enough for a human or the AI to see secure=secure is a passed-through variable, not a hardcoded False). Worth being upfront about rather than only showcasing the rules that looked clean on first real-world test.

Design notes (for defending decisions)
Why CWE and OWASP, not just one? Different audiences/tools expect different taxonomies — some security dashboards and compliance checklists are organized by OWASP Top 10 category, others by CWE. Carrying both costs nothing (it's static metadata) and means this tool's output maps cleanly onto whichever one a given team already uses.
Why is remediation separate from Module 4's patch_suggestion? They serve different moments: remediation is general, always-available guidance from the rule itself ("use parameterized queries") visible even from the free /analyze endpoint with no API key. patch_suggestion is Module 4's AI-generated, code-specific fix for this exact line. Having both means a candidate finding is still useful before spending anything on AI validation, and the AI's answer is additive rather than the only source of guidance.
Why an environment variable for rule configuration instead of a .codeguardian.yml config file? A new file format is a bigger surface: parsing, validation, docs for its schema, and a second way to configure something this project already configures via env vars everywhere else. A comma-separated env var is one line to explain and reuses infrastructure (Render environment variable settings) the project already relies on. Worth revisiting if per-rule severity overrides or path-based rule exclusions are ever needed — those genuinely don't fit an env var well and would justify the added complexity of a config file at that point.
Why derive JS_TS_RULE_IDS from RULES.keys() instead of listing them by hand (a mid-phase fix, not new to this phase)? The test file previously hardcoded which rules were JS/TS-only, which meant the "does every rule have a fixture" meta-test could never actually catch a new rule missing its fixture — the hardcoded set just silently stayed "complete" regardless of what got added to rules.py. Caught this while adding the new rules (the meta-test should have failed and didn't), fixed it to derive from RULES.keys() minus an explicit Python-only exclusion list — the same pattern test_python_rules.py already used correctly. A good example of why the test suite itself benefits from continued scrutiny, not just the code it's testing.
Custom rule support (letting a user define their own detection pattern without editing Python/tree-sitter code) was explicitly not attempted this phase. It's a materially bigger feature — a rule needs some kind of pattern DSL or config schema, an execution path that doesn't just eval() user-provided code (ironic given rule #dangerous-eval-exec), and real thought about what "custom rule" even means across two very different detection engines (ast vs. tree-sitter). Worth a dedicated phase of its own rather than a rushed addition here.