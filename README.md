# CodeGuardian AI

AI-powered SAST (Static Application Security Testing) agent. Give it a public GitHub repo and it clones it, parses every Python/TypeScript/JavaScript file, runs a 20-rule security analyzer with bounded cross-function taint tracking across both languages, then uses an LLM to validate each candidate finding down to a smaller set of higher-confidence, explained, patch-suggested results.

**Live demo:** [codeguardian-ai-ka1d.onrender.com](https://codeguardian-ai-ka1d.onrender.com/)
**Repository:** [github.com/Purvi1407/codeguardian-ai](https://github.com/Purvi1407/codeguardian-ai)

440 tests · 97% coverage across the entire `app/` package · verified in a clean venv matching CI on every phase

---

## Table of contents

- [Quick start](#quick-start)
- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Build history](#build-history)
  - [Module 1 + 2 — Repository Processor & Parser](#module-1--2--repository-processor--parser)
  - [Module 3 — Rule-Based Analyzer](#module-3--rule-based-analyzer)
  - [Module 4 — AI Validation](#module-4--ai-validation)
  - [Module 3 extended — TypeScript/JavaScript rules](#module-3-extended--typescriptjavascript-rules)
  - [Browser UI](#browser-ui)
  - [Deployment](#deployment)
  - [Phase 1 — Foundation & Safety](#phase-1--foundation--safety-automated-test-suite)
  - [Phase 2 — Parsing Engine](#phase-2--parsing-engine-tree-sitter-for-jstsjsx)
  - [Phase 3 — Security Analysis Engine](#phase-3--security-analysis-engine-bounded-cross-function-taint-tracking)
  - [Phase 4 — Security Rule Engine](#phase-4--security-rule-engine-6-new-rules-owasp-mapping-remediation-guidance-rule-configuration)
  - [Phase 5 — AI Intelligence](#phase-5--ai-intelligence-validation-caching-retryfallback-handling-and-a-real-test-suite-for-module-4)
  - [Phase 6 — Developer Experience](#phase-6--developer-experience-filters-search-and-the-first-api-level-test-suite)
  - [Phase 7 — Dashboard & UX](#phase-7--dashboard--ux-risk-score-severity-distribution-filter-ui-and-a-first-pass-at-frontend-testing)
  - [Phase 8 — CI/CD & Integration](#phase-8--cicd--integration-a-cli-sarif-output-github-actions-pr-scanning-and-baseline-support)
  - [Phase 9 — Learning & Platform](#phase-9--learning--platform-a-real-feedback-store-rule-effectiveness-stats-and-a-bug-caught-while-building-it)
  - [Phase 10 — Production Quality](#phase-10--production-quality-the-final-phase)
- [Known dependency conflict (fixed)](#known-dependency-conflict-fixed)
- [Using a free provider instead of paid OpenAI credits](#using-a-free-provider-instead-of-paid-openai-credits)

For a shorter, non-chronological map of the finished system, see **[ARCHITECTURE.md](./ARCHITECTURE.md)**.

---

## Quick start

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Open `http://localhost:8000/` for the browser UI, or call the API directly:

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/pallets/flask"}'
```

Run the test suite:

```bash
cd backend
pip install -r requirements-dev.txt
pytest tests/ -v --cov=app --cov-report=term-missing
```

## What it does

- **Clones** a public GitHub repo (shallow, `--depth 1`, size- and timeout-limited).
- **Parses** every `.py`/`.ts`/`.tsx`/`.js`/`.jsx` file — Python via the stdlib `ast` module, TS/JS/TSX via tree-sitter.
- **Analyzes** with 20 security rules across both languages (SQL injection, command injection, path traversal, insecure deserialization, weak crypto, hardcoded secrets, insecure randomness, missing cookie flags, JWT algorithm confusion, XSS, CORS misconfiguration, and more), each mapped to CWE and OWASP Top 10, with bounded cross-function taint tracking and alias propagation.
- **Validates** every candidate with an LLM (batched, cached, retried on transient failure) to cut noisy candidates down to a smaller set of explained, patch-suggested, confidence-rated findings.
- **Serves** results via a JSON API, a browser dashboard, or a CLI you can drop straight into CI — with SARIF output for GitHub's native code scanning UI, a security gate with real exit codes, PR-diff scanning, and baseline support.
- **Remembers**: every AI verdict is persisted to a feedback store, so `/stats/rules` can show which rules are actually earning their keep over time.

## Architecture

See **[ARCHITECTURE.md](./ARCHITECTURE.md)** for the full pipeline diagram, the two entry points (API and CLI) and why they share code, the two persistence mechanisms and why their formats differ, and an explicit list of what's deliberately not built yet.

---

## Build history

The sections below are kept in the order they were built — each one documents what changed, what was verified (and how), and the design decisions behind it, including the mistakes caught along the way. This is the detailed record; `ARCHITECTURE.md` is the fast version.

### Module 1 + 2 — Repository Processor & Parser

Validates a GitHub URL, shallow-clones it into a temp dir, cleans up after itself (even on failure), then walks the repo, finds `.py`/`.ts`/`.tsx`/`.js`/`.jsx` files, and extracts functions/classes with line numbers.

- Python uses the `ast` module — accurate line numbers, args, method/class attribution.
- TS/JS originally used regex as a documented MVP limitation — **replaced with tree-sitter in Phase 2** (see below).

Tested live against `pallets/flask` (83 files, 0 parse errors) and against invalid/nonexistent repo URLs (clean 400s, no orphaned temp dirs).

**Design notes:**
- **Why `ast` over regex for Python but regex for TS/JS (at the time)?** `ast` is stdlib, zero dependencies, and gives exact line numbers for free. Tree-sitter would give the same for TS/JS but adds a build dependency; regex was the pragmatic MVP call under a tight timeline, called out explicitly rather than hidden.
- **Why always clean up the clone, even on success?** Each scan is treated as stateless. Noted as a TODO in `api/scan.py` so a future change to short-TTL caching doesn't look accidental.
- **Why `--depth 1` clone?** Only current-state source is needed, not history — dramatically faster and safer against large repos.

### Module 3 — Rule-Based Analyzer

Added `app/analyzer/rules.py` (rule metadata) + `app/analyzer/python_rules.py` (AST-based detection) + `POST /analyze` (full Module 1+2+3 pipeline).

**10 rules implemented initially**, each backed by a CWE reference:

| Rule | Severity | What it catches |
|---|---|---|
| `sql-injection-string-build` | high | `execute()` called with f-string/concat/`.format()` — including tracked through a local variable |
| `command-injection-shell-true` | high | `subprocess.*(shell=True)` |
| `command-injection-os-system` | high | `os.system()`/`os.popen()` with a non-literal argument |
| `hardcoded-secret` | medium | password/token/api_key-named variables assigned string literals |
| `insecure-deserialization-pickle` | high | `pickle.load()`/`loads()` |
| `insecure-deserialization-yaml` | high | `yaml.load()` without `Loader=SafeLoader` |
| `dangerous-eval-exec` | high | `eval()`/`exec()` with a non-literal argument |
| `weak-crypto-hash` | low | `hashlib.md5()`/`sha1()` |
| `debug-mode-enabled` | medium | `.run(debug=True)` |
| `tls-verification-disabled` | high | HTTP calls with `verify=False` |

Verified against a deliberately vulnerable test file: 11/11 expected findings fired, 0 false positives on a parameterized-query control function in the same file. Also verified end-to-end against `pallets/flask` (real 83-file repo): 7 candidate findings, including a genuine example of why Module 4 is necessary — `config.py`'s `from_pyfile()` uses `exec()` legitimately to load a trusted local config file, but a pattern-only rule can't distinguish that from a real code-injection bug.

**Design notes:**
- **Why pattern-matching, not taint tracking?** True taint analysis needs a data-flow graph across the whole call chain — out of scope for the MVP. This is explicitly a candidate generator: fast, cheap, intentionally over-inclusive, with Module 4 doing the precision work.
- **Why track variables within a function for SQL injection, but not across functions (at the time)?** Cross-function tracking needs call-graph resolution — the same complexity tradeoff as full taint tracking. Single-function tracking catches the extremely common `query = f"..."; cursor.execute(query)` pattern cheaply. *(Extended with bounded cross-function tracking in Phase 3.)*
- **Why only Python gets analyzer rules at first?** The TS/JS parser was already regex-based — building AST-quality rules on top of a regex-quality parser would be false precision. Sequencing: get Python right first, then decide on tree-sitter.

### Module 4 — AI Validation

Added `app/ai/client.py` (OpenAI client + config), `app/ai/prompts.py` (system prompt + JSON schema), `app/ai/validator.py` (batching + merge logic), `POST /validate` (full Module 1+2+3+4 pipeline).

**This is the actual product.** Everything before this point produces candidates; `/validate` is what turns them into the "fewer, higher-confidence findings" the whole philosophy is built around. Response includes both `findings` (AI-verified) and `dismissed` (AI-rejected candidates, kept for transparency).

> **What's tested vs. not:** the real OpenAI API call cannot be made from this development environment (network sandbox doesn't allow `api.openai.com`). What was verified instead, with a mocked API response: batch → merge logic correctly maps AI judgments back onto the right findings; a finding the model "drops" fails safe (kept as unverified/low-confidence) instead of silently disappearing; missing `OPENAI_API_KEY` fails fast before cloning any repo; server starts cleanly with all routes registered. **The real API call itself needs to be tested with a live key against a real repo** — flagged explicitly rather than claimed as tested when it wasn't. *(Phase 5 later added a full mocked test suite for this module, 40 tests — see below.)*

**Setup:**
```bash
export OPENAI_API_KEY=sk-...
export OPENAI_MODEL=gpt-4o  # optional — defaults to gpt-4o-mini for cost
```

**Design notes:**
- **Why batch findings into one request instead of one call per finding?** Direct cost/latency tradeoff — batching 8 per call cuts a 50-candidate repo from ~50 calls to ~7. Structured output (JSON schema, `strict: true`) is used instead of free-text parsing for reliability without giving up the savings.
- **Why fail-fast on missing API key before cloning?** No reason to spend clone/parse time only to fail at the last step.
- **Why keep `dismissed` findings instead of dropping them?** Transparency, and it's the seed of a future feedback loop — *(built in Phase 9)*.
- **Why is the model configurable via `OPENAI_MODEL` rather than hardcoded?** A cost/quality knob the operator should control, not a decision baked into the code.

### Module 3 extended — TypeScript/JavaScript rules

Added `app/analyzer/js_ts_rules.py`: 8 regex-based rules for JS/TS. Wired into the same `/analyze` and `/validate` pipeline.

Verified against a deliberately vulnerable test file (8/8 findings fired, 0 false positives) and against a real, unfamiliar repo (`appsecco/dvna`), correctly finding its 3 genuine documented vulnerabilities with zero noise after fixing two bugs surfaced by that exact test: the `exec()` regex initially also matching `RegExp.prototype.exec()`, and vendor/minified bundles being scanned as if they were developer code.

> This whole section was **replaced by a tree-sitter rewrite in Phase 2** — the regex approach documented here was always flagged as the top-priority next step, and it was taken.

### Browser UI

Added `app/static/index.html` — a single-page frontend served at `GET /`. No build step, no separate frontend deployment: plain HTML/CSS/JS, calling the same `/analyze` and `/validate` endpoints, served by the same FastAPI app.

Two modes: **Quick scan** (`/analyze`, free, no API key) and **Full validate** (`/validate`, AI-reviewed, shows verified + dismissed findings).

**Design notes:**
- **Why no framework?** Zero build step, zero deployment complexity — the whole UI is one static file the backend already serves.
- **The candidates → verified gauge bar** visualizes the core product philosophy ("fewer, higher-confidence findings") as an actual number you watch shrink.
- **Dismissed findings are visible but collapsed by default** — transparency without cluttering the primary view.

### Deployment

Deployed on [Render](https://render.com) via the included Dockerfile. `OPENAI_API_KEY` (and optionally `OPENAI_BASE_URL` / `OPENAI_MODEL` for the Groq-compatible free tier) set as environment variables in the Render service settings — never committed to the repo.

---

### Phase 1 — Foundation & Safety: automated test suite

Added `backend/tests/` — a pytest suite covering the Python rule engine and parser, plus a GitHub Actions workflow that runs it on every push/PR.

**61 tests, 100% statement coverage on `python_rules.py`.**

```
backend/tests/
  fixtures/
    vulnerable_python.py     # one true-positive case per rule (21 functions)
    safe_python.py           # tricky-but-safe / false-positive regressions (21 functions)
    malformed/
      syntax_error.py
      empty.py
      only_comments.py
      unicode_content.py
  conftest.py
  test_python_rules.py
  test_python_parser.py
  test_edge_cases.py
```

```bash
cd backend
pip install -r requirements-dev.txt
pytest tests/ -v --cov=app.analyzer --cov=app.parser --cov-report=term-missing
```

**Design notes:**
- **Why assert on function name instead of line number?** Line-number assertions break every time a fixture file gets a comment added or a case reordered. Every fixture function is named `<rule_id>__<variant>`, so tests assert "this function fires this rule" independent of where it sits.
- **Why two meta-tests (`TestCoverageIsComplete`)?** Catches drift in both directions: a rule added with no fixture (silent gap), or a fixture added with no assertion (silent no-op test).
- **Why is the false-positive fixture the same size as the true-positive one?** A rule engine that never checks its own precision is only half-tested — includes the exact category of case AI validation is designed to catch by hand (e.g. `SandboxedEvaluator.eval()`, mirroring the real `mathjs.eval()` case from manual DVNA testing).
- **Verified the suite actually catches regressions:** temporarily disabled the SQL injection rule's trigger, confirmed 4 tests failed with a clear message, restored it, confirmed all 61 pass again.
- **Why is JS/TS excluded from this suite?** `js_ts_rules.py` was still regex-based, slated for a tree-sitter rewrite — writing rigorous tests against logic about to be replaced would mean rewriting them immediately after.

### Phase 2 — Parsing Engine: tree-sitter for JS/TS/TSX

Replaced the regex-based JS/TS parser and analyzer with tree-sitter — the single item both the original take-home feedback and this project's own README called out as the highest-leverage next step.

**What changed:**
- `app/parser/ts_grammars.py` — loads the JS/TS/TSX tree-sitter grammars once, shared by parser and analyzer.
- `app/parser/js_ts_parser.py` — rewritten to walk a real parse tree instead of matching regex per line.
- `app/analyzer/js_ts_rules.py` — rewritten so all 8 rules match on AST node shape, with same-function taint tracking mirroring `python_rules.py`.
- New fixtures + `tests/test_js_ts_rules.py`, `tests/test_js_ts_parser.py` — **77 tests, 92% coverage on the rules engine, 94% on the parser.**
- `requirements.txt` — added `tree-sitter`, `tree-sitter-javascript`, `tree-sitter-typescript` (prebuilt wheels, no compiler needed).

**138 total tests now**, verified in a clean venv matching CI exactly.

**What actually got fixed, concretely:**
- **Accurate `end_line`** — the old parser's own comment admitted `# regex approach can't reliably find the closing brace`.
- **Method and class-field extraction** — the old parser had no concept of a method inside a class at all; now extracts `method_definition` nodes and the common React `handleClick = () => {}` pattern.
- **`Finding.function` is no longer always `None`** — every JS/TS finding now carries its real enclosing function name, including through arrow functions and class methods.
- **Same-function variable taint tracking**, mirroring the Python side.
- **The `RegExp.exec()` vs `child_process.exec()` false positive is resolved structurally**, not by regex hack — no way for the two to be confused, by construction.

**An unexpected, genuinely positive side effect:** re-running the DVNA verification against the new AST engine returned 2 findings, both real — down from 3 candidates under the old regex version, because the AST rule structurally excludes `mathjs.eval()` from ever becoming a candidate (it requires a bare identifier call, not a member expression), the same reasoning that already excludes `someRegex.exec()`. A genuine tradeoff, not a pure win: fewer, cheaper AI calls, but the AI layer no longer gets to demonstrate that specific piece of contextual judgment on this input, since the rule is now precise enough not to need it.

**Design notes:**
- **Why keep SQL/exec rules narrower but make innerHTML broader?** A deliberate, documented asymmetry — `db.query(someIdentifier)` is commonly safe in real code, but `el.innerHTML = someIdentifier` (including a bare parameter) is precisely the XSS-relevant question regardless.
- **Why does `require('child_process').exec(cmd)` still go undetected?** Resolving a member expression's root requires it to bottom out in a plain identifier; `require(...)` is a call expression, not an identifier — real interprocedural reasoning, out of scope. Pre-existing gap, not a regression, now an explicit test case instead of a silent one.
- **Why prebuilt tree-sitter wheels?** No C compiler needed on Render or in CI.

### Phase 3 — Security Analysis Engine: bounded cross-function taint tracking

Extends the same-function variable tracking both analyzers already had so it can follow a tainted value **one function-call hop** further — a value built in caller A and passed to helper B is now caught at the sink inside B.

**What changed:**
- `app/analyzer/python_rules.py` — two-pass analysis: pass 1 runs as before and records which locally-defined functions were called with a dynamically-built argument; pass 2 re-runs with those parameters pre-seeded as tainted. Also adds **alias propagation** (`q2 = q1` now taints `q2` too).
- `app/analyzer/js_ts_rules.py` — identical two-pass design, adapted to tree-sitter traversal.
- `app/parser/js_ts_parser.py` — added `extract_top_level_function_params()`.
- New fixtures + `tests/test_cross_function_python.py`, `tests/test_cross_function_js.py` — **21 tests.**

**158 total tests now**, 100% coverage on `python_rules.py`, 92% on `js_ts_rules.py`.

**How it works, concretely:**

```python
def run_query(query):          # sink, no local dynamic-string build
    cursor.execute(query)

def handler(user_id):
    q = f"SELECT * FROM users WHERE id = {user_id}"
    run_query(q)                # caller passes a dynamically-built value
```

Before Phase 3, `run_query`'s `cursor.execute(query)` never fired — `query` looks like just a parameter. After Phase 3, pass 1 notices `handler` calls `run_query` with a tracked-dynamic value, records the parameter as a taint candidate, and pass 2 re-runs with it pre-seeded — so it now fires, attributed correctly to `run_query`, with a note that it arrived via a parameter.

**Design notes:**
- **Why exactly one hop, not a fixpoint over the whole call graph?** A real fixpoint is genuine taint-tracking/data-flow-analysis territory, the same complexity tradeoff documented as out of scope since Module 3. Tested explicitly with a two-hop case asserted to *not* fire — a documented, tested fact about the tool, not a silent gap.
- **Why does a function only get seeded if a caller passes it a provably dynamic value, not just any bare parameter?** Avoids a cascade where "any parameter, anywhere" eventually taints everything.
- **Why is deduplication now load-bearing?** Running two passes necessarily re-visits everything that doesn't depend on seeding — without dedup, every Phase 1/2 finding would double whenever cross-function seeding triggers at all. Caught by the fixture suite during development.
- **Why extend SQL/JS-exec rules but leave `os.system`/`eval`/`exec` unchanged?** Those already flagged any non-literal argument — maximally broad already, nothing for cross-function seeding to add.
- **Why not a `confidence` schema field instead of appending a note to `description`?** A schema change cascades into `/validate`, the AI prompt schema, and report/UI code — real risk for a phase whose actual goal was the tracking logic.
- **Explicitly deferred:** constant propagation, formal sanitizer-function recognition (analysis showed most value already captured for free by the existing taint-clearing logic), a `confidence` scoring field.

### Phase 4 — Security Rule Engine: 6 new rules, OWASP mapping, remediation guidance, rule configuration

**What changed:**
- `app/analyzer/rules.py` — every rule now carries an `owasp` field (OWASP Top 10 2021 category) alongside CWE, plus a `remediation` field available even from the free `/analyze` endpoint.
- **6 new rules**, one pair (Python + JS/TS) each:

| Rule | CWE | OWASP | What it catches |
|---|---|---|---|
| `path-traversal-open` / `path-traversal-fs` | CWE-22 | A01:2021-Broken Access Control | Dynamically-built path passed to a file read/write |
| `insecure-random-token` (both) | CWE-330 | A02:2021-Cryptographic Failures | Token/password-named var from `random`/`Math.random()` instead of a CSPRNG |
| `flask-cookie-missing-secure-flag` / `cookie-missing-secure-flag` | CWE-614 | A05:2021-Security Misconfiguration | Cookie set without `secure`/`httponly` flags |

- `app/schemas/findings.py` — `Finding` gains `owasp` and `remediation`, both additive/backward-compatible.
- **Rule configuration**: rules can be disabled via `CODEGUARDIAN_DISABLED_RULES` (comma-separated), consistent with how everything else in this project is already configured via env vars.
- **28 new tests**, including the interaction with Phase 3's cross-function tracking (disabling a rule must suppress it in both the direct and seeded case).

**187 total tests now**, 100% coverage on `python_rules.py`, 94% on `js_ts_rules.py`.

**A real find while verifying against Flask:** the new cookie rule flagged real production code in `src/flask/sessions.py`'s `save_session` method — a genuine false positive, since `secure`/`httponly` were being passed as variables computed elsewhere, not literal `True`/`False`. The rule can't see semantic intent, only syntax, so it correctly over-flags rather than silently missing real cases — exactly what Module 4's AI validation exists to resolve.

**Design notes:**
- **Why CWE and OWASP, not just one?** Different audiences/tools expect different taxonomies; carrying both costs nothing.
- **Why is `remediation` separate from `patch_suggestion`?** `remediation` is general and always available (no API key needed); `patch_suggestion` is AI-generated and code-specific.
- **Why an env var instead of a config file?** A new file format is a bigger surface (parsing, validation, docs) for one feature, when this project already configures everything else via env vars.
- **Why derive `JS_TS_RULE_IDS` from `RULES.keys()` instead of a hand-maintained list (a mid-phase fix)?** The old hardcoded set meant the "does every rule have a fixture" meta-test could never actually catch a new rule missing coverage — caught while adding these rules, fixed to derive properly.
- **Custom rule support was explicitly not attempted** — a materially bigger feature (pattern DSL, safe execution path, cross-engine design) deserving its own phase.

### Phase 5 — AI Intelligence: validation caching, retry/fallback handling, and a real test suite for Module 4

**What changed:**
- `app/ai/cache.py` — file-based cache (survives a server restart), keyed on `(prompt version, rule_id, snippet)` — deliberately not file/line, so the same vulnerable pattern still hits the cache after an unrelated edit shifts line numbers.
- `app/ai/validator.py` — checks the cache before spending an API call; retries transient failures (rate limits, timeouts, 5xx) with exponential backoff, up to `AI_VALIDATION_MAX_RETRIES`; optional opt-in fallback model via `AI_VALIDATION_FALLBACK_MODEL`.
- `app/ai/prompts.py` — added `PROMPT_VERSION`, bumped whenever the prompt changes in a way that could change judgments, consumed by the cache key.
- **40 new tests**, all fully mocked (no real API calls, consistent with this environment's network constraint). Module 4's first-ever committed test file.

**227 total tests now**, 100% coverage on `validator.py` and `client.py`, 92% on `cache.py`.

**Design notes:**
- **Why cache on `(rule_id, snippet)` instead of the whole finding?** Two findings with the same vulnerable pattern should get the same judgment regardless of file/line — caching on the full finding would almost never hit on a re-scan.
- **Why is `PROMPT_VERSION` hand-bumped, not a hash of the prompt text?** A hash would invalidate the whole cache on a no-op whitespace edit; a hand-bumped version signals "this could plausibly change judgments."
- **Why exponential backoff?** A rate-limit error means "you're calling too fast right now" — instant retry just repeats the problem.
- **Why does the fallback model only get one attempt?** By the time it triggers, the primary has already exhausted its retries — a full retry budget on the fallback would roughly double worst-case latency.
- **A real bug caught while writing tests:** `AI_VALIDATION_FALLBACK_MODEL` was first written as a module constant, evaluated once at import time — meaning `monkeypatch.setenv` in a test had no effect. Fixed to read fresh via a function each call, matching the pattern Phase 4's rule-disabling already used for the same reason.
- **Patch/diff generation and formal confidence calibration were explicitly deferred** — the former needs a real prompt/schema change, the latter needs historical outcome data that doesn't exist yet (that's what Phase 9 builds).

### Phase 6 — Developer Experience: filters, search, and the first API-level test suite

**What changed:**
- `app/services/finding_filters.py` — severity, language, rule ID, and free-text search filters.
- `app/schemas/scan.py` — `ScanRequest` gains four optional fields, all additive.
- Wired into `/scan`, `/analyze`, `/validate` — **on `/validate` specifically, filtering happens BEFORE AI validation runs**, so a filtered-out finding never costs an API call.
- **43 new tests** (26 pure logic + 17 API-level via `TestClient`) — the **first committed test file exercising the API/route layer at all**, which as a side effect also covers every documented error path (400/500/502) for the first time too.

**270 total tests now**, 100% coverage on `finding_filters.py` and all three API route files.

**Why dismiss/resolve/history aren't in this phase:** they require a finding to have a stable identity persisting across separate scans, plus somewhere to store that state — this project is deliberately stateless end-to-end at this point. Building that properly overlaps substantially with Phase 9's planned feedback store, so both were deferred to be designed together rather than building persistence twice.

**Design notes:**
- **Why filter on the `ScanRequest` body instead of a GET query-param endpoint?** No persisted findings exist yet to filter after the fact — filtering as part of the request that produces the results is the natural fit for a stateless pipeline.
- **Why is rule filtering exact-match but search is substring?** `rule_filter` is for "give me exactly these rules" (a UI checkbox list); a partial match there would be a correctness footgun.
- **Why does an unresolvable file get excluded, not included, when a language filter is active?** Excluding what can't be confirmed to match is the safer default for a filter whose purpose is narrowing.

### Phase 7 — Dashboard & UX: risk score, severity distribution, filter UI, and a first pass at frontend testing

**What changed:**
- `app/services/dashboard.py` — computes a `ScanSummary` (risk score 0–100 capped, severity distribution, rule distribution). On `/validate`, computed over verified findings only, not dismissed.
- `app/static/index.html` — added a dashboard panel and a filters row (severity checkboxes, search) wired to send filters as part of the request — using backend filtering that previously had no UI exposing it at all. Empty-state messaging now distinguishes "no findings at all" from "no findings matched your filters."
- **21 new tests** (12 Python + 9 Node, via Node's built-in test runner) — **the first frontend tests this project has ever had.** CI gained a second job running the Node tests independently.

**286 Python tests + 9 Node tests**, 100% coverage on `dashboard.py` and all API route files.

**An honest limit, stated plainly:** no headless browser is available in this environment, so anything DOM-touching in `index.html` isn't unit-tested — only the two genuinely pure functions (`riskClass()`, `hasActiveFilters()`) are, pulled out and tested in isolation. HTML tag balance and JS syntax validity are mechanically verified, which catches a broken build but not a broken *look* — visual verification is still an open ask, same as the original Browser UI section.

**Design notes:**
- **Why cap the risk score at 100?** An unbounded weighted sum makes a 100-finding repo dwarf a 5-finding one even if both are "clearly bad" — capping keeps the number interpretable regardless of repo size.
- **Why weren't the severity weights calibrated against real data?** No historical outcome data exists yet — same reason Phase 5 deferred confidence calibration to Phase 9.
- **Why compute the summary server-side instead of client-side?** Consistency (any future API client gets it too) and testability (pytest cases are a stronger guarantee than eyeballing a render).

### Phase 8 — CI/CD & Integration: a CLI, SARIF output, GitHub Actions PR scanning, and baseline support

**What changed:**
- `app/cli.py` — `python -m app.cli --path <dir>` runs Module 1-3 directly against a local directory, no clone or API key. Supports `--format {text,json,sarif}`, `--fail-on {low,medium,high}` (a real security gate with a real exit code), `--baseline`/`--write-baseline`, and `--changed-only --base-ref <ref>` for PR-diff scanning via `git diff`.
- `app/reports/sarif.py` — converts findings to SARIF 2.1.0 for GitHub's native code scanning UI, pulling rule metadata from the same `RULES` dict everything else uses.
- `app/services/baseline.py` — a committed baseline snapshot lets a team adopt this tool on an existing codebase without every pre-existing finding blocking the next PR. Fingerprinted on `(rule_id, file, function, snippet)`, not `line`, for the same reason as the Phase 5 cache key.
- `.github/workflows/pr-security-scan.yml` — a complete working example, dogfooded on this project's own repo: scans changed files, uploads SARIF, fails the check on a high-severity finding.
- **57 new tests**, including real subprocess-driven `git` repos to test `--changed-only` end-to-end, not mocked.

**343 total tests now**, 100% coverage on `sarif.py` and `baseline.py`, 97% on `cli.py`.

**Design notes:**
- **Why does the CLI re-run Modules 1-3 directly instead of calling the deployed API?** A CI job already has the repo checked out — the CLI needs nothing but a Python environment, no network or server dependency.
- **Why doesn't the CLI do AI validation by default?** A CI gate shouldn't have a hard dependency on an external API or cost real money on every push by default; the free rule-based tier is the right default.
- **Why does `--changed-only` filter results after scanning everything, not before?** Named explicitly rather than left implicit — this narrows what's reported, not how much work the scan does. A real optimization worth doing if scan time on a large repo actually becomes a bottleneck, not proven necessary yet.
- **Why `continue-on-error` + a separate final step in the GitHub Action?** If the gate step stops the job immediately on failure, the SARIF upload never runs — meaning a failed PR check would show a red X with no detail, exactly the failure case a security tool should explain best, not worst.

### Phase 9 — Learning & Platform: a real feedback store, rule effectiveness stats, and a bug caught while building it

The persistence layer three earlier phases already pointed at without building. It exists now.

**What changed:**
- `app/services/feedback_store.py` — SQLite-backed. Every `/validate` call records each verdict and a scan-level summary.
- `app/api/stats.py` — `GET /stats/rules` (dismissal rate per rule, `needs_review=True` once a rule has enough samples and a high enough dismissal rate) and `GET /stats/scans?repository=...&limit=...` (scan history, most recent first).
- `app/api/validate.py` — records to the feedback store after every scan, best-effort so a storage failure degrades gracefully rather than breaking the response.
- **28 new tests.**
- **A genuine bug fix, unrelated to this phase's feature work:** `.gitignore` had `backend/cache/` for the Phase 5 cache, but `BASE_DIR` actually resolves to the *repository root* — the real cache file had been living at `<repo root>/cache/...` the whole time, a path the gitignore entry never matched. Fixed alongside adding `data/` for this phase's SQLite file.

**369 total tests now**, 100% coverage on all three new files.

**The bug that almost shipped twice:** while writing the "needs review" thresholds, the exact same mistake Phase 5 already documented catching was made again — module-level constants evaluated once at import time, immune to `monkeypatch.setenv` in tests. Caught by an unexpectedly failing test, fixed the same way Phase 5 was: read fresh via a function. Worth naming plainly — knowing about a bug class doesn't prevent repeating it, it just makes it faster to catch the second time.

**Design notes:**
- **Why SQLite instead of the JSON approach the cache and baseline both use?** Those are single-key-lookup or whole-snapshot use cases; this phase needs real aggregation (`GROUP BY`, `COUNT`, `ORDER BY ... LIMIT`) across an unbounded, growing history — SQLite does that with an index, a JSON file re-read-and-recomputed every request would not scale.
- **Why does `needs_review` only ever get read by a person, never auto-feeding back into `CODEGUARDIAN_DISABLED_RULES`?** A high dismissal rate might mean a rule needs tightening, or might mean the AI validation layer is correctly doing its job on a rule that's intentionally broad — those look identical in the aggregate stat, and only a person reading the actual dismissed findings can tell them apart.
- **Known limitation, stated plainly:** Render's default filesystem is ephemeral — a redeploy can wipe both the cache and this phase's SQLite file. Fine for the cache; real data loss for accumulated feedback on the current deployment without a persistent disk add-on.

### Phase 10 — Production Quality: the final phase

The roadmap's last stop — not new capabilities, but making the existing ones trustworthy to actually run somewhere real. Every item here was chosen because a concrete gap was found and fixed, not because a roadmap item existed to check off.

**What changed:**
- **A real bug fix: repository size limits were never enforced.** `MAX_REPO_SIZE_MB` had been defined since Module 1 and referenced in a Phase 4 comment, but nothing ever actually checked it. Fixed: measured post-clone, rejected (with cleanup) if over the limit.
- **A real security gap: this tool could re-leak the secrets it finds.** The `hardcoded-secret` rule's snippet contained the literal secret value, which flowed into the AI prompt (a third party), the on-disk cache, and the SQLite feedback store, indefinitely. Fixed at the source: the literal value is now redacted (`api_key = "<redacted>"`) while the finding stays fully actionable.
- **Structured logging, where there was none** — every clone/analysis/validation now logs at INFO/WARNING/ERROR, configurable via `CODEGUARDIAN_LOG_LEVEL`, deliberately never logging full snippets even post-redaction.
- **CORS was wide open with a comment admitting it should be fixed** — now configurable via `CODEGUARDIAN_CORS_ORIGINS`.
- **Rate limiting, where there was none** — a simple in-memory sliding-window limiter on the three expensive endpoints, configurable via `CODEGUARDIAN_RATE_LIMIT_PER_MINUTE`, explicitly documented as single-process.
- **`scripts/benchmark.py`** — a reusable, re-runnable benchmark. Against `pallets/flask` (83 files, ~18.3k lines): ~0.45–0.48s median. Against `appsecco/dvna` (JS, tree-sitter): ~0.20–0.21s median.
- **A genuine full-stack integration test** (`tests/test_integration.py`) that mocks only the network clone boundary and lets parsing, analysis, filtering, summary computation, and feedback-store persistence all run for real.
- **`ARCHITECTURE.md`** — a from-scratch reader's map of the finished system.
- **71 new tests.**

**440 total tests now, 97% coverage across the entire `app/` package.**

**A real test-isolation bug, caught and fixed in this same phase:** adding the rate limiter broke the existing suite immediately, because its in-memory counters live for the lifetime of the cached `app.main` module across the whole pytest session — dozens of existing tests collectively exceeded the sensible production default of 10 requests/minute. Fixed with a session-scoped fixture setting a generous test-time default, while the rate-limiter's own tests explicitly override it lower against a freshly reloaded app instance. Confirmed fixed by running the full suite three times with no flakiness.

**Design notes:**
- **Why is repo-size enforcement post-clone, not pre-clone?** GitHub's API-reported size is compressed and doesn't account for `--depth 1` truncation — no reliable number exists to check beforehand.
- **Why redact only `hardcoded-secret`, not `insecure-random-token` too?** The latter flags a *pattern* (a call to `random.randint()`), not a captured literal — there's no secret string to redact in the first place.
- **Why an in-memory rate limiter instead of a distributed one?** This project runs one process per deployment right now, the same reality the SQLite feedback store already lives with — a distributed limiter solves a coordination problem that doesn't exist yet. Named explicitly: `uvicorn --workers 4` would allow up to 4x the configured limit.
- **What was explicitly not attempted:** parallel/incremental scanning beyond Phase 8's `--changed-only` (genuine parallelization needs profiling first, not a guess), and OpenAPI schema examples beyond FastAPI's auto-generated ones from the Pydantic models.

---

This closes out the original 10-phase roadmap. 440 tests, 97% coverage, ten independently-verified, independently-documented phases — tree-sitter parsing, bounded cross-function taint tracking, 20 security rules across two languages, AI validation with caching and retry/fallback handling, filtering and a dashboard, a CLI with SARIF output and CI integration, a real feedback store, and a production-hardening pass. Every phase found and fixed at least one real, concrete problem along the way, not just added features on top of a static foundation. **[ARCHITECTURE.md](./ARCHITECTURE.md)** is the fastest way to see the whole shape of it; this README is the record of how it got built and why.

---

## Known dependency conflict (fixed)

`openai==1.51.0` internally passes a `proxies` argument to `httpx.Client()`. `httpx` removed that argument in 0.28.0. If `pip install` resolves a newer `httpx` alongside the pinned `openai` version, every OpenAI client instantiation fails with:

```
TypeError: Client.__init__() got an unexpected keyword argument 'proxies'
```

This surfaces as a bare, un-detailed 500 from `/validate` (the error happens at `OpenAI(api_key=...)` construction, outside the endpoint's own try/except blocks).

**Fix:** `httpx<0.28` is now pinned in `requirements.txt`. If you already have a venv from before this fix, run `pip install "httpx<0.28"` directly.

## Using a free provider instead of paid OpenAI credits

The AI layer is provider-agnostic — it can point at any OpenAI-compatible API via `OPENAI_BASE_URL`. [Groq](https://console.groq.com) offers a genuinely free API tier (no card required) that works with this project with no code changes.

1. Sign up at [console.groq.com](https://console.groq.com) and generate an API key (starts with `gsk_`).
2. Set these instead of/in addition to your usual `OPENAI_API_KEY`:
   ```bash
   export OPENAI_API_KEY=gsk_your_groq_key_here
   export OPENAI_BASE_URL=https://api.groq.com/openai/v1
   export OPENAI_MODEL=openai/gpt-oss-20b
   ```
   *(Windows cmd: `set` instead of `export`. PowerShell: `$env:VAR="value"`)*
3. Restart the server and hit `/validate` as normal — no other changes needed.

**Design note:** this works because `app/ai/client.py` builds the OpenAI SDK client with an optional `base_url` override rather than hardcoding `api.openai.com` — a deliberate choice, not a hack, meaning the AI validation layer isn't locked to one vendor. One caveat: Groq's structured-output mode is stricter than OpenAI's about requiring every schema property to be listed under `required` — the schema in `app/ai/prompts.py` already satisfies this, but it's worth knowing if that schema is modified later.