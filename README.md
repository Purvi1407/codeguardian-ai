# CodeGuardian AI — Backend (Module 1 + 2)

AI-powered SAST agent. This slice implements:
- **Module 1 — Repository Processor**: validates a GitHub URL, shallow-clones it into a temp dir, cleans up after itself (even on failure).
- **Module 2 — Parser**: walks the repo, finds `.py`/`.ts`/`.tsx`/`.js`/`.jsx` files, and extracts functions/classes with line numbers.
  - Python uses the `ast` module — accurate line numbers, args, method/class attribution.
  - TS/JS uses regex for now (documented limitation — see `app/parser/js_ts_parser.py`). Swap for tree-sitter later if time allows.

## Run it

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## Try it

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/pallets/flask"}'
```

Tested live against `pallets/flask` (83 files, 0 parse errors) and against invalid/nonexistent repo URLs (clean 400s, no orphaned temp dirs).

## What's next (Module 3 + 4)

- `app/analyzer/` — rule-based static analyzer producing candidate findings from the parsed functions/classes (this is where SQLi/XSS/etc. rules go).
- `app/ai/` — sends candidate findings to the OpenAI API for validation, severity, explanation, and patch suggestion. This is where the "fewer, higher-confidence findings" philosophy actually gets enforced — the AI step is a *filter*, not a generator.

## Design notes (for defending decisions)

- **Why `ast` over regex for Python but regex for TS/JS?** `ast` is stdlib, zero dependencies, and gives exact line numbers for free. Tree-sitter would give the same for TS/JS but adds a build dependency; regex was the pragmatic MVP call under a tight timeline, called out explicitly rather than hidden.
- **Why always clean up the clone, even on success?** Module 1 currently treats each scan as stateless. Once Module 3/4 need to re-open the same repo for deeper analysis, this will change to a short-TTL cache instead of immediate deletion — noted as a TODO in `api/scan.py` so it doesn't look accidental later.
- **Why `--depth 1` clone?** We only need current-state source, not history, and a shallow clone is dramatically faster and safer against large repos.

## Module 3 — Rule-Based Analyzer

Added: `app/analyzer/rules.py` (rule metadata) + `app/analyzer/python_rules.py` (AST-based detection) + `POST /analyze` endpoint (full Module 1+2+3 pipeline).

**10 rules implemented**, each backed by CWE reference:

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

**Verified against a deliberately vulnerable test file**: 11/11 expected findings fired, **0 false positives** on a parameterized-query control function in the same file. Also verified end-to-end against `pallets/flask` (real 83-file repo): 7 candidate findings, including a genuine example of *why Module 4 is necessary* — `config.py`'s `from_pyfile()` uses `exec()` legitimately to load a trusted local config file, but a pattern-only rule can't distinguish that from a real code-injection bug. That's the exact gap AI validation is meant to close.

### Design notes (for defending decisions)

- **Why pattern-matching, not taint tracking?** True taint analysis (tracing whether a value actually originates from user input) needs a data-flow graph across the whole call chain — out of scope for a multi-day MVP. This is explicitly a *candidate generator*: fast, cheap, and intentionally over-inclusive, with Module 4 doing the precision work. Naming this limitation up front is stronger than pretending the rules are exploit-confirmed.
- **Why track variables within a function for SQL injection, but not across functions?** Cross-function tracking needs call-graph resolution (arguments passed between functions, aliasing, etc.) — the same complexity tradeoff as full taint tracking. Single-function tracking catches the extremely common `query = f"..."; cursor.execute(query)` pattern cheaply without that complexity.
- **Why only Python gets analyzer rules right now?** The TS/JS parser is already regex-based (documented Module 2 tradeoff) — building a security rule engine on top of an unreliable AST would just compound the imprecision. Sequencing: get Python's rules right first, decide whether tree-sitter is worth adding before extending rules to JS/TS.

## Module 4 — AI Validation

Added: `app/ai/client.py` (OpenAI client + config), `app/ai/prompts.py` (system prompt + JSON schema), `app/ai/validator.py` (batching + merge logic), `POST /validate` endpoint (full Module 1+2+3+4 pipeline).

**This is the actual product.** Everything before this point produces candidates; `/validate` is what turns them into the "fewer, higher-confidence findings" the whole philosophy is built around. Response includes both `findings` (AI-verified) and `dismissed` (AI-rejected candidates, kept for transparency — useful for tuning rules later).

### ⚠️ Important — what's tested vs. not

I could **not** make a real call to the OpenAI API from my environment (network sandbox doesn't allow `api.openai.com`). What I verified instead, with a mocked API response:
- Batch → merge logic correctly maps AI judgments back onto the right findings
- A finding the model "drops" from its response fails safe (kept as unverified/low-confidence) instead of silently disappearing
- Missing `OPENAI_API_KEY` fails fast with a clear message, before cloning any repo
- Server starts cleanly with all 4 routes registered (`/scan`, `/analyze`, `/validate`, `/health`)

**You need to test the real API call yourself** — set `OPENAI_API_KEY`, hit `/validate` against a real repo, and sanity-check the responses. Be honest about this in your writeup/demo; claiming something is tested when it wasn't is a much worse look than saying "the OpenAI integration itself needs your key to verify, here's what I did test."

### Setup

```bash
export OPENAI_API_KEY=sk-...
# optional — defaults to gpt-4o-mini for cost; override for a stronger model
export OPENAI_MODEL=gpt-4o
```

### Design notes (for defending decisions)

- **Why batch findings into one request instead of one call per finding?** Direct cost/latency tradeoff. A repo with 50 candidates would mean 50 separate API calls at ~1s+ each; batching 8 per call cuts that to ~7 calls. Tradeoff: harder to parse (need to map results back by index), which is why structured output (JSON schema, `strict: true`) is used instead of free-text parsing — reliability without giving up the cost savings.
- **Why fail-fast on missing API key before cloning?** Cloning + parsing a large repo can take real time. No reason to spend that time only to fail at the very last step. This is a small thing, but it's the kind of "did they think about the failure path" detail a reviewer notices.
- **Why keep `dismissed` findings in the response instead of just dropping them?** Two reasons: (1) transparency — if AI validation seems too aggressive, you can see exactly what it rejected and why; (2) it's the seed of a future feedback loop (Module 5+, not built) where a developer could mark a dismissed finding as "actually valid" to improve rule tuning over time.
- **Why is the model configurable via `OPENAI_MODEL` rather than hardcoded?** This is explicitly a cost/quality knob the person running the tool should control, not a decision baked into the code.

## Known dependency conflict (fixed)

`openai==1.51.0` internally passes a `proxies` argument to `httpx.Client()`. `httpx` removed that argument in 0.28.0. If `pip install` resolves a newer `httpx` alongside the pinned `openai` version, every OpenAI client instantiation fails with:
```
TypeError: Client.__init__() got an unexpected keyword argument 'proxies'
```
This surfaces as a bare, un-detailed 500 from `/validate` (the error happens at `OpenAI(api_key=...)` construction, which is outside the endpoint's own try/except blocks — a good reminder that error handling can only catch what it wraps).

**Fix**: `httpx<0.28` is now pinned in `requirements.txt`. If you already have a venv from before this fix, run `pip install "httpx<0.28"` directly.

## Using a free provider instead of paid OpenAI credits

If you don't want to add billing to OpenAI, the AI layer is provider-agnostic — it can point at any OpenAI-compatible API via `OPENAI_BASE_URL`. **Groq** offers a genuinely free API tier (no card required) that works with this project with no code changes.

1. Sign up at https://console.groq.com and generate an API key (starts with `gsk_`)
2. Set these instead of/in addition to your usual `OPENAI_API_KEY`:
   ```bash
   export OPENAI_API_KEY=gsk_your_groq_key_here
   export OPENAI_BASE_URL=https://api.groq.com/openai/v1
   export OPENAI_MODEL=openai/gpt-oss-20b
   ```
   (Windows cmd: `set` instead of `export`. PowerShell: `$env:VAR="value"`)
3. Restart the server and hit `/validate` as normal — no other changes needed.

**Design note**: this works because `app/ai/client.py` builds the OpenAI SDK client with an optional `base_url` override rather than hardcoding `api.openai.com`. That's a deliberate choice, not a hack — it means the AI validation layer isn't locked to one vendor, which is a reasonable thing to point to if asked "why did you structure the client this way?" One caveat worth knowing: Groq's structured-output mode is stricter than OpenAI's about requiring every schema property to be listed under `required` — the schema in `app/ai/prompts.py` already satisfies this, but it's worth knowing if you modify that schema later.

## Module 3 extended — TypeScript/JavaScript rules

Added `app/analyzer/js_ts_rules.py`: 8 regex-based rules for JS/TS (SQL injection, Node command injection, XSS via innerHTML, dangerous eval/Function, weak crypto, insecure CORS wildcard, JWT algorithm confusion, hardcoded secrets). Wired into the same `/analyze` and `/validate` pipeline — no new endpoints needed.

**Verified two ways:**
1. Against a deliberately vulnerable test file: 8/8 expected findings fired, 0 false positives on parameterized/safe counterpart functions in the same file.
2. Against a real, unfamiliar repo (`appsecco/dvna` — Damn Vulnerable NodeJS Application): correctly found its 3 genuine, documented vulnerabilities (SQL injection, command injection via `ping`, unsafe `eval()`) with zero noise after two bugs found during this exact test were fixed:
   - The `exec()` regex was initially also matching JavaScript's unrelated `RegExp.prototype.exec()` method — fixed by requiring either explicit `child_process.exec` or a bare (non-method) `exec(` call.
   - Vendor/minified bundles (`jquery-3.2.1.min.js`) were being scanned as if they were the developer's own code, producing noise on single-line minified files. Fixed by excluding `*.min.js`/`*.min.ts`/`*.bundle.js` from discovery — scanning vendored third-party code a developer can't meaningfully "fix" isn't useful for a SAST tool anyway.

### Design notes (for defending decisions)

- **Why regex instead of upgrading to a real JS/TS parser?** The JS/TS parser (Module 2) was already regex-based as a documented MVP tradeoff; building AST-quality rules on top of a regex-quality parser would be false precision. This keeps the limitation consistent and honestly documented rather than half-fixed. If given another month, tree-sitter would upgrade both the parser and this analyzer for one integration cost — noted as the top priority next step.
- **Why exclude minified/vendor files rather than flag them?** A SAST tool exists to help a developer fix code they own. Findings inside a third-party minified bundle aren't actionable — the fix isn't "edit this line," it's "update the dependency," which is a different problem (and better solved by `npm audit`, not this tool).
- **The RegExp.exec() false-positive is a good real example of testing value**: it only surfaced by running against genuine, unfamiliar code — my own hand-written test file never would have caught it, since I wouldn't have coincidentally used `.exec()` in a regex context. This is the argument for testing against code you didn't write, not just code you designed to be caught.

## Browser UI

Added `app/static/index.html` — a single-page frontend served at `GET /`. No build step, no separate frontend deployment: it's plain HTML/CSS/JS, fetch-calling the same `/analyze` and `/validate` endpoints, served by the same FastAPI app.

**Run it**: start the server as usual, open `http://localhost:8000/` (not `/docs` — that's still the API explorer, `/` is now the actual product UI).

Two modes, exposed as a toggle:
- **Quick scan** → calls `/analyze` (free, no API key, rule-based candidates only)
- **Full validate** → calls `/validate` (uses your API key, AI-reviewed, shows verified + dismissed findings)

**Verified working**: `GET /` returns 200 with the correct HTML: confirmed `/health`, `/docs`, and `/analyze` all still work correctly and aren't shadowed by the new root route (the UI route is a specific `GET /`, not a catch-all mount, so it can't intercept other paths).

**Not verified**: I don't have a way to render and screenshot a browser in my environment, so the visual layout/styling is untested by me beyond reading the CSS carefully. Open it yourself and tell me if anything looks broken, misaligned, or is hard to read — that's the one part of this I genuinely can't confirm without your eyes on it.

### Design notes (for defending decisions)

- **Why no framework (React/Next.js)?** Zero build step, zero deployment complexity — the whole UI is one static file the backend already serves. For a 2-endpoint tool with no client-side state beyond "what did the last scan return," a framework would add process without adding capability. This is a legitimate answer if asked "why not React" — not every UI needs one.
- **The candidates → verified gauge bar** is the one deliberately designed element: it visualizes the core product philosophy ("fewer, higher-confidence findings") as an actual number you watch shrink, rather than just stating it in copy.
- **Dismissed findings are visible but collapsed by default** — same reasoning as the API design: transparency without cluttering the primary view.
