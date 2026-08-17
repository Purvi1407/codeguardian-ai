# Architecture

A reader-friendly map of the system, for anyone who wants the shape of the whole thing without reading through 10 phases of incremental README history. Each section links back to where the detail actually lives.

## The pipeline, end to end

```
GitHub URL
    |
    v
[Clone]  Module 1 - repo_processor.py
    Validates the URL, clones with --depth 1, enforces
    MAX_REPO_SIZE_MB (Phase 10) and CLONE_TIMEOUT_SECONDS,
    always cleans up regardless of how the request ends.
    |
    v
[Parse]  Module 2 - parser/
    python_parser.py (stdlib ast) and js_ts_parser.py
    (tree-sitter, Phase 2) walk each file into
    FunctionInfo/ClassInfo objects.
    |
    v
[Analyze]  Module 3 - analyzer/
    python_rules.py / js_ts_rules.py walk the same trees,
    flagging 20 rule patterns (analyzer/rules.py) with
    same-function AND bounded cross-function taint tracking
    (Phase 3). Secret values are redacted at this point
    (Phase 10) before a Finding object even exists.
    |
    v
[Filter]  Phase 6 - services/finding_filters.py
    severity / language / rule / search filters applied HERE,
    before Module 4, so a filtered-out finding never costs an
    AI call.
    |
    v
[Validate]  Module 4 - ai/
    validator.py batches candidates to an LLM (client.py),
    checked against cache.py first (Phase 5) so identical
    findings aren't re-paid for. Retries transient failures,
    supports an optional fallback model.
    |
    v
[Summarize]  Phase 7 - services/dashboard.py
    Risk score + severity/rule distribution, computed fresh
    over whatever findings survived filtering and validation.
    |
    +----------------> API response (api/analyze.py, api/validate.py)
    |
    +----------------> Phase 9 - services/feedback_store.py (SQLite)
                        Every verdict + scan summary persisted for
                        GET /stats/rules and GET /stats/scans.
```

## Two ways in: the API, and the CLI

**The FastAPI app** (`app/main.py`) is the full pipeline above, reachable over HTTP — `/scan`, `/analyze`, `/validate`, `/stats/rules`, `/stats/scans`, plus the browser UI at `/` (`app/static/index.html`, Phase 7's dashboard and filter controls). This is what you get running `uvicorn app.main:app`.

**The CLI** (`app/cli.py`, Phase 8) runs Module 1-3 directly against a local directory — no clone, no server, no API key. This is what a CI job actually wants: the repo's already checked out, and a security gate needs a plain exit code (`--fail-on high`), not an HTTP response. It also supports SARIF output (`app/reports/sarif.py`) for GitHub's native code scanning UI, `--changed-only` for PR-diff scanning, and `--baseline`/`--write-baseline` for adopting the tool on an existing codebase without every pre-existing finding blocking the next PR.

They share the same Module 1-3 code — the CLI just skips the clone step (`build_file_metadata_and_findings()` is called directly against whatever `--path` you give it) and doesn't call Module 4 by default (see Phase 8's design notes for why AI validation isn't in CI's default path).

## Two persistence mechanisms, deliberately different shapes

| | Phase 5's AI cache | Phase 9's feedback store |
|---|---|---|
| **What** | One AI verdict per `(rule_id, snippet)` | Every verdict ever, plus scan summaries |
| **Format** | JSON file | SQLite |
| **Access pattern** | Single-key lookup | Aggregation (`GROUP BY`, `COUNT`, `ORDER BY ... LIMIT`) |
| **Why the format differs** | A cache hit/miss doesn't need a query engine | Rule-effectiveness stats genuinely need one |

Both are file-based, both live under the repo root (`cache/`, `data/` — gitignored), both are best-effort (a write failure degrades gracefully, never breaks the response someone's waiting on), and both are honestly documented as not surviving Render's ephemeral filesystem across a redeploy without a persistent disk add-on.

## Where the two analyzers diverge, and why that's fine

`python_rules.py` uses Python's stdlib `ast` module. `js_ts_rules.py` uses tree-sitter (Phase 2, replacing an earlier regex version). They're independent siblings, not a shared abstraction over "some AST" — each walks its own tree shape, tracks taint with the same conceptual design (same-function tracking, Phase 3's bounded cross-function extension, alias propagation) but genuinely different code, because `ast.Call` and tree-sitter's `call_expression` don't share a useful common interface. Rule metadata (title, CWE, OWASP, remediation) lives in one shared place — `analyzer/rules.py` — so the two engines stay aligned on *what* they're allowed to claim about a rule, even though *how* they detect it differs completely.

## What's NOT here, on purpose

- **No database beyond SQLite.** No hosted Postgres, no Redis. Every persistence decision in this project asked "does this actually need more than a file?" before reaching for infrastructure — see Phase 9's design notes for the one case (aggregation queries) where the answer was yes, and SQLite was still enough.
- **No message queue, no background workers.** Every scan is a synchronous request-response. Fine at this scale; would need to change if scan volume or repo size grew enough that a request should return immediately with a job ID instead of blocking — not attempted here, since it's a real architectural shift, not a tweak.
- **No multi-tenant anything.** One feedback store, one cache, no concept of "which user/org does this belong to." Fine for a single-deployment tool; would need real design work (not just adding a `tenant_id` column) to support multiple isolated users safely.
- **No distributed rate limiting.** Phase 10's rate limiter is in-memory, single-process — see `app/core/rate_limit.py`'s own docstring for exactly what that does and doesn't cover.

None of these are gaps that were missed — each is a deliberate "this project's actual scale doesn't need it yet" call, made the same way every other scope decision in this README was: named explicitly, not silently assumed.
