# Bumped whenever SYSTEM_PROMPT, build_user_prompt, or
# response_json_schema changes in a way that could change the model's
# judgment — e.g. tightening the "be skeptical by default" instruction,
# adding a new required field. Consumed by ai/cache.py so a prompt
# change correctly invalidates previously-cached verdicts instead of
# serving a judgment reached under different instructions. Bump this
# any time you edit the prompt text below, even a small wording change —
# it's cheap to bump and expensive to silently serve a stale verdict.
PROMPT_VERSION = "v1"

SYSTEM_PROMPT = """You are a senior application security engineer reviewing \
candidate findings produced by a static analysis rule engine.

Your job is NOT to find more issues. Your job is to REDUCE NOISE. The rule \
engine over-flags on purpose (pattern-matching without full data-flow \
analysis) — many of its candidates are false positives, safe usages, or \
findings in test/trusted code. Developers already ignore long vulnerability \
lists; your review is what makes this tool worth using.

For each candidate finding, decide:
1. verified: true only if you believe this is a REAL, actionable security \
   issue a developer should fix. false if it's a false positive, a safe \
   usage (e.g. parameterized query, trusted input, test fixture, internal \
   tooling), or you lack enough context to be confident it's exploitable.
2. confidence: "high" | "medium" | "low" — your confidence in the \
   `verified` judgment itself, not the severity of the issue.
3. explanation: 1-3 plain-language sentences on WHY this is (or isn't) a \
   real issue, referencing the actual code shown.
4. exploit_scenario: a concrete, specific sentence describing how an \
   attacker would exploit this IF verified is true. If verified is false, \
   explain instead why exploitation isn't realistic here.
5. patch_suggestion: a short, specific code-level suggestion. If verified \
   is false, this can be empty or note "no fix needed."
6. things_to_verify: 0-3 short bullet points a developer should manually \
   check before considering this fixed (e.g. "confirm this endpoint is \
   reachable without authentication").

Be skeptical by default. When genuinely uncertain, prefer verified=false \
with confidence="low" over guessing — a missed finding is better than \
adding back the noise this tool exists to remove.

Respond with ONLY a JSON object matching the provided schema. No prose \
outside the JSON.
"""


def build_user_prompt(batch) -> str:
    """
    batch: List[Finding]. Builds one prompt covering multiple findings so
    we're not paying a full request's overhead per finding — this is a
    direct cost/latency tradeoff worth being able to explain: batching
    trades a slightly harder parsing step for meaningfully lower cost on
    repos with many candidates.
    """
    parts = ["Review these candidate findings:\n"]
    for i, finding in enumerate(batch):
        parts.append(
            f"--- Finding {i} ---\n"
            f"Rule: {finding.rule_id} ({finding.title})\n"
            f"CWE: {finding.cwe}\n"
            f"File: {finding.file}\n"
            f"Function: {finding.function or '(module level)'}\n"
            f"Line: {finding.line}\n"
            f"Code: {finding.snippet}\n"
            f"Rule description: {finding.description}\n"
        )
    parts.append(
        "\nReturn a JSON object with a `results` array. Each element must "
        "include `index` matching the Finding number above, plus "
        "verified, confidence, explanation, exploit_scenario, "
        "patch_suggestion, and things_to_verify."
    )
    return "\n".join(parts)


def response_json_schema() -> dict:
    """JSON schema passed to the OpenAI structured-output API so the model's
    reply is guaranteed to be parseable — no regex-scraping of free text."""
    return {
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "index": {"type": "integer"},
                        "verified": {"type": "boolean"},
                        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                        "explanation": {"type": "string"},
                        "exploit_scenario": {"type": "string"},
                        "patch_suggestion": {"type": "string"},
                        "things_to_verify": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "required": [
                        "index", "verified", "confidence", "explanation",
                        "exploit_scenario", "patch_suggestion", "things_to_verify",
                    ],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["results"],
        "additionalProperties": False,
    }
