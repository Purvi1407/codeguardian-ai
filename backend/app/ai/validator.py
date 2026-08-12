import json
import os
import time
from typing import Dict, List

from app.ai import cache
from app.ai.client import get_client, get_model_name, AIConfigError
from app.ai.prompts import SYSTEM_PROMPT, build_user_prompt, response_json_schema
from app.schemas.findings import Finding, ValidatedFinding

BATCH_SIZE = int(os.getenv("AI_VALIDATION_BATCH_SIZE", "8"))

# Phase 5, item 41 (AI fallback handling): transient failures — rate
# limits, timeouts, connection errors, 5xx server errors — are worth
# retrying, since the same request will often succeed a moment later.
# A request that fails for a NON-transient reason (bad API key, content
# refused) will just fail identically on retry, so those are not
# retried — retrying them would only burn time and, for a paid API,
# money, for a guaranteed-identical failure.
MAX_RETRIES = int(os.getenv("AI_VALIDATION_MAX_RETRIES", "2"))
RETRY_BACKOFF_SECONDS = float(os.getenv("AI_VALIDATION_RETRY_BACKOFF_SECONDS", "1.0"))

# Optional: if every retry against the primary model fails, try once
# more against a different model before giving up entirely. Unset by
# default — this is an explicit opt-in, not a silent behavior change,
# since falling back to a different (possibly weaker or differently
# priced) model is a real tradeoff the person running this should choose,
# not one made silently on their behalf. Read fresh on each call (like
# analyzer/python_rules.py's _disabled_rule_ids()) rather than captured
# once at import time, so it can be changed without a process restart
# and so tests can set/unset it per-test via monkeypatch.setenv.
def _fallback_model() -> str:
    return os.getenv("AI_VALIDATION_FALLBACK_MODEL", "")


class AIValidationError(Exception):
    """Raised when the OpenAI call itself fails (network, rate limit, bad response)."""


def _is_retryable(exc: Exception) -> bool:
    try:
        from openai import RateLimitError, APITimeoutError, APIConnectionError, InternalServerError
    except ImportError:  # pragma: no cover - openai package always present in practice
        return False
    return isinstance(exc, (RateLimitError, APITimeoutError, APIConnectionError, InternalServerError))


def _call_model(client, model: str, batch: List[Finding]):
    """One attempt, no retry logic — retry/fallback orchestration lives
    in _call_with_retry_and_fallback so this stays a simple, single
    responsibility (and simple to call directly from a test with a
    mocked client)."""
    return client.chat.completions.create(
        model=model,
        temperature=0,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(batch)},
        ],
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "validated_findings",
                "schema": response_json_schema(),
                "strict": True,
            },
        },
    )


def _call_with_retry_and_fallback(client, model: str, batch: List[Finding]):
    last_exc: Exception = RuntimeError("unreachable")  # overwritten before ever being raised
    for attempt in range(MAX_RETRIES + 1):
        try:
            return _call_model(client, model, batch)
        except Exception as e:
            last_exc = e
            if attempt < MAX_RETRIES and _is_retryable(e):
                time.sleep(RETRY_BACKOFF_SECONDS * (2 ** attempt))
                continue
            break

    fallback_model = _fallback_model()
    if fallback_model and fallback_model != model:
        try:
            return _call_model(client, fallback_model, batch)
        except Exception as fallback_exc:
            last_exc = fallback_exc

    raise AIValidationError(f"OpenAI API call failed after retries: {last_exc}") from last_exc


def _validate_batch(batch: List[Finding]) -> List[ValidatedFinding]:
    client = get_client()
    model = get_model_name()

    response = _call_with_retry_and_fallback(client, model, batch)

    try:
        message = response.choices[0].message
        if getattr(message, "refusal", None):
            raise AIValidationError(f"Model refused to respond: {message.refusal}")
        content = message.content
        if content is None:
            raise AIValidationError(
                "OpenAI response had no content (empty/refused response). "
                "Raw response: " + str(response)[:500]
            )
        parsed = json.loads(content)
        results = {r["index"]: r for r in parsed["results"]}

        validated: List[ValidatedFinding] = []
        for i, finding in enumerate(batch):
            r = results.get(i)
            if r is None:
                # Model dropped this index — fail safe by keeping it as an
                # unverified, low-confidence candidate rather than silently
                # discarding it. Silent data loss is worse than an honest
                # "we couldn't confirm this."
                validated.append(ValidatedFinding(
                    **finding.model_dump(),
                    verified=False,
                    confidence="low",
                    explanation="AI validation did not return a result for this finding.",
                    exploit_scenario="",
                    patch_suggestion="",
                    things_to_verify=["Re-run validation or review this finding manually."],
                ))
                continue

            validated.append(ValidatedFinding(
                **finding.model_dump(),
                verified=r["verified"],
                confidence=r["confidence"],
                explanation=r["explanation"],
                exploit_scenario=r["exploit_scenario"],
                patch_suggestion=r["patch_suggestion"],
                things_to_verify=r.get("things_to_verify", []),
            ))
    except AIValidationError:
        raise
    except (KeyError, ValueError, TypeError, IndexError) as e:
        # Catches failures both in parsing the response AND in building
        # ValidatedFinding objects from it (e.g. a missing expected key) —
        # previously only the parsing step was wrapped, which let a
        # KeyError from a malformed-but-parseable response escape uncaught.
        raise AIValidationError(f"Couldn't parse AI response as expected JSON: {e}") from e

    return validated


def validate_findings(findings: List[Finding]) -> List[ValidatedFinding]:
    """
    Runs Module 4 over every candidate finding, in batches. Raises
    AIConfigError immediately if no API key is set (fail fast, before
    wasting a repo clone), or AIValidationError if a batch call fails.

    Phase 5: checks the on-disk cache (app/ai/cache.py) before spending
    an API call on any finding that's already been validated (same
    rule_id + snippet under the current prompt version) — only the
    uncached findings get sent to the model at all.
    """
    if not findings:
        return []

    get_client()  # raises AIConfigError early if misconfigured

    result_cache = cache.load_cache()
    results: List[ValidatedFinding] = [None] * len(findings)  # type: ignore[list-item]
    uncached_indices: List[int] = []
    uncached_findings: List[Finding] = []

    for i, finding in enumerate(findings):
        hit = cache.lookup(result_cache, finding)
        if hit is not None:
            results[i] = hit
        else:
            uncached_indices.append(i)
            uncached_findings.append(finding)

    newly_validated: List[ValidatedFinding] = []
    for i in range(0, len(uncached_findings), BATCH_SIZE):
        batch = uncached_findings[i:i + BATCH_SIZE]
        newly_validated.extend(_validate_batch(batch))

    for idx, finding, validated in zip(uncached_indices, uncached_findings, newly_validated):
        results[idx] = validated
        cache.record(result_cache, finding, validated)

    if newly_validated:
        cache.save_cache(result_cache)

    return results
