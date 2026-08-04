import json
import os
from typing import List

from app.ai.client import get_client, get_model_name, AIConfigError
from app.ai.prompts import SYSTEM_PROMPT, build_user_prompt, response_json_schema
from app.schemas.findings import Finding, ValidatedFinding

BATCH_SIZE = int(os.getenv("AI_VALIDATION_BATCH_SIZE", "8"))


class AIValidationError(Exception):
    """Raised when the OpenAI call itself fails (network, rate limit, bad response)."""


def _validate_batch(batch: List[Finding]) -> List[ValidatedFinding]:
    client = get_client()
    model = get_model_name()

    try:
        response = client.chat.completions.create(
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
    except Exception as e:
        raise AIValidationError(f"OpenAI API call failed: {e}") from e

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
    """
    if not findings:
        return []

    get_client()  # raises AIConfigError early if misconfigured

    all_validated: List[ValidatedFinding] = []
    for i in range(0, len(findings), BATCH_SIZE):
        batch = findings[i:i + BATCH_SIZE]
        all_validated.extend(_validate_batch(batch))

    return all_validated
