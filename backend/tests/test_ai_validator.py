"""
Tests for app/ai/validator.py. No real OpenAI API calls anywhere in
this file — the client is always mocked. This project's own README
already noted the real API integration itself needs a live key to
verify end-to-end; what's tested here is everything Python-level around
that call: batching, retry/fallback logic, cache integration, and safe
handling of a malformed or partial response. This is also the first
committed test file for Module 4 at all — the README previously only
described manual mocked verification, not an actual pytest suite.
"""
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
import pytest
from openai import APIConnectionError, AuthenticationError, RateLimitError

from app.ai import cache, validator
from app.schemas.findings import Finding


def make_finding(rule_id="sql-injection-string-build", snippet="cursor.execute(query)", **overrides):
    defaults = dict(
        rule_id=rule_id,
        title="SQL query built with string formatting",
        severity="high",
        cwe="CWE-89",
        file="app.py",
        function="handler",
        line=10,
        snippet=snippet,
        description="A SQL query is built dynamically.",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def make_openai_response(results: list):
    """Builds a fake openai ChatCompletion-shaped response carrying the
    given `results` array as its JSON content — mirrors exactly what
    _validate_batch expects to parse."""
    content = json.dumps({"results": results})
    message = SimpleNamespace(content=content, refusal=None)
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice])


def make_result(index, verified=True, confidence="high"):
    return {
        "index": index,
        "verified": verified,
        "confidence": confidence,
        "explanation": "Explanation text.",
        "exploit_scenario": "Exploit scenario text.",
        "patch_suggestion": "Patch suggestion text.",
        "things_to_verify": [],
    }


@pytest.fixture(autouse=True)
def isolated_cache_and_env(tmp_path, monkeypatch):
    cache_path = tmp_path / "test_cache.json"
    monkeypatch.setenv("CODEGUARDIAN_CACHE_FILE", str(cache_path))
    monkeypatch.delenv("CODEGUARDIAN_DISABLE_CACHE", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-fake-key")
    monkeypatch.delenv("AI_VALIDATION_FALLBACK_MODEL", raising=False)
    # Reset the module-level cached client between tests, since
    # ai/client.py memoizes it globally.
    import app.ai.client as client_module
    client_module._client = None
    # No real sleeping during retry tests.
    monkeypatch.setattr(validator.time, "sleep", lambda *_args, **_kwargs: None)
    yield cache_path


def fake_request():
    return httpx.Request("POST", "https://api.openai.com/v1/chat/completions")


class TestBasicValidation:
    def test_single_finding_gets_validated(self):
        finding = make_finding()
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = make_openai_response([make_result(0)])

        with patch("app.ai.validator.get_client", return_value=mock_client):
            results = validator.validate_findings([finding])

        assert len(results) == 1
        assert results[0].verified is True
        assert results[0].confidence == "high"

    def test_empty_findings_list_returns_empty_without_calling_api(self):
        mock_client = MagicMock()
        with patch("app.ai.validator.get_client", return_value=mock_client):
            results = validator.validate_findings([])
        assert results == []
        mock_client.chat.completions.create.assert_not_called()

    def test_dropped_index_fails_safe_as_unverified(self):
        """The model's response omits an index entirely — must not
        silently drop that finding, must return it as low-confidence
        unverified instead."""
        finding = make_finding()
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = make_openai_response([])  # no results at all

        with patch("app.ai.validator.get_client", return_value=mock_client):
            results = validator.validate_findings([finding])

        assert len(results) == 1
        assert results[0].verified is False
        assert results[0].confidence == "low"

    def test_batching_splits_large_finding_lists(self, monkeypatch):
        monkeypatch.setattr(validator, "BATCH_SIZE", 2)
        findings = [make_finding(line=i) for i in range(5)]
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = [
            make_openai_response([make_result(0), make_result(1)]),
            make_openai_response([make_result(0), make_result(1)]),
            make_openai_response([make_result(0)]),
        ]

        with patch("app.ai.validator.get_client", return_value=mock_client):
            results = validator.validate_findings(findings)

        assert len(results) == 5
        assert mock_client.chat.completions.create.call_count == 3


class TestCacheIntegration:
    def test_cached_finding_skips_the_api_call_entirely(self):
        finding = make_finding()
        result_cache = cache.load_cache()
        cache.record(result_cache, finding, MagicMock(
            verified=True, confidence="high", explanation="cached",
            exploit_scenario="cached", patch_suggestion="cached", things_to_verify=[],
        ))
        cache.save_cache(result_cache)

        mock_client = MagicMock()
        with patch("app.ai.validator.get_client", return_value=mock_client):
            results = validator.validate_findings([finding])

        assert len(results) == 1
        assert results[0].explanation == "cached"
        mock_client.chat.completions.create.assert_not_called()

    def test_uncached_finding_gets_validated_and_then_cached(self):
        finding = make_finding()
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = make_openai_response([make_result(0)])

        with patch("app.ai.validator.get_client", return_value=mock_client):
            validator.validate_findings([finding])

        result_cache = cache.load_cache()
        assert cache.lookup(result_cache, finding) is not None

    def test_mixed_cached_and_uncached_only_calls_api_for_uncached(self):
        cached_finding = make_finding(snippet="cursor.execute(cached_query)")
        uncached_finding = make_finding(snippet="cursor.execute(new_query)")

        result_cache = cache.load_cache()
        cache.record(result_cache, cached_finding, MagicMock(
            verified=True, confidence="high", explanation="cached",
            exploit_scenario="x", patch_suggestion="x", things_to_verify=[],
        ))
        cache.save_cache(result_cache)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = make_openai_response([make_result(0)])

        with patch("app.ai.validator.get_client", return_value=mock_client):
            results = validator.validate_findings([cached_finding, uncached_finding])

        assert len(results) == 2
        # Only ONE finding (the uncached one) should have gone to the API
        call_args = mock_client.chat.completions.create.call_args
        assert mock_client.chat.completions.create.call_count == 1

    def test_results_preserve_original_input_order_when_mixed(self):
        """The uncached finding is listed SECOND in the input — its
        result must still land at index 1 in the output, not get
        shuffled to the front just because it was processed separately
        from the cache hit."""
        cached_finding = make_finding(snippet="cursor.execute(cached_query)", line=1)
        uncached_finding = make_finding(snippet="cursor.execute(new_query)", line=2)

        result_cache = cache.load_cache()
        cache.record(result_cache, cached_finding, MagicMock(
            verified=True, confidence="high", explanation="cached",
            exploit_scenario="x", patch_suggestion="x", things_to_verify=[],
        ))
        cache.save_cache(result_cache)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = make_openai_response([make_result(0)])

        with patch("app.ai.validator.get_client", return_value=mock_client):
            results = validator.validate_findings([cached_finding, uncached_finding])

        assert results[0].line == 1
        assert results[1].line == 2


class TestRetryBehavior:
    def test_retryable_error_succeeds_on_second_attempt(self):
        finding = make_finding()
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = [
            RateLimitError("rate limited", response=httpx.Response(429, request=fake_request()), body=None),
            make_openai_response([make_result(0)]),
        ]

        with patch("app.ai.validator.get_client", return_value=mock_client):
            results = validator.validate_findings([finding])

        assert len(results) == 1
        assert results[0].verified is True
        assert mock_client.chat.completions.create.call_count == 2

    def test_retryable_error_gives_up_after_max_retries(self, monkeypatch):
        monkeypatch.setattr(validator, "MAX_RETRIES", 1)
        finding = make_finding()
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = APIConnectionError(request=fake_request())

        with patch("app.ai.validator.get_client", return_value=mock_client):
            with pytest.raises(validator.AIValidationError):
                validator.validate_findings([finding])

        assert mock_client.chat.completions.create.call_count == 2  # initial + 1 retry

    def test_non_retryable_error_is_not_retried(self):
        finding = make_finding()
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = AuthenticationError(
            "bad key", response=httpx.Response(401, request=fake_request()), body=None,
        )

        with patch("app.ai.validator.get_client", return_value=mock_client):
            with pytest.raises(validator.AIValidationError):
                validator.validate_findings([finding])

        assert mock_client.chat.completions.create.call_count == 1


class TestMalformedResponseHandling:
    def test_model_refusal_raises_validation_error(self):
        finding = make_finding()
        message = SimpleNamespace(content=None, refusal="I won't do that.")
        choice = SimpleNamespace(message=message)
        response = SimpleNamespace(choices=[choice])
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = response

        with patch("app.ai.validator.get_client", return_value=mock_client):
            with pytest.raises(validator.AIValidationError, match="refused"):
                validator.validate_findings([finding])

    def test_empty_content_raises_validation_error(self):
        finding = make_finding()
        message = SimpleNamespace(content=None, refusal=None)
        choice = SimpleNamespace(message=message)
        response = SimpleNamespace(choices=[choice])
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = response

        with patch("app.ai.validator.get_client", return_value=mock_client):
            with pytest.raises(validator.AIValidationError):
                validator.validate_findings([finding])

    def test_malformed_json_content_raises_validation_error(self):
        finding = make_finding()
        message = SimpleNamespace(content="{not valid json at all", refusal=None)
        choice = SimpleNamespace(message=message)
        response = SimpleNamespace(choices=[choice])
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = response

        with patch("app.ai.validator.get_client", return_value=mock_client):
            with pytest.raises(validator.AIValidationError):
                validator.validate_findings([finding])

    def test_result_missing_required_key_raises_validation_error(self):
        """A result that parses as JSON but is missing a field the code
        expects (e.g. 'confidence') must surface as a clear
        AIValidationError, not an uncaught KeyError."""
        finding = make_finding()
        bad_result = make_result(0)
        del bad_result["confidence"]
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = make_openai_response([bad_result])

        with patch("app.ai.validator.get_client", return_value=mock_client):
            with pytest.raises(validator.AIValidationError):
                validator.validate_findings([finding])


class TestFallbackModel:
    def test_fallback_model_used_after_primary_exhausts_retries(self, monkeypatch):
        monkeypatch.setenv("AI_VALIDATION_FALLBACK_MODEL", "fallback-model")
        monkeypatch.setattr(validator, "MAX_RETRIES", 0)
        finding = make_finding()
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = [
            APIConnectionError(request=fake_request()),  # primary model fails
            make_openai_response([make_result(0)]),       # fallback model succeeds
        ]

        with patch("app.ai.validator.get_client", return_value=mock_client):
            results = validator.validate_findings([finding])

        assert len(results) == 1
        assert results[0].verified is True
        # Second call should have used the fallback model
        second_call_kwargs = mock_client.chat.completions.create.call_args_list[1].kwargs
        assert second_call_kwargs["model"] == "fallback-model"

    def test_fallback_model_also_failing_raises_original_style_error(self, monkeypatch):
        monkeypatch.setenv("AI_VALIDATION_FALLBACK_MODEL", "fallback-model")
        monkeypatch.setattr(validator, "MAX_RETRIES", 0)
        finding = make_finding()
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = APIConnectionError(request=fake_request())

        with patch("app.ai.validator.get_client", return_value=mock_client):
            with pytest.raises(validator.AIValidationError):
                validator.validate_findings([finding])

        assert mock_client.chat.completions.create.call_count == 2  # primary + fallback attempt

    def test_no_fallback_configured_raises_after_retries_exhausted(self, monkeypatch):
        monkeypatch.setattr(validator, "MAX_RETRIES", 0)
        finding = make_finding()
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = APIConnectionError(request=fake_request())

        with patch("app.ai.validator.get_client", return_value=mock_client):
            with pytest.raises(validator.AIValidationError):
                validator.validate_findings([finding])

        assert mock_client.chat.completions.create.call_count == 1
