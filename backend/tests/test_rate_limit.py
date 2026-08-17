"""
Tests for app/core/rate_limit.py. Uses a fresh TestClient per test
(via a fixture that reloads app.main) since the middleware's request
counters are held in the middleware instance itself, and reusing one
app instance across tests would leak rate-limit state between them.
"""
import importlib
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.services.repo_processor import RepoProcessorError


@pytest.fixture
def fresh_client(monkeypatch):
    """Fresh app + middleware instance per test, so rate-limit counters
    never leak between tests."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")
    import app.main
    importlib.reload(app.main)
    return TestClient(app.main.app)


class TestRateLimitedEndpoints:
    def test_requests_under_limit_all_succeed(self, fresh_client, monkeypatch):
        monkeypatch.setenv("CODEGUARDIAN_RATE_LIMIT_PER_MINUTE", "10")
        with patch("app.api.scan.clone_repository", side_effect=RepoProcessorError("bad url")):
            for _ in range(5):
                resp = fresh_client.post("/scan", json={"github_url": "https://github.com/x/y"})
                assert resp.status_code == 400  # reaches the real handler, just a mocked failure

    def test_requests_over_limit_return_429(self, fresh_client, monkeypatch):
        monkeypatch.setenv("CODEGUARDIAN_RATE_LIMIT_PER_MINUTE", "3")
        with patch("app.api.scan.clone_repository", side_effect=RepoProcessorError("bad url")):
            codes = [fresh_client.post("/scan", json={"github_url": "https://github.com/x/y"}).status_code
                     for _ in range(5)]
        assert codes == [400, 400, 400, 429, 429]

    def test_429_response_has_a_detail_message(self, fresh_client, monkeypatch):
        monkeypatch.setenv("CODEGUARDIAN_RATE_LIMIT_PER_MINUTE", "1")
        with patch("app.api.scan.clone_repository", side_effect=RepoProcessorError("bad url")):
            fresh_client.post("/scan", json={"github_url": "https://github.com/x/y"})
            resp = fresh_client.post("/scan", json={"github_url": "https://github.com/x/y"})
        assert resp.status_code == 429
        assert "detail" in resp.json()
        assert "Rate limit" in resp.json()["detail"]

    def test_different_endpoints_share_one_counter_per_client(self, fresh_client, monkeypatch):
        """Each client IP has ONE shared counter across all
        RATE_LIMITED_PATHS in the current implementation (see
        rate_limit.py's _client_key) — hitting /scan's budget affects
        /analyze too. Documented explicitly via this test rather than
        assumed, since per-path counters would be an equally reasonable
        alternative design a future change might adopt."""
        monkeypatch.setenv("CODEGUARDIAN_RATE_LIMIT_PER_MINUTE", "2")
        with patch("app.api.scan.clone_repository", side_effect=RepoProcessorError("x")), \
             patch("app.api.analyze.clone_repository", side_effect=RepoProcessorError("x")):
            scan_codes = [fresh_client.post("/scan", json={"github_url": "https://github.com/x/y"}).status_code
                          for _ in range(3)]
            analyze_codes = [fresh_client.post("/analyze", json={"github_url": "https://github.com/x/y"}).status_code
                              for _ in range(3)]
        assert scan_codes == [400, 400, 429]
        assert analyze_codes == [429, 429, 429]


class TestUnlimitedEndpoints:
    def test_health_endpoint_never_rate_limited(self, fresh_client, monkeypatch):
        monkeypatch.setenv("CODEGUARDIAN_RATE_LIMIT_PER_MINUTE", "1")
        for _ in range(10):
            resp = fresh_client.get("/health")
            assert resp.status_code == 200

    def test_stats_endpoints_never_rate_limited(self, fresh_client, monkeypatch, tmp_path):
        monkeypatch.setenv("CODEGUARDIAN_RATE_LIMIT_PER_MINUTE", "1")
        monkeypatch.setenv("CODEGUARDIAN_DB_FILE", str(tmp_path / "test.db"))
        for _ in range(10):
            resp = fresh_client.get("/stats/rules")
            assert resp.status_code == 200


class TestClientKeyFallback:
    def test_missing_client_falls_back_to_shared_bucket_not_a_crash(self):
        """request.client can be None in some ASGI test/proxy setups —
        _client_key must degrade to a shared bucket rather than raising."""
        from app.core.rate_limit import RateLimitMiddleware
        from unittest.mock import MagicMock

        middleware = RateLimitMiddleware(app=MagicMock())
        fake_request = MagicMock()
        fake_request.client = None
        assert middleware._client_key(fake_request) == "unknown"
