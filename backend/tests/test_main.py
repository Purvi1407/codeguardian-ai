"""
Tests for app/main.py — app assembly, route registration, and Phase
10's configurable CORS. These run the module fresh via importlib.reload
where CORS env-var behavior is under test, since CORS_ORIGINS is
computed once at import time (module-level, read at app startup — the
right choice here, unlike the per-request-relevant env vars in earlier
phases like Phase 4's rule disabling or Phase 5's fallback model, since
CORS policy genuinely is a startup-time decision, not something that
should change mid-process for a running server).
"""
import importlib
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def api_key_set(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")
    yield


class TestAppBootsAndRegistersRoutes:
    def test_all_expected_routes_registered(self):
        """Uses app.routes' url_path_for resolution rather than
        introspecting route objects directly — the exact internal shape
        of app.routes (whether included routers show up as raw APIRoute
        objects or wrapped) varies across FastAPI/Starlette versions;
        asking the app "can you resolve this path" is stable across
        that, and is closer to what actually matters: can a client
        reach this endpoint."""
        from app.main import app
        client = TestClient(app)
        # A lightweight way to confirm a route exists without invoking
        # its real logic: OPTIONS is handled by Starlette's routing
        # layer for any registered path, returning 200/405 rather than
        # 404 — a 404 here would mean the route genuinely isn't registered.
        for path in ("/scan", "/analyze", "/validate", "/stats/rules", "/stats/scans", "/health", "/"):
            resp = client.options(path)
            assert resp.status_code != 404, f"{path} is not registered"

    def test_health_endpoint_returns_ok(self):
        from app.main import app
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_root_serves_html_not_json(self):
        from app.main import app
        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]


class TestCorsConfiguration:
    def test_default_cors_is_wildcard(self, monkeypatch):
        monkeypatch.delenv("CODEGUARDIAN_CORS_ORIGINS", raising=False)
        import app.main
        importlib.reload(app.main)
        assert app.main.CORS_ORIGINS == ["*"]

    def test_custom_cors_origins_parsed_as_list(self, monkeypatch):
        monkeypatch.setenv("CODEGUARDIAN_CORS_ORIGINS", "https://example.com,https://foo.com")
        import app.main
        importlib.reload(app.main)
        assert app.main.CORS_ORIGINS == ["https://example.com", "https://foo.com"]

    def test_custom_cors_origins_whitespace_trimmed(self, monkeypatch):
        monkeypatch.setenv("CODEGUARDIAN_CORS_ORIGINS", " https://example.com , https://foo.com ")
        import app.main
        importlib.reload(app.main)
        assert app.main.CORS_ORIGINS == ["https://example.com", "https://foo.com"]

    def test_single_custom_origin(self, monkeypatch):
        monkeypatch.setenv("CODEGUARDIAN_CORS_ORIGINS", "https://example.com")
        import app.main
        importlib.reload(app.main)
        assert app.main.CORS_ORIGINS == ["https://example.com"]

    @pytest.fixture(autouse=True)
    def restore_default_module_state(self):
        """Reloading app.main mutates a module every other test file
        also imports — reload it back to the env-free default afterward
        so this file's tests can't leak CORS_ORIGINS into unrelated
        test files that run later in the same session."""
        yield
        os.environ.pop("CODEGUARDIAN_CORS_ORIGINS", None)
        import app.main
        importlib.reload(app.main)
