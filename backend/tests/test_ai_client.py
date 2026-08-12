"""
Tests for app/ai/client.py. No real network calls — get_client() only
constructs an OpenAI SDK client object, it doesn't contact the API
until a method is actually called on it, so this is fully testable
offline.
"""
import pytest

from app.ai import client as client_module


@pytest.fixture(autouse=True)
def reset_client_singleton(monkeypatch):
    """ai/client.py memoizes the constructed client in a module-level
    global — reset it before and after every test so tests don't leak
    state into each other."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    client_module._client = None
    yield
    client_module._client = None


class TestGetClient:
    def test_raises_config_error_when_api_key_missing(self):
        with pytest.raises(client_module.AIConfigError):
            client_module.get_client()

    def test_error_message_mentions_env_var_name(self):
        with pytest.raises(client_module.AIConfigError, match="OPENAI_API_KEY"):
            client_module.get_client()

    def test_succeeds_when_api_key_is_set(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        c = client_module.get_client()
        assert c is not None

    def test_client_is_memoized_across_calls(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        c1 = client_module.get_client()
        c2 = client_module.get_client()
        assert c1 is c2

    def test_custom_base_url_is_applied(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "gsk-test-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://api.groq.com/openai/v1")
        c = client_module.get_client()
        assert str(c.base_url).rstrip("/") == "https://api.groq.com/openai/v1"

    def test_no_base_url_uses_default_openai_endpoint(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        c = client_module.get_client()
        assert "api.openai.com" in str(c.base_url)


class TestGetModelName:
    def test_defaults_to_gpt_4o_mini(self):
        assert client_module.get_model_name() == "gpt-4o-mini"

    def test_respects_openai_model_env_var(self, monkeypatch):
        monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
        assert client_module.get_model_name() == "gpt-4o"
