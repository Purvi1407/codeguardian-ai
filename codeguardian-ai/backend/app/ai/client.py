import os
from openai import OpenAI

_client: OpenAI | None = None


class AIConfigError(Exception):
    """Raised when the AI layer can't run due to missing/bad configuration."""


def get_client() -> OpenAI:
    global _client
    if _client is not None:
        return _client

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise AIConfigError(
            "OPENAI_API_KEY is not set. Module 4 (AI validation) needs an "
            "API key — either a real OpenAI key, or a free-tier "
            "OpenAI-compatible key (e.g. Groq — see README) with "
            "OPENAI_BASE_URL set accordingly. Set it as an environment "
            "variable before starting the server, e.g.:\n"
            "  export OPENAI_API_KEY=sk-...   (macOS/Linux)\n"
            "  set OPENAI_API_KEY=sk-...      (Windows cmd)\n"
            "  $env:OPENAI_API_KEY=\"sk-...\"   (PowerShell)"
        )

    # Optional: point the OpenAI SDK at a different OpenAI-compatible
    # provider (e.g. Groq's free tier) instead of api.openai.com. This
    # keeps the AI layer provider-agnostic rather than hard-locking to
    # one vendor — a deliberate design choice, not just a workaround.
    base_url = os.getenv("OPENAI_BASE_URL")  # e.g. https://api.groq.com/openai/v1

    _client = OpenAI(api_key=api_key, base_url=base_url) if base_url else OpenAI(api_key=api_key)
    return _client


def get_model_name() -> str:
    """
    Model is configurable via env var rather than hardcoded, since the
    right choice trades off cost/latency vs. judgment quality — and that's
    a decision the person running this should make, not one baked into
    the code. Defaults to a small, cheap OpenAI model so the pipeline is
    runnable out of the box; swap via OPENAI_MODEL for a different model
    or provider (e.g. openai/gpt-oss-20b on Groq).
    """
    return os.getenv("OPENAI_MODEL", "gpt-4o-mini")

