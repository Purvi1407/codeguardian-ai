"""
Validation result caching (Phase 5, item 36). Avoids re-paying for an
AI call on a finding that's effectively identical to one already
validated — same rule_id and same source snippet almost always means
the same judgment, so re-scanning an unchanged file (or hitting the
same vulnerable pattern in a second file) can skip the API call
entirely.

File-based, not just in-memory: an in-memory-only cache would lose all
its value the instant the server process restarts, which defeats the
point on a long-running deployment (this project is deployed on
Render — see README "Deployment" section — where the process can and
does restart between deploys).
"""
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Optional

from app.ai.prompts import PROMPT_VERSION
from app.core.config import BASE_DIR
from app.schemas.findings import Finding, ValidatedFinding

DEFAULT_CACHE_FILE = BASE_DIR / "cache" / "ai_validation_cache.json"

# Only the AI-derived fields get cached, not the whole ValidatedFinding —
# reconstructing the rest from the current `finding` on lookup means a
# future wording change in rules.py (title, description, etc.) doesn't
# require a cache-format migration; only the AI's actual judgment is
# what's persisted and reused.
_CACHED_FIELDS = (
    "verified", "confidence", "explanation",
    "exploit_scenario", "patch_suggestion", "things_to_verify",
)


def _cache_file() -> Path:
    """Configurable via env var so tests can point at an isolated temp
    file instead of writing into the real project cache directory."""
    override = os.getenv("CODEGUARDIAN_CACHE_FILE")
    return Path(override) if override else DEFAULT_CACHE_FILE


def cache_enabled() -> bool:
    return os.getenv("CODEGUARDIAN_DISABLE_CACHE", "").lower() not in ("1", "true", "yes")


def cache_key(finding: Finding) -> str:
    """Keyed on prompt version + rule_id + snippet — deliberately NOT
    file/line/function, so the same vulnerable pattern appearing in a
    different file, or the same file after an unrelated edit shifts
    line numbers, still hits the cache. Including PROMPT_VERSION means
    a prompt change correctly invalidates old cached judgments instead
    of silently serving a verdict reached under different instructions."""
    raw = f"{PROMPT_VERSION}:{finding.rule_id}:{finding.snippet}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_cache() -> Dict[str, dict]:
    if not cache_enabled():
        return {}
    path = _cache_file()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        # A corrupted or unreadable cache file must never break
        # validation — treat it as empty; it'll get overwritten cleanly
        # on the next save_cache().
        return {}


def save_cache(cache: Dict[str, dict]) -> None:
    if not cache_enabled():
        return
    path = _cache_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        # Caching is a performance optimization, not a correctness
        # requirement — a failure to persist it must never break a scan
        # that otherwise completed successfully.
        pass


def lookup(cache: Dict[str, dict], finding: Finding) -> Optional[ValidatedFinding]:
    """Returns a fully-formed ValidatedFinding if this exact
    (prompt-version, rule_id, snippet) combination was already
    validated, else None."""
    entry = cache.get(cache_key(finding))
    if entry is None or not all(k in entry for k in _CACHED_FIELDS):
        return None
    try:
        return ValidatedFinding(**{**finding.model_dump(), **{k: entry[k] for k in _CACHED_FIELDS}})
    except Exception:
        # A malformed cache entry (e.g. hand-edited, or from an older
        # incompatible cache format) must degrade to "not cached", not
        # crash validation.
        return None


def record(cache: Dict[str, dict], finding: Finding, validated: ValidatedFinding) -> None:
    cache[cache_key(finding)] = {k: getattr(validated, k) for k in _CACHED_FIELDS}
