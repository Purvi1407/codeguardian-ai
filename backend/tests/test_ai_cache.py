"""
Tests for app/ai/cache.py. No network calls — this module never talks
to an API, it's pure file I/O and hashing, so these run fully offline.
"""
import json
import os

import pytest

from app.ai import cache
from app.schemas.findings import Finding, ValidatedFinding


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


def make_validated(finding: Finding, verified=True, confidence="high"):
    return ValidatedFinding(
        **finding.model_dump(),
        verified=verified,
        confidence=confidence,
        explanation="This is exploitable.",
        exploit_scenario="An attacker could inject SQL via the id parameter.",
        patch_suggestion="Use a parameterized query.",
        things_to_verify=["Confirm the endpoint is reachable without auth."],
    )


@pytest.fixture(autouse=True)
def isolated_cache_file(tmp_path, monkeypatch):
    """Every test gets its own throwaway cache file, so tests can't
    pollute each other or the real project cache directory."""
    cache_path = tmp_path / "test_cache.json"
    monkeypatch.setenv("CODEGUARDIAN_CACHE_FILE", str(cache_path))
    monkeypatch.delenv("CODEGUARDIAN_DISABLE_CACHE", raising=False)
    yield cache_path


class TestCacheKey:
    def test_same_rule_and_snippet_produce_same_key(self):
        f1 = make_finding(file="a.py", line=10)
        f2 = make_finding(file="b.py", line=99)  # different file/line
        assert cache.cache_key(f1) == cache.cache_key(f2)

    def test_different_snippet_produces_different_key(self):
        f1 = make_finding(snippet="cursor.execute(query)")
        f2 = make_finding(snippet="cursor.execute(other_query)")
        assert cache.cache_key(f1) != cache.cache_key(f2)

    def test_different_rule_id_produces_different_key_even_with_same_snippet(self):
        f1 = make_finding(rule_id="sql-injection-string-build", snippet="x = y")
        f2 = make_finding(rule_id="hardcoded-secret", snippet="x = y")
        assert cache.cache_key(f1) != cache.cache_key(f2)


class TestLoadAndSave:
    def test_load_returns_empty_dict_when_file_does_not_exist(self, isolated_cache_file):
        assert cache.load_cache() == {}

    def test_save_then_load_roundtrips(self, isolated_cache_file):
        cache.save_cache({"somekey": {"verified": True}})
        assert cache.load_cache() == {"somekey": {"verified": True}}

    def test_corrupted_cache_file_treated_as_empty_not_raised(self, isolated_cache_file):
        isolated_cache_file.write_text("{not valid json", encoding="utf-8")
        assert cache.load_cache() == {}

    def test_cache_file_containing_a_json_list_treated_as_empty(self, isolated_cache_file):
        """Defensive: a cache file that's syntactically valid JSON but
        not the expected shape (dict) must not crash lookups downstream."""
        isolated_cache_file.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        assert cache.load_cache() == {}


class TestLookupAndRecord:
    def test_lookup_miss_returns_none(self, isolated_cache_file):
        result_cache = {}
        finding = make_finding()
        assert cache.lookup(result_cache, finding) is None

    def test_record_then_lookup_returns_validated_finding(self, isolated_cache_file):
        result_cache = {}
        finding = make_finding()
        validated = make_validated(finding)
        cache.record(result_cache, finding, validated)

        hit = cache.lookup(result_cache, finding)
        assert hit is not None
        assert hit.verified == validated.verified
        assert hit.confidence == validated.confidence
        assert hit.explanation == validated.explanation
        assert hit.patch_suggestion == validated.patch_suggestion

    def test_lookup_hit_reflects_the_CURRENT_finding_metadata_not_the_cached_one(self, isolated_cache_file):
        """Only the AI-derived fields are cached — rule metadata (title,
        description, etc.) is re-taken from the finding passed to
        lookup(), not frozen at cache-write time. Confirms a rules.py
        wording change doesn't need a cache migration."""
        result_cache = {}
        original = make_finding(title="Old title")
        cache.record(result_cache, original, make_validated(original))

        updated = make_finding(title="New title")  # same rule_id+snippet, different title
        hit = cache.lookup(result_cache, updated)
        assert hit is not None
        assert hit.title == "New title"

    def test_malformed_cache_entry_treated_as_miss(self, isolated_cache_file):
        finding = make_finding()
        result_cache = {cache.cache_key(finding): {"verified": True}}  # missing required fields
        assert cache.lookup(result_cache, finding) is None


class TestCacheDisabling:
    def test_disabled_via_env_var_load_returns_empty(self, isolated_cache_file, monkeypatch):
        cache.save_cache({"somekey": {"verified": True}})
        monkeypatch.setenv("CODEGUARDIAN_DISABLE_CACHE", "true")
        assert cache.load_cache() == {}

    def test_disabled_via_env_var_save_is_a_no_op(self, isolated_cache_file, monkeypatch):
        monkeypatch.setenv("CODEGUARDIAN_DISABLE_CACHE", "1")
        cache.save_cache({"somekey": {"verified": True}})
        assert not isolated_cache_file.exists()


class TestPersistenceAcrossProcesses:
    def test_cache_written_by_one_call_is_visible_to_a_fresh_load(self, isolated_cache_file):
        """Simulates the real-world benefit: a second, independent
        server process (or the same process after a restart) reading
        the same cache file sees prior results — this is the whole
        point of a file-based cache over an in-memory one."""
        finding = make_finding()
        validated = make_validated(finding)

        first_process_cache = cache.load_cache()
        cache.record(first_process_cache, finding, validated)
        cache.save_cache(first_process_cache)

        second_process_cache = cache.load_cache()  # simulates a fresh process
        hit = cache.lookup(second_process_cache, finding)
        assert hit is not None
        assert hit.verified == validated.verified
