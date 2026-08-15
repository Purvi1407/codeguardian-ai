"""
API-level tests for Phase 9's /stats/rules and /stats/scans endpoints.
No repo cloning or AI calls involved here — these endpoints only read
from the feedback store, so tests just seed it directly.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import feedback_store
from app.schemas.findings import ValidatedFinding

client = TestClient(app)


def make_validated(rule_id="sql-injection-string-build", verified=True, **overrides):
    defaults = dict(
        rule_id=rule_id,
        title="SQL query built with string formatting",
        severity="high",
        cwe="CWE-89",
        file="app.py",
        function="handler",
        line=10,
        snippet="cursor.execute(query)",
        description="A SQL query is built dynamically.",
        verified=verified,
        confidence="high",
        explanation="Explanation.",
        exploit_scenario="Scenario.",
        patch_suggestion="Patch.",
        things_to_verify=[],
    )
    defaults.update(overrides)
    return ValidatedFinding(**defaults)


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEGUARDIAN_DB_FILE", str(tmp_path / "test_feedback.db"))
    yield


class TestRuleStatsEndpoint:
    def test_empty_store_returns_empty_list(self):
        resp = client.get("/stats/rules")
        assert resp.status_code == 200
        assert resp.json()["rules"] == []

    def test_recorded_validations_appear_in_response(self):
        feedback_store.record_validations("org/repo", [
            make_validated(verified=True),
            make_validated(verified=False),
        ])
        resp = client.get("/stats/rules")
        assert resp.status_code == 200
        rules = resp.json()["rules"]
        assert len(rules) == 1
        assert rules[0]["rule_id"] == "sql-injection-string-build"
        assert rules[0]["total_validations"] == 2
        assert rules[0]["dismissal_rate"] == 0.5


class TestScanHistoryEndpoint:
    def test_empty_store_returns_empty_list(self):
        resp = client.get("/stats/scans")
        assert resp.status_code == 200
        assert resp.json()["scans"] == []

    def test_recorded_scan_appears_in_response(self):
        feedback_store.record_scan("org/repo", "main", candidate_count=5, verified_count=2, risk_score=15)
        resp = client.get("/stats/scans")
        assert resp.status_code == 200
        scans = resp.json()["scans"]
        assert len(scans) == 1
        assert scans[0]["repository"] == "org/repo"
        assert scans[0]["risk_score"] == 15

    def test_repository_query_param_filters(self):
        feedback_store.record_scan("org/repo-a", "main", 1, 1, 5)
        feedback_store.record_scan("org/repo-b", "main", 1, 1, 5)

        resp = client.get("/stats/scans", params={"repository": "org/repo-a"})
        scans = resp.json()["scans"]
        assert len(scans) == 1
        assert scans[0]["repository"] == "org/repo-a"

    def test_limit_query_param_is_respected(self):
        for i in range(5):
            feedback_store.record_scan("org/repo", "main", i, i, i)

        resp = client.get("/stats/scans", params={"limit": 2})
        assert len(resp.json()["scans"]) == 2

    def test_limit_out_of_range_is_rejected(self):
        resp = client.get("/stats/scans", params={"limit": 0})
        assert resp.status_code == 422  # FastAPI validation error, ge=1 constraint

        resp = client.get("/stats/scans", params={"limit": 500})
        assert resp.status_code == 422  # le=200 constraint
