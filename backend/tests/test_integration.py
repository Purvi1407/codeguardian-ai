"""
Phase 10 (item 91): a genuine end-to-end integration test, distinct
from the API-level tests in test_api_filters.py and test_stats_api.py
(which mock build_file_metadata_and_findings itself, using canned
fixture data to isolate what they're actually testing — filter wiring,
error paths). This file mocks ONLY the network boundary — the actual
`git clone` over HTTPS, which this environment can't do — and lets
every other layer run for real against a real local git repo: parsing,
rule-based analysis, filtering, risk-score computation, and feedback
store persistence. If a bug exists in how these pieces are actually
wired together (not just in each piece individually), this is the test
most likely to catch it.
"""
import subprocess
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

VULNERABLE_APP_PY = '''
import os
import sqlite3

def run_query(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

def run_command(filename):
    os.system("cat " + filename)
'''

VULNERABLE_APP_JS = '''
function runQuery(userId) {
  db.query(`SELECT * FROM users WHERE id = ${userId}`);
}
'''


@pytest.fixture
def real_local_repo(tmp_path):
    """A real git repository on disk with actual vulnerable code across
    two languages, so the integration test exercises both analyzers,
    not just one."""
    repo_dir = tmp_path / "integration_test_repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text(VULNERABLE_APP_PY, encoding="utf-8")
    (repo_dir / "app.js").write_text(VULNERABLE_APP_JS, encoding="utf-8")

    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=repo_dir, check=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo_dir, check=True)

    return repo_dir


@pytest.fixture(autouse=True)
def isolated_feedback_db(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEGUARDIAN_DB_FILE", str(tmp_path / "integration_feedback.db"))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")


class TestFullAnalyzeIntegration:
    """/analyze needs no AI/API key — everything in this pipeline runs
    for real."""

    def test_real_scan_finds_real_vulnerabilities_in_both_languages(self, real_local_repo):
        with patch("app.api.analyze.clone_repository", return_value=real_local_repo), \
             patch("app.api.analyze.get_default_branch", return_value="main"), \
             patch("app.api.analyze.cleanup_repository"):
            resp = client.post("/analyze", json={"github_url": "https://github.com/x/y"})

        assert resp.status_code == 200
        body = resp.json()

        rule_ids = {f["rule_id"] for f in body["findings"]}
        assert "sql-injection-string-build" in rule_ids  # from app.py
        assert "command-injection-os-system" in rule_ids  # from app.py
        assert any(f["file"] == "app.js" for f in body["findings"])  # JS analyzer ran too

        assert body["file_count"] == 2
        assert set(body["languages"]) == {"Python", "JavaScript"}

    def test_real_summary_reflects_real_findings(self, real_local_repo):
        with patch("app.api.analyze.clone_repository", return_value=real_local_repo), \
             patch("app.api.analyze.get_default_branch", return_value="main"), \
             patch("app.api.analyze.cleanup_repository"):
            resp = client.post("/analyze", json={"github_url": "https://github.com/x/y"})

        summary = resp.json()["summary"]
        assert summary["risk_score"] > 0
        assert summary["severity_distribution"].get("high", 0) >= 1

    def test_real_filters_narrow_real_results(self, real_local_repo):
        with patch("app.api.analyze.clone_repository", return_value=real_local_repo), \
             patch("app.api.analyze.get_default_branch", return_value="main"), \
             patch("app.api.analyze.cleanup_repository"):
            resp = client.post("/analyze", json={
                "github_url": "https://github.com/x/y",
                "language_filter": ["Python"],
            })

        body = resp.json()
        assert body["file_count"] == 1
        assert all(f["file"] == "app.py" for f in body["findings"])


class TestFullValidateIntegration:
    """/validate's AI call is still mocked (no real network access to
    OpenAI in this environment — see the Module 4 section above for
    the same constraint) — everything else (clone boundary aside) runs
    for real, including the feedback store write, which this test
    verifies actually landed on disk."""

    def test_real_scan_through_to_feedback_store(self, real_local_repo):
        from app.schemas.findings import ValidatedFinding
        from app.services import feedback_store

        def fake_validate(findings):
            return [
                ValidatedFinding(
                    **f.model_dump(), verified=True, confidence="high",
                    explanation="e", exploit_scenario="s", patch_suggestion="p", things_to_verify=[],
                )
                for f in findings
            ]

        with patch("app.api.validate.clone_repository", return_value=real_local_repo), \
             patch("app.api.validate.get_default_branch", return_value="main"), \
             patch("app.api.validate.cleanup_repository"), \
             patch("app.api.validate.validate_findings", side_effect=fake_validate):
            resp = client.post("/validate", json={"github_url": "https://github.com/x/y"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["verified_finding_count"] >= 2  # at least the SQL injection and command injection

        # The feedback store write is real — confirm it actually landed.
        stats = feedback_store.get_rule_stats()
        stat_rule_ids = {s.rule_id for s in stats}
        assert "sql-injection-string-build" in stat_rule_ids

        history = feedback_store.get_scan_history()
        assert len(history) == 1
        assert history[0].repository == "https://github.com/x/y"
