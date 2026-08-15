"""
API-level tests for the filtering fields (Phase 6) on /scan, /analyze,
and /validate. Uses FastAPI's TestClient against the real app, but with
repo_processor (cloning), scan_service (parsing/analysis), and
ai.validator (AI calls) all mocked — no real network access, no real
git clone, no real OpenAI call. This is the first committed test file
that exercises the API layer at all; everything before this phase
tested the analyzer/parser/AI modules directly, not the FastAPI routes
wired around them.
"""
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.findings import Finding, ValidatedFinding
from app.schemas.scan import FileMetadata

client = TestClient(app)


def make_finding(**overrides):
    defaults = dict(
        rule_id="sql-injection-string-build",
        title="SQL query built with string formatting",
        severity="high",
        cwe="CWE-89",
        file="app.py",
        function="handler",
        line=10,
        snippet="cursor.execute(query)",
        description="A SQL query is built dynamically.",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def make_validated(finding, verified=True, confidence="high"):
    return ValidatedFinding(
        **finding.model_dump(),
        verified=verified,
        confidence=confidence,
        explanation="Explanation.",
        exploit_scenario="Scenario.",
        patch_suggestion="Patch.",
        things_to_verify=[],
    )


SAMPLE_FILES = [
    FileMetadata(path="app.py", language="Python"),
    FileMetadata(path="app.js", language="JavaScript"),
]

SAMPLE_FINDINGS = [
    make_finding(file="app.py", severity="high", rule_id="sql-injection-string-build",
                 title="SQL query built with string formatting",
                 description="A SQL query is built dynamically."),
    make_finding(file="app.js", severity="low", rule_id="weak-crypto-hash",
                 title="Weak hash algorithm (MD5/SHA1)",
                 description="Uses an outdated hashing algorithm.", snippet="hashlib.md5(data)"),
]


@pytest.fixture(autouse=True)
def mock_repo_pipeline(tmp_path, monkeypatch):
    """Mocks the parts of the pipeline that would otherwise need real
    network access (cloning a GitHub repo) — every test in this file
    gets a fake, deterministic repo/scan result to filter against.
    Also isolates the Phase 9 feedback-store DB to a temp file, so
    /validate calls in this file never touch the real project database."""
    monkeypatch.setenv("CODEGUARDIAN_DB_FILE", str(tmp_path / "test_feedback.db"))
    with patch("app.api.scan.clone_repository", return_value="/fake/repo"), \
         patch("app.api.scan.get_default_branch", return_value="main"), \
         patch("app.api.scan.cleanup_repository"), \
         patch("app.api.scan.build_file_metadata", return_value=list(SAMPLE_FILES)), \
         patch("app.api.analyze.clone_repository", return_value="/fake/repo"), \
         patch("app.api.analyze.get_default_branch", return_value="main"), \
         patch("app.api.analyze.cleanup_repository"), \
         patch("app.api.analyze.build_file_metadata_and_findings",
               return_value=(list(SAMPLE_FILES), list(SAMPLE_FINDINGS))), \
         patch("app.api.validate.clone_repository", return_value="/fake/repo"), \
         patch("app.api.validate.get_default_branch", return_value="main"), \
         patch("app.api.validate.cleanup_repository"), \
         patch("app.api.validate.build_file_metadata_and_findings",
               return_value=(list(SAMPLE_FILES), list(SAMPLE_FINDINGS))), \
         patch("app.api.validate.get_client"):
        yield


class TestScanLanguageFilter:
    def test_no_filter_returns_all_files(self):
        resp = client.post("/scan", json={"github_url": "https://github.com/x/y"})
        assert resp.status_code == 200
        assert resp.json()["file_count"] == 2

    def test_language_filter_narrows_files(self):
        resp = client.post("/scan", json={"github_url": "https://github.com/x/y", "language_filter": ["Python"]})
        assert resp.status_code == 200
        body = resp.json()
        assert body["file_count"] == 1
        assert body["files"][0]["path"] == "app.py"


class TestAnalyzeFilters:
    def test_no_filter_returns_all_findings(self):
        resp = client.post("/analyze", json={"github_url": "https://github.com/x/y"})
        assert resp.status_code == 200
        assert resp.json()["finding_count"] == 2

    def test_severity_filter(self):
        resp = client.post("/analyze", json={"github_url": "https://github.com/x/y", "severity_filter": ["high"]})
        assert resp.status_code == 200
        body = resp.json()
        assert body["finding_count"] == 1
        assert body["findings"][0]["severity"] == "high"

    def test_rule_filter(self):
        resp = client.post("/analyze", json={"github_url": "https://github.com/x/y", "rule_filter": ["weak-crypto-hash"]})
        assert resp.status_code == 200
        body = resp.json()
        assert body["finding_count"] == 1
        assert body["findings"][0]["rule_id"] == "weak-crypto-hash"

    def test_language_filter_narrows_both_files_and_findings(self):
        resp = client.post("/analyze", json={"github_url": "https://github.com/x/y", "language_filter": ["JavaScript"]})
        assert resp.status_code == 200
        body = resp.json()
        assert body["file_count"] == 1
        assert body["finding_count"] == 1
        assert body["findings"][0]["file"] == "app.js"

    def test_search_filter(self):
        resp = client.post("/analyze", json={"github_url": "https://github.com/x/y", "search": "sql"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["finding_count"] == 1
        assert body["findings"][0]["rule_id"] == "sql-injection-string-build"

    def test_filters_that_match_nothing_return_empty_list_not_error(self):
        resp = client.post("/analyze", json={"github_url": "https://github.com/x/y", "search": "nonexistent_xyz"})
        assert resp.status_code == 200
        assert resp.json()["finding_count"] == 0
        assert resp.json()["findings"] == []


class TestValidateFilters:
    def test_filters_apply_before_ai_validation_not_just_after(self):
        """The critical Phase 6 behavior: validate_findings() should
        only ever be called with the FILTERED candidates, never the
        full unfiltered list — confirms filtering happens before, not
        after, the (costly) AI call."""
        with patch("app.api.validate.validate_findings") as mock_validate:
            mock_validate.side_effect = lambda findings: [make_validated(f) for f in findings]

            resp = client.post("/validate", json={
                "github_url": "https://github.com/x/y",
                "severity_filter": ["high"],
            })

            assert resp.status_code == 200
            called_with = mock_validate.call_args[0][0]
            assert len(called_with) == 1
            assert called_with[0].severity == "high"

    def test_candidate_finding_count_reflects_post_filter_count(self):
        with patch("app.api.validate.validate_findings") as mock_validate:
            mock_validate.side_effect = lambda findings: [make_validated(f) for f in findings]

            resp = client.post("/validate", json={
                "github_url": "https://github.com/x/y",
                "rule_filter": ["sql-injection-string-build"],
            })

        assert resp.status_code == 200
        assert resp.json()["candidate_finding_count"] == 1

    def test_no_filter_validates_everything(self):
        with patch("app.api.validate.validate_findings") as mock_validate:
            mock_validate.side_effect = lambda findings: [make_validated(f) for f in findings]

            resp = client.post("/validate", json={"github_url": "https://github.com/x/y"})

        assert resp.status_code == 200
        called_with = mock_validate.call_args[0][0]
        assert len(called_with) == 2

    def test_validate_records_to_feedback_store(self):
        """Phase 9: every /validate call should record its verdicts,
        so /stats/rules and /stats/scans reflect real usage over time."""
        from app.services import feedback_store

        with patch("app.api.validate.validate_findings") as mock_validate:
            mock_validate.side_effect = lambda findings: [make_validated(f) for f in findings]
            client.post("/validate", json={"github_url": "https://github.com/x/y"})

        stats = feedback_store.get_rule_stats()
        assert len(stats) == 2  # two distinct rule_ids in SAMPLE_FINDINGS
        history = feedback_store.get_scan_history()
        assert len(history) == 1
        assert history[0].repository == "https://github.com/x/y"

    def test_validate_still_succeeds_if_feedback_store_write_fails(self):
        """Best-effort contract: a feedback-store failure must not
        break the actual /validate response."""
        with patch("app.api.validate.validate_findings") as mock_validate, \
             patch("app.api.validate.feedback_store.record_validations", side_effect=OSError("disk full")):
            mock_validate.side_effect = lambda findings: [make_validated(f) for f in findings]
            resp = client.post("/validate", json={"github_url": "https://github.com/x/y"})

        assert resp.status_code == 200


class TestSummaryInResponse:
    def test_analyze_response_includes_summary(self):
        resp = client.post("/analyze", json={"github_url": "https://github.com/x/y"})
        assert resp.status_code == 200
        summary = resp.json()["summary"]
        assert "risk_score" in summary
        assert "severity_distribution" in summary
        assert "rule_distribution" in summary
        assert summary["severity_distribution"] == {"high": 1, "low": 1}

    def test_analyze_summary_reflects_filtered_findings_not_unfiltered(self):
        resp = client.post("/analyze", json={"github_url": "https://github.com/x/y", "severity_filter": ["high"]})
        assert resp.status_code == 200
        summary = resp.json()["summary"]
        assert summary["severity_distribution"] == {"high": 1}

    def test_validate_response_includes_summary(self):
        with patch("app.api.validate.validate_findings") as mock_validate:
            mock_validate.side_effect = lambda findings: [make_validated(f) for f in findings]
            resp = client.post("/validate", json={"github_url": "https://github.com/x/y"})

        assert resp.status_code == 200
        summary = resp.json()["summary"]
        assert "risk_score" in summary

    def test_validate_summary_computed_over_verified_only_not_dismissed(self):
        with patch("app.api.validate.validate_findings") as mock_validate:
            # First finding verified, second dismissed
            mock_validate.side_effect = lambda findings: [
                make_validated(findings[0], verified=True),
                make_validated(findings[1], verified=False),
            ]
            resp = client.post("/validate", json={"github_url": "https://github.com/x/y"})

        assert resp.status_code == 200
        body = resp.json()
        assert len(body["findings"]) == 1
        assert len(body["dismissed"]) == 1
        # Summary should only reflect the 1 verified finding, not both
        assert sum(body["summary"]["severity_distribution"].values()) == 1


class TestErrorHandling:
    """Confirms each endpoint's error paths actually produce the
    documented status code/body, not just that the happy path works."""

    def test_analyze_bad_repo_url_returns_400(self):
        from app.services.repo_processor import RepoProcessorError
        with patch("app.api.analyze.clone_repository", side_effect=RepoProcessorError("not a valid github url")):
            resp = client.post("/analyze", json={"github_url": "not-a-url"})
        assert resp.status_code == 400
        assert "not a valid github url" in resp.json()["detail"]

    def test_scan_bad_repo_url_returns_400(self):
        from app.services.repo_processor import RepoProcessorError
        with patch("app.api.scan.clone_repository", side_effect=RepoProcessorError("repo not found")):
            resp = client.post("/scan", json={"github_url": "not-a-url"})
        assert resp.status_code == 400

    def test_validate_missing_api_key_returns_500_before_cloning(self):
        """Fails fast on missing API key, before any clone happens —
        confirms clone_repository is never even called in this case."""
        from app.ai.client import AIConfigError
        with patch("app.api.validate.get_client", side_effect=AIConfigError("OPENAI_API_KEY not set")):
            with patch("app.api.validate.clone_repository") as mock_clone:
                resp = client.post("/validate", json={"github_url": "https://github.com/x/y"})

        assert resp.status_code == 500
        mock_clone.assert_not_called()

    def test_validate_bad_repo_url_returns_400(self):
        from app.services.repo_processor import RepoProcessorError
        with patch("app.api.validate.clone_repository", side_effect=RepoProcessorError("clone failed")):
            resp = client.post("/validate", json={"github_url": "not-a-url"})
        assert resp.status_code == 400

    def test_validate_ai_validation_error_returns_502(self):
        from app.ai.validator import AIValidationError
        with patch("app.api.validate.validate_findings", side_effect=AIValidationError("API call failed")):
            resp = client.post("/validate", json={"github_url": "https://github.com/x/y"})
        assert resp.status_code == 502

    def test_validate_unexpected_error_returns_500_not_unhandled_exception(self):
        """Defense-in-depth catch-all — an unexpected exception during
        validation must still come back as a readable 500, not an
        opaque server crash."""
        with patch("app.api.validate.validate_findings", side_effect=TypeError("unexpected None")):
            resp = client.post("/validate", json={"github_url": "https://github.com/x/y"})
        assert resp.status_code == 500
        assert "Unexpected error" in resp.json()["detail"]
