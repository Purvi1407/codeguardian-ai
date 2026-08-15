"""
Tests for app/services/feedback_store.py. Every test gets an isolated
SQLite file via CODEGUARDIAN_DB_FILE (same pattern as Phase 5's
ai/cache.py tests) — no test ever touches the real project database.
"""
import pytest

from app.services import feedback_store
from app.schemas.findings import ValidatedFinding


def make_validated(rule_id="sql-injection-string-build", verified=True, confidence="high", **overrides):
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
        confidence=confidence,
        explanation="Explanation.",
        exploit_scenario="Scenario.",
        patch_suggestion="Patch.",
        things_to_verify=[],
    )
    defaults.update(overrides)
    return ValidatedFinding(**defaults)


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test_feedback.db"
    monkeypatch.setenv("CODEGUARDIAN_DB_FILE", str(db_path))
    yield db_path


class TestRecordAndRetrieveValidations:
    def test_empty_findings_list_is_a_no_op(self):
        feedback_store.record_validations("org/repo", [])
        assert feedback_store.get_rule_stats() == []

    def test_single_verified_finding_recorded(self):
        feedback_store.record_validations("org/repo", [make_validated(verified=True)])
        stats = feedback_store.get_rule_stats()
        assert len(stats) == 1
        assert stats[0].rule_id == "sql-injection-string-build"
        assert stats[0].total_validations == 1
        assert stats[0].verified_count == 1
        assert stats[0].dismissed_count == 0

    def test_single_dismissed_finding_recorded(self):
        feedback_store.record_validations("org/repo", [make_validated(verified=False)])
        stats = feedback_store.get_rule_stats()
        assert stats[0].verified_count == 0
        assert stats[0].dismissed_count == 1

    def test_multiple_findings_across_different_rules(self):
        feedback_store.record_validations("org/repo", [
            make_validated(rule_id="sql-injection-string-build", verified=True),
            make_validated(rule_id="weak-crypto-hash", verified=False),
        ])
        stats = {s.rule_id: s for s in feedback_store.get_rule_stats()}
        assert stats["sql-injection-string-build"].verified_count == 1
        assert stats["weak-crypto-hash"].dismissed_count == 1

    def test_recording_across_multiple_calls_accumulates(self):
        """Simulates two separate /validate scans over time — stats
        should accumulate, not overwrite."""
        feedback_store.record_validations("org/repo", [make_validated(verified=True)])
        feedback_store.record_validations("org/repo", [make_validated(verified=True)])
        feedback_store.record_validations("org/repo", [make_validated(verified=False)])

        stats = feedback_store.get_rule_stats()
        assert stats[0].total_validations == 3
        assert stats[0].verified_count == 2
        assert stats[0].dismissed_count == 1


class TestDismissalRateComputation:
    def test_dismissal_rate_is_dismissed_over_total(self):
        feedback_store.record_validations("org/repo", [
            make_validated(verified=True),
            make_validated(verified=True),
            make_validated(verified=False),
            make_validated(verified=False),
        ])
        stats = feedback_store.get_rule_stats()
        assert stats[0].dismissal_rate == 0.5

    def test_all_verified_gives_zero_dismissal_rate(self):
        feedback_store.record_validations("org/repo", [make_validated(verified=True)] * 3)
        stats = feedback_store.get_rule_stats()
        assert stats[0].dismissal_rate == 0.0

    def test_all_dismissed_gives_dismissal_rate_of_one(self):
        feedback_store.record_validations("org/repo", [make_validated(verified=False)] * 3)
        stats = feedback_store.get_rule_stats()
        assert stats[0].dismissal_rate == 1.0


class TestNeedsReviewFlag:
    def test_high_dismissal_rate_with_enough_samples_flags_needs_review(self, monkeypatch):
        monkeypatch.setenv("CODEGUARDIAN_MIN_SAMPLE_SIZE", "3")
        monkeypatch.setenv("CODEGUARDIAN_DISMISSAL_THRESHOLD", "0.5")
        feedback_store.record_validations("org/repo", [
            make_validated(verified=False),
            make_validated(verified=False),
            make_validated(verified=False),
            make_validated(verified=True),
        ])
        stats = feedback_store.get_rule_stats()
        assert stats[0].needs_review is True

    def test_high_dismissal_rate_with_too_few_samples_does_not_flag(self, monkeypatch):
        """The whole point of the sample-size gate: a rule dismissed
        once out of one validation has a 100% dismissal rate, but
        that's not a reliable signal yet."""
        monkeypatch.setenv("CODEGUARDIAN_MIN_SAMPLE_SIZE", "5")
        feedback_store.record_validations("org/repo", [make_validated(verified=False)])
        stats = feedback_store.get_rule_stats()
        assert stats[0].needs_review is False

    def test_low_dismissal_rate_with_enough_samples_does_not_flag(self, monkeypatch):
        monkeypatch.setenv("CODEGUARDIAN_MIN_SAMPLE_SIZE", "3")
        monkeypatch.setenv("CODEGUARDIAN_DISMISSAL_THRESHOLD", "0.5")
        feedback_store.record_validations("org/repo", [
            make_validated(verified=True),
            make_validated(verified=True),
            make_validated(verified=True),
            make_validated(verified=False),
        ])
        stats = feedback_store.get_rule_stats()
        assert stats[0].needs_review is False


class TestScanHistory:
    def test_empty_history_returns_empty_list(self):
        assert feedback_store.get_scan_history() == []

    def test_recorded_scan_appears_in_history(self):
        feedback_store.record_scan("org/repo", "main", candidate_count=10, verified_count=3, risk_score=25)
        history = feedback_store.get_scan_history()
        assert len(history) == 1
        assert history[0].repository == "org/repo"
        assert history[0].branch == "main"
        assert history[0].candidate_finding_count == 10
        assert history[0].verified_finding_count == 3
        assert history[0].risk_score == 25

    def test_filtered_by_repository(self):
        feedback_store.record_scan("org/repo-a", "main", 5, 1, 10)
        feedback_store.record_scan("org/repo-b", "main", 5, 1, 10)

        history = feedback_store.get_scan_history(repository="org/repo-a")
        assert len(history) == 1
        assert history[0].repository == "org/repo-a"

    def test_most_recent_scan_first(self):
        feedback_store.record_scan("org/repo", "main", 1, 1, 5)
        feedback_store.record_scan("org/repo", "main", 2, 2, 10)
        feedback_store.record_scan("org/repo", "main", 3, 3, 15)

        history = feedback_store.get_scan_history()
        assert [h.risk_score for h in history] == [15, 10, 5]

    def test_limit_is_respected(self):
        for i in range(10):
            feedback_store.record_scan("org/repo", "main", i, i, i)

        history = feedback_store.get_scan_history(limit=3)
        assert len(history) == 3


class TestPersistenceAcrossConnections:
    def test_data_written_in_one_call_visible_in_a_fresh_call(self):
        """Confirms this actually persists to disk, not just an
        in-memory structure that happens to survive within one test —
        each public function opens and closes its own connection."""
        feedback_store.record_validations("org/repo", [make_validated(verified=True)])
        feedback_store.record_scan("org/repo", "main", 1, 1, 5)

        stats = feedback_store.get_rule_stats()
        history = feedback_store.get_scan_history()
        assert len(stats) == 1
        assert len(history) == 1
