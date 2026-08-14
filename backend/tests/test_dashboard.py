"""
Tests for app/services/dashboard.py — pure computation, no network,
no mocking needed.
"""
from app.schemas.findings import Finding
from app.services.dashboard import compute_summary, SEVERITY_WEIGHTS, MAX_RISK_SCORE


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


class TestEmptyInput:
    def test_no_findings_gives_zero_score(self):
        summary = compute_summary([])
        assert summary.risk_score == 0
        assert summary.severity_distribution == {}
        assert summary.rule_distribution == {}


class TestSeverityDistribution:
    def test_counts_each_severity(self):
        findings = [
            make_finding(severity="high"),
            make_finding(severity="high"),
            make_finding(severity="medium"),
            make_finding(severity="low"),
        ]
        summary = compute_summary(findings)
        assert summary.severity_distribution == {"high": 2, "medium": 1, "low": 1}

    def test_case_normalized_to_lowercase(self):
        findings = [make_finding(severity="High"), make_finding(severity="HIGH")]
        summary = compute_summary(findings)
        assert summary.severity_distribution == {"high": 2}


class TestRuleDistribution:
    def test_counts_each_rule_id(self):
        findings = [
            make_finding(rule_id="sql-injection-string-build"),
            make_finding(rule_id="sql-injection-string-build"),
            make_finding(rule_id="weak-crypto-hash"),
        ]
        summary = compute_summary(findings)
        assert summary.rule_distribution == {"sql-injection-string-build": 2, "weak-crypto-hash": 1}


class TestRiskScore:
    def test_single_high_severity_finding(self):
        summary = compute_summary([make_finding(severity="high")])
        assert summary.risk_score == SEVERITY_WEIGHTS["high"]

    def test_single_medium_severity_finding(self):
        summary = compute_summary([make_finding(severity="medium")])
        assert summary.risk_score == SEVERITY_WEIGHTS["medium"]

    def test_single_low_severity_finding(self):
        summary = compute_summary([make_finding(severity="low")])
        assert summary.risk_score == SEVERITY_WEIGHTS["low"]

    def test_score_is_weighted_sum_across_severities(self):
        findings = [
            make_finding(severity="high"),   # 10
            make_finding(severity="medium"), # 5
            make_finding(severity="low"),    # 1
        ]
        summary = compute_summary(findings)
        expected = SEVERITY_WEIGHTS["high"] + SEVERITY_WEIGHTS["medium"] + SEVERITY_WEIGHTS["low"]
        assert summary.risk_score == expected

    def test_score_caps_at_max_even_with_many_high_severity_findings(self):
        findings = [make_finding(severity="high") for _ in range(50)]  # 50 * 10 = 500, way over cap
        summary = compute_summary(findings)
        assert summary.risk_score == MAX_RISK_SCORE

    def test_score_never_exceeds_max_risk_score(self):
        findings = [make_finding(severity="high") for _ in range(1000)]
        summary = compute_summary(findings)
        assert summary.risk_score <= MAX_RISK_SCORE

    def test_more_high_severity_findings_increases_score_below_cap(self):
        low_count_summary = compute_summary([make_finding(severity="high")])
        high_count_summary = compute_summary([make_finding(severity="high"), make_finding(severity="high")])
        assert high_count_summary.risk_score > low_count_summary.risk_score

    def test_unknown_severity_contributes_zero_not_an_error(self):
        """Defensive: a severity string outside high/medium/low (e.g. a
        future rule with a typo, or an unexpected value) must not crash
        the score computation — it just doesn't contribute weight."""
        summary = compute_summary([make_finding(severity="critical")])
        assert summary.risk_score == 0
        assert summary.severity_distribution == {"critical": 1}
