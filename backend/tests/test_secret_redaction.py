"""
Tests for Phase 10's secret redaction: hardcoded-secret findings must
never echo the literal secret value back out in the Finding's snippet —
that value flows into the AI validation prompt (a third party, OpenAI),
the on-disk cache (Phase 5), and the persisted feedback store (Phase 9),
none of which should end up holding a copy of someone's real API key
just because our tool found it.
"""
from pathlib import Path

from app.analyzer.python_rules import analyze_python_file
from app.analyzer.js_ts_rules import analyze_js_ts_file


class TestPythonSecretRedaction:
    def test_literal_secret_value_not_present_in_snippet(self, tmp_path):
        secret = "sk-live-abcdef1234567890REALSECRETVALUE"
        src = f'def get_config():\n    api_key = "{secret}"\n    return api_key\n'
        path = tmp_path / "config.py"
        path.write_text(src, encoding="utf-8")

        findings = analyze_python_file(path, "config.py")
        matches = [f for f in findings if f.rule_id == "hardcoded-secret"]
        assert matches
        assert secret not in matches[0].snippet

    def test_redaction_placeholder_present(self, tmp_path):
        secret = "sk-live-abcdef1234567890REALSECRETVALUE"
        src = f'def get_config():\n    api_key = "{secret}"\n    return api_key\n'
        path = tmp_path / "config.py"
        path.write_text(src, encoding="utf-8")

        findings = analyze_python_file(path, "config.py")
        matches = [f for f in findings if f.rule_id == "hardcoded-secret"]
        assert "<redacted>" in matches[0].snippet

    def test_variable_name_and_surrounding_code_still_visible(self, tmp_path):
        """The finding must stay actionable — you should still be able
        to tell WHERE the secret is and WHAT variable holds it, just
        not the secret's actual value."""
        secret = "sk-live-abcdef1234567890REALSECRETVALUE"
        src = f'def get_config():\n    api_key = "{secret}"\n    return api_key\n'
        path = tmp_path / "config.py"
        path.write_text(src, encoding="utf-8")

        findings = analyze_python_file(path, "config.py")
        matches = [f for f in findings if f.rule_id == "hardcoded-secret"]
        assert "api_key" in matches[0].snippet
        assert "get_config" in matches[0].snippet

    def test_other_findings_on_the_same_file_are_unaffected(self, tmp_path):
        """Redaction is scoped to the specific finding whose value is
        being redacted — a different finding elsewhere in the same
        file (sharing the same snippet window) must not have unrelated
        text redacted."""
        secret = "sk-live-abcdef1234567890REALSECRETVALUE"
        src = (
            f'def get_config():\n    api_key = "{secret}"\n    return api_key\n\n'
            'def run_query(conn, user_id):\n'
            '    cursor = conn.cursor()\n'
            '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        )
        path = tmp_path / "mixed.py"
        path.write_text(src, encoding="utf-8")

        findings = analyze_python_file(path, "mixed.py")
        sql_finding = next(f for f in findings if f.rule_id == "sql-injection-string-build")
        assert "SELECT * FROM users" in sql_finding.snippet
        assert secret not in sql_finding.snippet  # never appeared in this window anyway, sanity check


class TestJsSecretRedaction:
    def test_literal_secret_value_not_present_in_snippet(self, tmp_path):
        secret = "sk-live-abcdef1234567890REALSECRETVALUE"
        src = f'function getConfig() {{\n  const apiKey = "{secret}";\n  return apiKey;\n}}\n'
        path = tmp_path / "config.js"
        path.write_text(src, encoding="utf-8")

        findings = analyze_js_ts_file(path, "config.js")
        matches = [f for f in findings if f.rule_id == "hardcoded-secret"]
        assert matches
        assert secret not in matches[0].snippet

    def test_redaction_placeholder_present(self, tmp_path):
        secret = "sk-live-abcdef1234567890REALSECRETVALUE"
        src = f'function getConfig() {{\n  const apiKey = "{secret}";\n  return apiKey;\n}}\n'
        path = tmp_path / "config.js"
        path.write_text(src, encoding="utf-8")

        findings = analyze_js_ts_file(path, "config.js")
        matches = [f for f in findings if f.rule_id == "hardcoded-secret"]
        assert "<redacted>" in matches[0].snippet

    def test_variable_name_and_surrounding_code_still_visible(self, tmp_path):
        secret = "sk-live-abcdef1234567890REALSECRETVALUE"
        src = f'function getConfig() {{\n  const apiKey = "{secret}";\n  return apiKey;\n}}\n'
        path = tmp_path / "config.js"
        path.write_text(src, encoding="utf-8")

        findings = analyze_js_ts_file(path, "config.js")
        matches = [f for f in findings if f.rule_id == "hardcoded-secret"]
        assert "apiKey" in matches[0].snippet
        assert "getConfig" in matches[0].snippet
