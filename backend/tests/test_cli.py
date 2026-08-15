"""
Tests for app/cli.py. Calls run() directly (not via subprocess) against
real fixture files on disk under tests/fixtures/ and tmp_path
directories — no mocking needed, since the CLI is designed to scan a
local directory directly with no network dependency at all.
"""
import json
import subprocess

import pytest

from app import cli

VULNERABLE_PY = "import os\ndef vuln(cmd):\n    os.system(cmd)\n"
SAFE_PY = "def safe():\n    return 1\n"


@pytest.fixture
def vuln_dir(tmp_path):
    (tmp_path / "vuln.py").write_text(VULNERABLE_PY, encoding="utf-8")
    return tmp_path


@pytest.fixture
def safe_dir(tmp_path):
    (tmp_path / "safe.py").write_text(SAFE_PY, encoding="utf-8")
    return tmp_path


class TestBasicScanning:
    def test_exit_code_0_on_clean_directory(self, safe_dir, capsys):
        code = cli.run(["--path", str(safe_dir)])
        assert code == 0
        assert "No findings" in capsys.readouterr().out

    def test_exit_code_0_on_vulnerable_dir_with_no_fail_on(self, vuln_dir, capsys):
        """Without --fail-on, findings are reported but don't affect
        the exit code — a CI job that wants JSON/SARIF output without
        gating the build should be able to opt into that."""
        code = cli.run(["--path", str(vuln_dir)])
        assert code == 0
        assert "command-injection-os-system" in capsys.readouterr().out

    def test_bad_path_exits_2(self, capsys):
        code = cli.run(["--path", "/this/path/does/not/exist"])
        assert code == 2
        assert "not a directory" in capsys.readouterr().err


class TestSeverityGate:
    def test_fail_on_high_triggers_on_high_severity_finding(self, vuln_dir):
        code = cli.run(["--path", str(vuln_dir), "--fail-on", "high"])
        assert code == 1

    def test_fail_on_high_does_not_trigger_on_clean_dir(self, safe_dir):
        code = cli.run(["--path", str(safe_dir), "--fail-on", "high"])
        assert code == 0

    def test_fail_on_low_triggers_on_high_severity_finding_too(self, vuln_dir):
        """--fail-on low means 'anything at or above low', so a high
        finding still triggers it — the gate is a floor, not an exact
        match."""
        code = cli.run(["--path", str(vuln_dir), "--fail-on", "low"])
        assert code == 1

    def test_fail_on_high_does_not_trigger_on_low_severity_only(self, tmp_path):
        (tmp_path / "weak.py").write_text("import hashlib\ndef h():\n    return hashlib.md5(b'x')\n", encoding="utf-8")
        code = cli.run(["--path", str(tmp_path), "--fail-on", "high"])
        assert code == 0  # weak-crypto-hash is "low" severity


class TestOutputFormats:
    def test_json_format_is_valid_json_array(self, vuln_dir, capsys):
        cli.run(["--path", str(vuln_dir), "--format", "json"])
        out = capsys.readouterr().out
        data = json.loads(out)
        assert isinstance(data, list)
        assert data[0]["rule_id"] == "command-injection-os-system"

    def test_sarif_format_is_valid_sarif_structure(self, vuln_dir, capsys):
        cli.run(["--path", str(vuln_dir), "--format", "sarif"])
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) >= 1

    def test_output_to_file(self, vuln_dir, tmp_path, capsys):
        out_file = tmp_path.parent / "cli_output.json"
        code = cli.run(["--path", str(vuln_dir), "--format", "json", "--output", str(out_file)])
        assert code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        # Nothing should have gone to stdout when --output is used
        assert capsys.readouterr().out == ""


class TestBaseline:
    def test_write_baseline_creates_file_and_exits_0(self, vuln_dir, tmp_path, capsys):
        baseline_path = tmp_path.parent / "baseline.json"
        code = cli.run(["--path", str(vuln_dir), "--write-baseline", str(baseline_path)])
        assert code == 0
        assert baseline_path.exists()
        assert "Baseline written" in capsys.readouterr().out

    def test_write_baseline_ignores_fail_on(self, vuln_dir, tmp_path):
        """Writing a baseline is a snapshot operation, not a gate check
        — even with --fail-on high and high-severity findings present,
        this should exit 0."""
        baseline_path = tmp_path.parent / "baseline.json"
        code = cli.run(["--path", str(vuln_dir), "--write-baseline", str(baseline_path), "--fail-on", "high"])
        assert code == 0

    def test_baseline_suppresses_previously_seen_findings(self, vuln_dir, tmp_path, capsys):
        baseline_path = tmp_path.parent / "baseline.json"
        cli.run(["--path", str(vuln_dir), "--write-baseline", str(baseline_path)])
        capsys.readouterr()  # clear captured output from the write-baseline run

        code = cli.run(["--path", str(vuln_dir), "--baseline", str(baseline_path), "--fail-on", "high"])
        assert code == 0
        assert "No findings" in capsys.readouterr().out

    def test_baseline_still_reports_genuinely_new_findings(self, vuln_dir, tmp_path, capsys):
        baseline_path = tmp_path.parent / "baseline.json"
        cli.run(["--path", str(vuln_dir), "--write-baseline", str(baseline_path)])
        capsys.readouterr()

        # Add a new, different vulnerability after the baseline was captured
        (vuln_dir / "new_vuln.py").write_text(
            "import hashlib\ndef h():\n    return hashlib.md5(b'x')\n", encoding="utf-8"
        )
        code = cli.run(["--path", str(vuln_dir), "--baseline", str(baseline_path)])
        assert code == 0
        out = capsys.readouterr().out
        assert "weak-crypto-hash" in out
        assert "1 finding" in out  # only the new one, not the baselined one too


class TestChangedOnly:
    def _init_git_repo_with_two_commits(self, tmp_path):
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, check=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=tmp_path, check=True)
        (tmp_path / "existing.py").write_text(SAFE_PY, encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=tmp_path, check=True)
        subprocess.run(["git", "branch", "base"], cwd=tmp_path, check=True)
        (tmp_path / "new_vuln.py").write_text(VULNERABLE_PY, encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "add vuln"], cwd=tmp_path, check=True)

    def test_only_reports_findings_in_changed_files(self, tmp_path, capsys):
        self._init_git_repo_with_two_commits(tmp_path)
        # Also add a pre-existing vulnerability to the untouched file to
        # confirm it's excluded even though it would show up in a full scan
        (tmp_path / "existing.py").write_text(VULNERABLE_PY, encoding="utf-8")
        subprocess.run(["git", "stash"], cwd=tmp_path, check=True)  # revert that edit so it's NOT "changed"

        code = cli.run(["--path", str(tmp_path), "--changed-only", "--base-ref", "base"])
        assert code == 0
        out = capsys.readouterr().out
        assert "new_vuln.py" in out
        assert "existing.py" not in out

    def test_bad_base_ref_exits_2(self, tmp_path, capsys):
        self._init_git_repo_with_two_commits(tmp_path)
        code = cli.run(["--path", str(tmp_path), "--changed-only", "--base-ref", "totally-nonexistent-ref"])
        assert code == 2
        assert "git diff" in capsys.readouterr().err
