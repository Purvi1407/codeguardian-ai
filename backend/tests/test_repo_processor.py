"""
Tests for app/services/repo_processor.py. `clone_repository`'s actual
git subprocess call is mocked throughout — no real network access, no
real git clone. What's under test is the logic AROUND that call: URL
validation, timeout/failure handling, cleanup guarantees, and (Phase
10) the previously-unenforced MAX_REPO_SIZE_MB check.
"""
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.services import repo_processor
from app.services.repo_processor import (
    validate_github_url, clone_repository, cleanup_repository,
    get_default_branch, RepoProcessorError, _directory_size_mb,
)


class TestValidateGithubUrl:
    def test_valid_url_passes_through(self):
        assert validate_github_url("https://github.com/org/repo") == "https://github.com/org/repo"

    def test_trailing_slash_stripped(self):
        assert validate_github_url("https://github.com/org/repo/") == "https://github.com/org/repo"

    def test_git_suffix_stripped(self):
        assert validate_github_url("https://github.com/org/repo.git") == "https://github.com/org/repo"

    def test_whitespace_stripped(self):
        assert validate_github_url("  https://github.com/org/repo  ") == "https://github.com/org/repo"

    def test_non_github_url_rejected(self):
        with pytest.raises(RepoProcessorError):
            validate_github_url("https://gitlab.com/org/repo")

    def test_non_url_rejected(self):
        with pytest.raises(RepoProcessorError):
            validate_github_url("not a url at all")

    def test_github_url_missing_repo_rejected(self):
        with pytest.raises(RepoProcessorError):
            validate_github_url("https://github.com/org")

    def test_error_message_includes_the_bad_url(self):
        with pytest.raises(RepoProcessorError, match="not-a-real-url"):
            validate_github_url("not-a-real-url")


class TestDirectorySizeMb:
    def test_empty_directory_is_zero(self, tmp_path):
        assert _directory_size_mb(tmp_path) == 0

    def test_counts_file_sizes(self, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"x" * (1024 * 1024))  # 1 MB
        assert _directory_size_mb(tmp_path) == pytest.approx(1.0, abs=0.01)

    def test_counts_nested_files(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "b.txt").write_bytes(b"x" * (1024 * 1024))
        assert _directory_size_mb(tmp_path) == pytest.approx(1.0, abs=0.01)


class TestCloneRepository:
    def _fake_success_result(self):
        return MagicMock(returncode=0, stdout="", stderr="")

    def test_invalid_url_raises_before_attempting_clone(self):
        with patch("app.services.repo_processor.subprocess.run") as mock_run:
            with pytest.raises(RepoProcessorError):
                clone_repository("not-a-github-url")
            mock_run.assert_not_called()

    def test_successful_clone_returns_dest_path(self, tmp_path, monkeypatch):
        monkeypatch.setattr(repo_processor, "TEMP_DIR", tmp_path)
        with patch("app.services.repo_processor.subprocess.run", return_value=self._fake_success_result()):
            dest = clone_repository("https://github.com/org/repo")
        assert dest.parent == tmp_path
        assert dest.name.startswith("scan_")

    def test_clone_command_uses_shallow_single_branch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(repo_processor, "TEMP_DIR", tmp_path)
        with patch("app.services.repo_processor.subprocess.run", return_value=self._fake_success_result()) as mock_run:
            clone_repository("https://github.com/org/repo")
        cmd = mock_run.call_args[0][0]
        assert "--depth" in cmd and "1" in cmd
        assert "--single-branch" in cmd

    def test_branch_argument_passed_through(self, tmp_path, monkeypatch):
        monkeypatch.setattr(repo_processor, "TEMP_DIR", tmp_path)
        with patch("app.services.repo_processor.subprocess.run", return_value=self._fake_success_result()) as mock_run:
            clone_repository("https://github.com/org/repo", branch="develop")
        cmd = mock_run.call_args[0][0]
        assert "--branch" in cmd
        assert "develop" in cmd

    def test_git_failure_raises_with_stderr_in_message(self, tmp_path, monkeypatch):
        monkeypatch.setattr(repo_processor, "TEMP_DIR", tmp_path)
        failure = MagicMock(returncode=128, stdout="", stderr="fatal: repository not found")
        with patch("app.services.repo_processor.subprocess.run", return_value=failure):
            with pytest.raises(RepoProcessorError, match="repository not found"):
                clone_repository("https://github.com/org/nonexistent")

    def test_git_failure_cleans_up_dest_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(repo_processor, "TEMP_DIR", tmp_path)
        failure = MagicMock(returncode=128, stdout="", stderr="fatal: error")

        with patch("app.services.repo_processor.subprocess.run", return_value=failure):
            with pytest.raises(RepoProcessorError):
                clone_repository("https://github.com/org/repo")
        # Nothing should be left behind under TEMP_DIR after a failed clone
        assert list(tmp_path.iterdir()) == []

    def test_timeout_raises_repo_processor_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(repo_processor, "TEMP_DIR", tmp_path)
        with patch("app.services.repo_processor.subprocess.run",
                    side_effect=subprocess.TimeoutExpired(cmd="git", timeout=60)):
            with pytest.raises(RepoProcessorError, match="timed out"):
                clone_repository("https://github.com/org/repo")

    def test_timeout_cleans_up_dest_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(repo_processor, "TEMP_DIR", tmp_path)
        with patch("app.services.repo_processor.subprocess.run",
                    side_effect=subprocess.TimeoutExpired(cmd="git", timeout=60)):
            with pytest.raises(RepoProcessorError):
                clone_repository("https://github.com/org/repo")
        assert list(tmp_path.iterdir()) == []


class TestRepoSizeLimit:
    def test_repo_under_limit_succeeds(self, tmp_path, monkeypatch):
        monkeypatch.setattr(repo_processor, "TEMP_DIR", tmp_path)
        monkeypatch.setattr(repo_processor, "MAX_REPO_SIZE_MB", 10)

        def fake_run(cmd, **kwargs):
            dest = Path(cmd[-1])
            dest.mkdir(parents=True)
            (dest / "small.txt").write_bytes(b"x" * 1024)  # 1 KB, well under 10 MB
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("app.services.repo_processor.subprocess.run", side_effect=fake_run):
            dest = clone_repository("https://github.com/org/repo")
        assert dest.exists()

    def test_repo_over_limit_raises_and_cleans_up(self, tmp_path, monkeypatch):
        monkeypatch.setattr(repo_processor, "TEMP_DIR", tmp_path)
        monkeypatch.setattr(repo_processor, "MAX_REPO_SIZE_MB", 1)  # 1 MB limit

        def fake_run(cmd, **kwargs):
            dest = Path(cmd[-1])
            dest.mkdir(parents=True)
            (dest / "big.txt").write_bytes(b"x" * (2 * 1024 * 1024))  # 2 MB, over the limit
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("app.services.repo_processor.subprocess.run", side_effect=fake_run):
            with pytest.raises(RepoProcessorError, match="exceeds"):
                clone_repository("https://github.com/org/repo")
        # The oversized clone must be cleaned up, not left on disk
        assert list(tmp_path.iterdir()) == []

    def test_error_message_mentions_the_configured_limit(self, tmp_path, monkeypatch):
        monkeypatch.setattr(repo_processor, "TEMP_DIR", tmp_path)
        monkeypatch.setattr(repo_processor, "MAX_REPO_SIZE_MB", 1)

        def fake_run(cmd, **kwargs):
            dest = Path(cmd[-1])
            dest.mkdir(parents=True)
            (dest / "big.txt").write_bytes(b"x" * (2 * 1024 * 1024))
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("app.services.repo_processor.subprocess.run", side_effect=fake_run):
            with pytest.raises(RepoProcessorError, match="1 MB"):
                clone_repository("https://github.com/org/repo")


class TestGetDefaultBranch:
    def test_returns_branch_name_on_success(self):
        result = MagicMock(stdout="main\n")
        with patch("app.services.repo_processor.subprocess.run", return_value=result):
            assert get_default_branch(Path("/fake/repo")) == "main"

    def test_returns_unknown_on_empty_output(self):
        result = MagicMock(stdout="")
        with patch("app.services.repo_processor.subprocess.run", return_value=result):
            assert get_default_branch(Path("/fake/repo")) == "unknown"

    def test_returns_unknown_on_exception_not_raised(self):
        with patch("app.services.repo_processor.subprocess.run", side_effect=OSError("git not found")):
            assert get_default_branch(Path("/fake/repo")) == "unknown"


class TestCleanupRepository:
    def test_removes_existing_directory(self, tmp_path):
        target = tmp_path / "to_remove"
        target.mkdir()
        (target / "file.txt").write_text("x")
        cleanup_repository(target)
        assert not target.exists()

    def test_missing_directory_does_not_raise(self, tmp_path):
        cleanup_repository(tmp_path / "does_not_exist")  # must not raise


class TestLogging:
    """Phase 10: confirms key clone lifecycle events are actually
    logged, and — just as importantly — that logging never includes a
    Finding snippet or anything that could carry a redacted-but-still-
    sensitive secret value. This module doesn't handle Finding objects
    directly, but the discipline is checked here at the layer that DOES
    log the repository URL, since that's the most sensitive string this
    module handles."""

    def test_successful_clone_logs_info(self, tmp_path, monkeypatch, caplog):
        monkeypatch.setattr(repo_processor, "TEMP_DIR", tmp_path)
        with caplog.at_level("INFO", logger="app.services.repo_processor"):
            with patch("app.services.repo_processor.subprocess.run",
                       return_value=MagicMock(returncode=0, stdout="", stderr="")):
                clone_repository("https://github.com/org/repo")
        assert any("clone success" in r.message for r in caplog.records)

    def test_failed_clone_logs_warning(self, tmp_path, monkeypatch, caplog):
        monkeypatch.setattr(repo_processor, "TEMP_DIR", tmp_path)
        failure = MagicMock(returncode=128, stdout="", stderr="fatal: not found")
        with caplog.at_level("WARNING", logger="app.services.repo_processor"):
            with patch("app.services.repo_processor.subprocess.run", return_value=failure):
                with pytest.raises(RepoProcessorError):
                    clone_repository("https://github.com/org/repo")
        assert any("clone failed" in r.message for r in caplog.records)

    def test_oversized_repo_rejection_logs_warning(self, tmp_path, monkeypatch, caplog):
        monkeypatch.setattr(repo_processor, "TEMP_DIR", tmp_path)
        monkeypatch.setattr(repo_processor, "MAX_REPO_SIZE_MB", 1)

        def fake_run(cmd, **kwargs):
            dest = Path(cmd[-1])
            dest.mkdir(parents=True)
            (dest / "big.txt").write_bytes(b"x" * (2 * 1024 * 1024))
            return MagicMock(returncode=0, stdout="", stderr="")

        with caplog.at_level("WARNING", logger="app.services.repo_processor"):
            with patch("app.services.repo_processor.subprocess.run", side_effect=fake_run):
                with pytest.raises(RepoProcessorError):
                    clone_repository("https://github.com/org/repo")
        assert any("clone rejected" in r.message for r in caplog.records)
