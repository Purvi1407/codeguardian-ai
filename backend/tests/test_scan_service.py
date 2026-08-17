"""
Tests for app/services/scan_service.py's build_file_metadata (used by
/scan) directly against a real local directory — no mocking needed,
since this function only does filesystem discovery + parsing, both of
which are already fast and side-effect-free.
"""
from app.services.scan_service import build_file_metadata, build_file_metadata_and_findings


class TestBuildFileMetadata:
    def test_discovers_python_file(self, tmp_path):
        (tmp_path / "app.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
        files = build_file_metadata(tmp_path)
        assert len(files) == 1
        assert files[0].path == "app.py"
        assert files[0].language == "Python"

    def test_discovers_js_file(self, tmp_path):
        (tmp_path / "app.js").write_text("function foo() { return 1; }\n", encoding="utf-8")
        files = build_file_metadata(tmp_path)
        assert len(files) == 1
        assert files[0].language == "JavaScript"

    def test_uses_forward_slashes_regardless_of_platform(self, tmp_path):
        sub = tmp_path / "sub" / "dir"
        sub.mkdir(parents=True)
        (sub / "app.py").write_text("x = 1\n", encoding="utf-8")
        files = build_file_metadata(tmp_path)
        assert files[0].path == "sub/dir/app.py"
        assert "\\" not in files[0].path

    def test_results_sorted_by_path(self, tmp_path):
        (tmp_path / "z.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        files = build_file_metadata(tmp_path)
        assert [f.path for f in files] == ["a.py", "z.py"]

    def test_functions_and_classes_populated(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "def my_func():\n    pass\n\nclass MyClass:\n    def method(self):\n        pass\n",
            encoding="utf-8",
        )
        files = build_file_metadata(tmp_path)
        assert any(f.name == "my_func" for f in files[0].functions)
        assert any(c.name == "MyClass" for c in files[0].classes)

    def test_syntax_error_reported_not_raised(self, tmp_path):
        (tmp_path / "broken.py").write_text("def broken(:::\n", encoding="utf-8")
        files = build_file_metadata(tmp_path)
        assert files[0].parse_error is not None

    def test_clean_file_has_no_parse_error(self, tmp_path):
        (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
        files = build_file_metadata(tmp_path)
        assert files[0].parse_error is None

    def test_empty_directory_returns_empty_list(self, tmp_path):
        assert build_file_metadata(tmp_path) == []


class TestBuildFileMetadataAndFindings:
    def test_returns_both_files_and_findings(self, tmp_path):
        (tmp_path / "vuln.py").write_text(
            "import os\ndef f(cmd):\n    os.system(cmd)\n", encoding="utf-8"
        )
        files, findings = build_file_metadata_and_findings(tmp_path)
        assert len(files) == 1
        assert len(findings) == 1
        assert findings[0].rule_id == "command-injection-os-system"

    def test_file_with_syntax_error_is_skipped_for_analysis_not_metadata(self, tmp_path):
        """A file that fails to parse should still show up in `files`
        (with parse_error set) but contribute no findings, since
        analysis can't run on a tree that doesn't exist."""
        (tmp_path / "broken.py").write_text("def broken(:::\n", encoding="utf-8")
        files, findings = build_file_metadata_and_findings(tmp_path)
        assert len(files) == 1
        assert files[0].parse_error is not None
        assert findings == []
