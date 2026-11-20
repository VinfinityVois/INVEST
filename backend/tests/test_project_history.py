from app.main import _project_file_snapshot, _project_snapshot_diff


def test_project_snapshot_detects_content_changes_and_ignores_git(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / ".git").mkdir()
    (root / "src" / "Main.kt").write_text("fun main() = Unit", encoding="utf-8")
    (root / "README.md").write_text("old", encoding="utf-8")
    (root / ".git" / "config").write_text("internal", encoding="utf-8")

    before = _project_file_snapshot(root)
    (root / "src" / "Main.kt").write_text("fun main() = Two", encoding="utf-8")
    (root / "README.md").unlink()
    (root / "new.txt").write_text("new", encoding="utf-8")
    after = _project_file_snapshot(root)

    assert set(before) == {"src/Main.kt", "README.md"}
    assert set(after) == {"src/Main.kt", "new.txt"}
    diff = _project_snapshot_diff(before, after)
    assert diff["added_count"] == 1
    assert diff["removed_count"] == 1
    assert diff["changed_count"] == 1
    assert diff["added_files"] == ["new.txt"]
    assert diff["removed_files"] == ["README.md"]
    assert diff["changed_files"] == ["src/Main.kt"]


def test_project_snapshot_diff_limits_path_samples():
    before = {f"old-{index}.txt": {"size": 1, "sha256": "a"} for index in range(60)}
    after = {f"new-{index}.txt": {"size": 1, "sha256": "b"} for index in range(60)}

    diff = _project_snapshot_diff(before, after)

    assert diff["added_count"] == 60
    assert diff["removed_count"] == 60
    assert len(diff["added_files"]) == 50
    assert len(diff["removed_files"]) == 50
    assert diff["sample_truncated"] is True


from pathlib import PurePosixPath

from app.main import _project_content_is_safe, _project_path_is_sensitive


def test_project_editor_blocks_secret_paths_in_nested_directories():
    assert _project_path_is_sensitive(PurePosixPath("config/private/app.yaml"))
    assert _project_path_is_sensitive(PurePosixPath("src/.env.production"))
    assert not _project_path_is_sensitive(PurePosixPath("src/application.yaml"))


def test_project_editor_rejects_secret_like_content():
    assert _project_content_is_safe("name: sample\nversion: 1.0\n")
    assert not _project_content_is_safe("API_TOKEN=example-secret-value\n")
    assert not _project_content_is_safe("token: unquoted-secret-value\\n")
    assert not _project_content_is_safe("-----BEGIN RSA PRIVATE KEY-----\\n")
