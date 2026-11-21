from pathlib import PurePosixPath

import pytest

from app.security.project_file_history import (
    load_project_file_version,
    save_project_file_version,
)


def test_project_file_snapshot_round_trip(tmp_path):
    relative = PurePosixPath("src/main.py")
    content = "print('version one')\n"
    digest = save_project_file_version(tmp_path, "project-a", relative, content)
    assert load_project_file_version(tmp_path, "project-a", relative, digest) == content


def test_project_file_snapshots_are_content_addressed(tmp_path):
    relative = PurePosixPath("src/main.py")
    first = save_project_file_version(tmp_path, "project-a", relative, "one\n")
    second = save_project_file_version(tmp_path, "project-a", relative, "one\n")
    assert first == second


def test_project_file_snapshots_are_scoped_to_project_and_path(tmp_path):
    relative = PurePosixPath("src/main.py")
    digest = save_project_file_version(tmp_path, "project-a", relative, "one\n")
    with pytest.raises(FileNotFoundError):
        load_project_file_version(tmp_path, "project-b", relative, digest)
    with pytest.raises(FileNotFoundError):
        load_project_file_version(tmp_path, "project-a", PurePosixPath("src/other.py"), digest)


def test_project_file_snapshot_rejects_tampered_content(tmp_path):
    relative = PurePosixPath("src/main.py")
    digest = save_project_file_version(tmp_path, "project-a", relative, "safe\n")
    snapshot = tmp_path / ".invest-versions" / "project-a"
    snapshot = next(snapshot.rglob("*.snapshot"))
    snapshot.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(OSError, match="integrity"):
        load_project_file_version(tmp_path, "project-a", relative, digest)


def test_project_file_snapshot_rejects_invalid_digest(tmp_path):
    with pytest.raises(ValueError, match="digest"):
        load_project_file_version(tmp_path, "project-a", PurePosixPath("src/main.py"), "../bad")
