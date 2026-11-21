import hashlib

import pytest
from filelock import Timeout

from app.security.file_versions import project_file_lock, sha256_text, version_matches


def test_sha256_text_uses_utf8_content():
    content = "class Example: café"
    assert sha256_text(content) == hashlib.sha256(content.encode("utf-8")).hexdigest()


def test_version_matches_accepts_unchanged_snapshot():
    content = "print('safe')\\n"
    assert version_matches(content, sha256_text(content))


def test_version_matches_rejects_stale_snapshot():
    original = "print('before')\\n"
    changed = "print('after')\\n"
    assert not version_matches(changed, sha256_text(original))


def test_project_file_lock_is_scoped_to_project_file(tmp_path):
    from pathlib import PurePosixPath

    first = project_file_lock(tmp_path, "project-a", PurePosixPath("src/main.py"))
    same_file = project_file_lock(tmp_path, "project-a", PurePosixPath("src/main.py"))
    other_file = project_file_lock(tmp_path, "project-a", PurePosixPath("src/other.py"))
    with first:
        with pytest.raises(Timeout):
            same_file.acquire()
        with other_file:
            pass


def test_project_file_lock_rejects_symlinked_lock_directory(tmp_path):
    from pathlib import PurePosixPath

    target = tmp_path / "target"
    target.mkdir()
    lock_dir = tmp_path / ".invest-locks"
    try:
        lock_dir.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable on this platform")
    with pytest.raises(OSError):
        project_file_lock(tmp_path, "project-a", PurePosixPath("src/main.py"))
