from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from app.sources.archive import MAX_ARCHIVE_BYTES, ArchiveValidationError, extract_project_archive


def make_zip(entries):
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        for name, payload in entries:
            archive.writestr(name, payload)
    stream.seek(0)
    return stream


def test_extracts_project_without_running_files(tmp_path):
    archive = make_zip([
        ("repair-desk/src/Main.kt", "fun main() = Unit"),
        ("repair-desk/build.gradle.kts", "plugins {}"),
    ])

    result = extract_project_archive(archive, tmp_path)

    assert result["files"] == 2
    assert (tmp_path / result["path"] / "repair-desk/src/Main.kt").read_text() == "fun main() = Unit"
    assert (tmp_path / result["path"] / "repair-desk/build.gradle.kts").exists()


@pytest.mark.parametrize("name", ["../escape.txt", "/absolute.txt", "C:/drive.txt", "folder\\..\\escape.txt"])
def test_rejects_unsafe_archive_paths(tmp_path, name):
    archive = make_zip([(name, "nope")])

    with pytest.raises(ArchiveValidationError):
        extract_project_archive(archive, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_accepts_windows_style_separators_after_safe_normalization(tmp_path):
    archive = make_zip([(r"project\\src\\Main.kt", "fun main() = Unit")])

    result = extract_project_archive(archive, tmp_path)

    assert (tmp_path / result["path"] / "project" / "src" / "Main.kt").read_text() == "fun main() = Unit"


def test_rejects_non_zip_and_cleans_workspace(tmp_path):
    with pytest.raises(ArchiveValidationError):
        extract_project_archive(BytesIO(b"not a zip"), tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_rejects_duplicate_paths(tmp_path):
    archive = make_zip([("src/A.kt", "one"), ("src/A.kt", "two")])

    with pytest.raises(ArchiveValidationError):
        extract_project_archive(archive, tmp_path)

    assert list(tmp_path.iterdir()) == []



def test_archive_upload_limit_is_300_mib():
    assert MAX_ARCHIVE_BYTES == 300 * 1024 * 1024


def test_extracts_into_nested_project_library_path(tmp_path):
    archive = make_zip([("src/Main.kt", "fun main() = Unit")])
    result = extract_project_archive(archive, tmp_path, "projects/project-demo")

    assert result["path"] == "projects/project-demo"
    assert (tmp_path / "projects" / "project-demo" / "src" / "Main.kt").exists()


def test_rejects_existing_extraction_destination(tmp_path):
    destination = tmp_path / "projects" / "project-existing"
    destination.mkdir(parents=True)
    archive = make_zip([("src/Main.kt", "fun main() = Unit")])

    with pytest.raises(ArchiveValidationError):
        extract_project_archive(archive, tmp_path, "projects/project-existing")
