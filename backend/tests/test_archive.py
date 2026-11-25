from io import BytesIO
import stat
import zlib
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest

import app.sources.archive as archive_module
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



def test_cleans_partial_extraction_after_corrupt_entry(tmp_path, monkeypatch):
    archive = make_zip([
        ("first.txt", "written successfully"),
        ("second.txt", "this entry will fail"),
    ])
    original_open = archive_module.zipfile.ZipFile.open
    second_entry_attempted = False

    class BrokenReader:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def read(self, size=-1):
            raise zlib.error("simulated corrupt compressed data")

    def fail_second_entry(self, name, mode="r", pwd=None, *, force_zip64=False):
        nonlocal second_entry_attempted
        filename = name.filename if isinstance(name, ZipInfo) else name
        if filename == "second.txt":
            second_entry_attempted = True
            return BrokenReader()
        return original_open(self, name, mode, pwd, force_zip64=force_zip64)

    monkeypatch.setattr(archive_module.zipfile.ZipFile, "open", fail_second_entry)

    with pytest.raises(ArchiveValidationError, match="corrupt or unsupported"):
        extract_project_archive(archive, tmp_path)

    assert second_entry_attempted
    assert list(tmp_path.iterdir()) == []

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


def make_special_zip_entry(name, file_mode, payload="target"):
    stream = BytesIO()
    info = ZipInfo(name)
    info.create_system = 3
    info.external_attr = (file_mode | 0o777) << 16
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        archive.writestr(info, payload)
    stream.seek(0)
    return stream


def test_rejects_destination_parent_symlink_escape(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = workspace / "projects"

    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory symlinks are unavailable on this platform")

    archive = make_zip([("src/Main.kt", "fun main() = Unit")])

    with pytest.raises(ArchiveValidationError, match="escapes the workspace"):
        extract_project_archive(archive, workspace, "projects/project-demo")

    assert not (outside / "project-demo").exists()


def test_rejects_symlink_entries(tmp_path):
    archive = make_special_zip_entry("link", stat.S_IFLNK)

    with pytest.raises(ArchiveValidationError, match="Symbolic links"):
        extract_project_archive(archive, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_rejects_special_files(tmp_path):
    archive = make_special_zip_entry("pipe", stat.S_IFIFO)

    with pytest.raises(ArchiveValidationError, match="special filesystem"):
        extract_project_archive(archive, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_rejects_expanded_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(archive_module, "MAX_EXTRACTED_BYTES", 3)
    archive = make_zip([("large.txt", "four")])

    with pytest.raises(ArchiveValidationError, match="2 GiB limit"):
        extract_project_archive(archive, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_rejects_entry_count_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(archive_module, "MAX_FILES", 1)
    archive = make_zip([("one.txt", "1"), ("two.txt", "2")])

    with pytest.raises(ArchiveValidationError, match="20000 entries"):
        extract_project_archive(archive, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_rejects_excessive_compression_ratio(tmp_path, monkeypatch):
    monkeypatch.setattr(archive_module, "MAX_COMPRESSION_RATIO", 2)
    archive = make_zip([("repeated.txt", "A" * 1000)])

    with pytest.raises(ArchiveValidationError, match="compression ratio"):
        extract_project_archive(archive, tmp_path)

    assert list(tmp_path.iterdir()) == []
