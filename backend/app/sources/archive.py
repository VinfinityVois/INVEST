from __future__ import annotations

import shutil
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_EXTRACTED_BYTES = 250 * 1024 * 1024
MAX_FILES = 5000
MAX_COMPRESSION_RATIO = 100


class ArchiveValidationError(ValueError):
    pass


def _safe_member_name(name: str) -> PurePosixPath:
    if "\x00" in name or "\\" in name:
        raise ArchiveValidationError("Archive contains an invalid path")
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ArchiveValidationError("Archive contains a path traversal entry")
    if path.parts[0].endswith(":"):
        raise ArchiveValidationError("Archive contains an absolute drive path")
    return path


def extract_project_archive(stream: BinaryIO, workspace_root: str | Path) -> dict:
    """Extract an untrusted ZIP into a fresh workspace directory without executing it."""
    root = Path(workspace_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    destination = root / f"upload-{uuid.uuid4().hex}"
    destination.mkdir(mode=0o700)

    try:
        stream.seek(0, 2)
        archive_size = stream.tell()
        stream.seek(0)
        if archive_size > MAX_ARCHIVE_BYTES:
            raise ArchiveValidationError("Archive exceeds the 50 MiB upload limit")

        try:
            archive = zipfile.ZipFile(stream)
        except (zipfile.BadZipFile, OSError) as exc:
            raise ArchiveValidationError("Uploaded file is not a valid ZIP archive") from exc

        with archive:
            entries = archive.infolist()
            if not entries or len(entries) > MAX_FILES:
                raise ArchiveValidationError("Archive must contain between 1 and 5000 entries")

            total_size = 0
            seen: set[str] = set()
            prepared = []
            for info in entries:
                relative = _safe_member_name(info.filename.rstrip("/"))
                normalized = relative.as_posix()
                if normalized in seen:
                    raise ArchiveValidationError("Archive contains duplicate paths")
                seen.add(normalized)

                unix_mode = (info.external_attr >> 16) & 0xFFFF
                file_type = unix_mode & 0o170000
                if file_type == 0o120000:
                    raise ArchiveValidationError("Symbolic links are not allowed in archives")
                if file_type not in (0, 0o040000, 0o100000):
                    raise ArchiveValidationError("Archive contains a special filesystem entry")
                if info.flag_bits & 0x1:
                    raise ArchiveValidationError("Encrypted ZIP entries are not supported")

                if info.is_dir():
                    prepared.append((info, relative, True))
                    continue

                total_size += info.file_size
                if total_size > MAX_EXTRACTED_BYTES:
                    raise ArchiveValidationError("Expanded archive exceeds the 250 MiB limit")
                if info.file_size and (info.compress_size == 0 or info.file_size / info.compress_size > MAX_COMPRESSION_RATIO):
                    raise ArchiveValidationError("Archive compression ratio is too high")
                prepared.append((info, relative, False))

            for info, relative, is_dir in prepared:
                target = destination.joinpath(*relative.parts)
                resolved_parent = target.parent.resolve()
                if not resolved_parent.is_relative_to(destination):
                    raise ArchiveValidationError("Archive entry escapes the upload directory")
                if is_dir:
                    target.mkdir(parents=True, exist_ok=True)
                    continue

                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(info, "r") as source, target.open("xb") as output:
                    while chunk := source.read(1024 * 1024):
                        written += len(chunk)
                        if written > info.file_size or written > MAX_EXTRACTED_BYTES:
                            raise ArchiveValidationError("ZIP entry expanded beyond its declared size")
                        output.write(chunk)
                if written != info.file_size:
                    raise ArchiveValidationError("ZIP entry size does not match its directory record")

        return {
            "path": destination.name,
            "files": sum(1 for _, _, is_dir in prepared if not is_dir),
            "expanded_bytes": total_size,
        }
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
