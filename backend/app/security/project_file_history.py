"""Content-addressed snapshots for safe project-file history and rollback."""
import hashlib
import os
from pathlib import Path, PurePosixPath
import tempfile
from uuid import UUID


MAX_VERSION_BYTES = 1_000_000


def _version_directory(workspace_root: str | Path, project_id: UUID | str, relative_path: PurePosixPath) -> Path:
    workspace = Path(workspace_root).resolve(strict=True)
    root = workspace / ".invest-versions"
    if root.is_symlink():
        raise OSError("Version storage must not be a symlink")
    root.mkdir(mode=0o700, parents=False, exist_ok=True)
    if root.is_symlink():
        raise OSError("Version storage must not be a symlink")
    project_dir = root / str(project_id)
    if project_dir.is_symlink():
        raise OSError("Project version storage must not be a symlink")
    project_dir.mkdir(mode=0o700, exist_ok=True)
    key = hashlib.sha256(relative_path.as_posix().encode("utf-8")).hexdigest()
    path_dir = project_dir / key
    if path_dir.is_symlink():
        raise OSError("File version storage must not be a symlink")
    path_dir.mkdir(mode=0o700, exist_ok=True)
    resolved = path_dir.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve(strict=True)) or not resolved.is_dir():
        raise OSError("Version storage is unavailable")
    try:
        os.chmod(resolved, 0o700)
    except OSError:
        pass
    return resolved


def save_project_file_version(
    workspace_root: str | Path,
    project_id: UUID | str,
    relative_path: PurePosixPath,
    content: str,
) -> str:
    """Persist an immutable UTF-8 snapshot and return its SHA-256."""
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_VERSION_BYTES:
        raise ValueError("Project file version exceeds the storage limit")
    digest = hashlib.sha256(encoded).hexdigest()
    directory = _version_directory(workspace_root, project_id, relative_path)
    target = directory / f"{digest}.snapshot"
    if target.is_symlink():
        raise OSError("Version snapshot must not be a symlink")
    if target.exists():
        if target.read_bytes() != encoded:
            raise OSError("Content-addressed version hash collision")
        return digest
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=directory, prefix=".snapshot-", delete=False) as temporary:
            temporary_name = temporary.name
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
        if target.exists() or target.is_symlink():
            if target.is_symlink() or target.read_bytes() != encoded:
                raise OSError("Version snapshot already exists with unexpected content")
            return digest
        os.replace(temporary_name, target)
        temporary_name = None
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return digest


def load_project_file_version(
    workspace_root: str | Path,
    project_id: UUID | str,
    relative_path: PurePosixPath,
    expected_sha256: str,
) -> str:
    """Load a snapshot only when its path and bytes match the requested digest."""
    if len(expected_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in expected_sha256):
        raise ValueError("Invalid version digest")
    directory = _version_directory(workspace_root, project_id, relative_path)
    target = directory / f"{expected_sha256}.snapshot"
    if target.is_symlink() or not target.is_file():
        raise FileNotFoundError("Project file version was not found")
    content = target.read_bytes()
    if len(content) > MAX_VERSION_BYTES or hashlib.sha256(content).hexdigest() != expected_sha256:
        raise OSError("Stored project file version failed integrity validation")
    return content.decode("utf-8")
