"""Content-version helpers and cross-process locks for safe project file updates."""
import hashlib
import os
from pathlib import Path, PurePosixPath

from filelock import FileLock


def sha256_text(content: str) -> str:
    """Return the SHA-256 digest of a UTF-8 text snapshot."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def version_matches(content: str, expected_sha256: str) -> bool:
    """Compare a client snapshot token with the current file contents."""
    return sha256_text(content) == expected_sha256


def project_file_lock(workspace_root: str | Path, project_id, relative_path: PurePosixPath) -> FileLock:
    """Return a non-blocking OS-backed lock scoped to one project file.

    Lock files live outside individual project trees but on the workspace
    filesystem, so API processes sharing the workspace coordinate with one
    another. The OS releases the advisory lock when a process exits.
    """
    workspace = Path(workspace_root).resolve(strict=True)
    lock_dir = workspace / ".invest-locks"
    if lock_dir.is_symlink():
        raise OSError("Project lock directory must not be a symlink")
    lock_dir.mkdir(mode=0o700, parents=False, exist_ok=True)
    if lock_dir.is_symlink():
        raise OSError("Project lock directory must not be a symlink")
    resolved_lock_dir = lock_dir.resolve(strict=True)
    if not resolved_lock_dir.is_relative_to(workspace) or not resolved_lock_dir.is_dir():
        raise OSError("Project lock directory is unavailable")
    try:
        os.chmod(resolved_lock_dir, 0o700)
    except OSError:
        # Windows ACLs govern access there; chmod may be unsupported.
        pass
    key = hashlib.sha256(
        f"{project_id}:{relative_path.as_posix()}".encode("utf-8")
    ).hexdigest()
    return FileLock(str(resolved_lock_dir / f"{key}.lock"), timeout=0)
