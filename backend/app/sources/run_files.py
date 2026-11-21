"""Resolve source files strictly within the workspace artifact owned by one run."""
from pathlib import Path, PurePosixPath

from app.sources.project_root import detect_project_root


class RunSourceFileError(ValueError):
    pass


def resolve_run_source_file(
    workspace_root: str | Path,
    graph_snapshot: dict,
    result: dict,
    relative_file: str,
) -> Path:
    if not isinstance(relative_file, str) or not relative_file or "\x00" in relative_file or "\\" in relative_file:
        raise RunSourceFileError("Invalid source path")
    relative = PurePosixPath(relative_file)
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise RunSourceFileError("Invalid source path")

    nodes = graph_snapshot.get("nodes", []) if isinstance(graph_snapshot, dict) else []
    outputs = result.get("outputs", {}) if isinstance(result, dict) else {}
    candidates = []
    for node in nodes:
        if not isinstance(node, dict) or node.get("type") not in {"source.upload", "source.git"}:
            continue
        output = outputs.get(node.get("id"), {})
        if not isinstance(output, dict) or output.get("status") not in {"ready"}:
            continue
        source_name = output.get("path")
        if isinstance(source_name, str):
            subdirectory = output.get("project_subdirectory") or output.get("subdirectory")
            candidates.append((source_name, subdirectory))

    if len(candidates) != 1:
        raise RunSourceFileError("Run source artifact is ambiguous or unavailable")

    source_path, project_subdirectory = candidates[0]
    source_name = PurePosixPath(source_path)
    if source_name.is_absolute() or any(part in {"", ".", ".."} for part in source_name.parts):
        raise RunSourceFileError("Invalid run source artifact")
    if len(source_name.parts) == 1 and source_name.parts[0].startswith(("upload-", "git-")):
        artifact_parts = source_name.parts
    elif (
        len(source_name.parts) == 2
        and source_name.parts[0] == "projects"
        and source_name.parts[1].startswith("project-")
    ):
        artifact_parts = source_name.parts
    else:
        raise RunSourceFileError("Unknown run source artifact")

    workspace = Path(workspace_root).resolve()
    source_root = workspace.joinpath(*artifact_parts)
    if source_root.is_symlink():
        raise RunSourceFileError("Symlink source artifacts are not allowed")
    try:
        source_root = source_root.resolve(strict=True)
    except OSError as exc:
        raise RunSourceFileError("Run source artifact is unavailable") from exc
    if not source_root.is_relative_to(workspace) or not source_root.is_dir():
        raise RunSourceFileError("Run source artifact is outside the workspace")

    candidate = source_root
    for part in relative.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise RunSourceFileError("Symlinks are not allowed in source files")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise RunSourceFileError("Source file is unavailable") from exc
    if not resolved.is_relative_to(project_root) or not resolved.is_file():
        raise RunSourceFileError("Source file is outside the run workspace")
    return resolved
