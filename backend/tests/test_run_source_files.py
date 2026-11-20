from pathlib import Path

import pytest

from app.sources.run_files import RunSourceFileError, resolve_run_source_file


def _run(source_type="source.upload", source_name="upload-demo"):
    graph = {"nodes": [{"id": "src", "type": source_type}]}
    result = {"outputs": {"src": {"status": "ready", "path": source_name}}}
    return graph, result


def test_resolves_file_inside_run_source(tmp_path: Path):
    root = tmp_path / "upload-demo"
    root.mkdir()
    (root / "App.kt").write_text("class App {}\n", encoding="utf-8")
    graph, result = _run()
    assert resolve_run_source_file(tmp_path, graph, result, "App.kt") == root / "App.kt"


@pytest.mark.parametrize("path", ["../outside.txt", "/etc/passwd", "a/../../secret", "a\\..\\secret"])
def test_rejects_traversal_paths(tmp_path: Path, path: str):
    root = tmp_path / "upload-demo"
    root.mkdir()
    graph, result = _run()
    with pytest.raises(RunSourceFileError):
        resolve_run_source_file(tmp_path, graph, result, path)


def test_rejects_symlink_inside_source(tmp_path: Path):
    root = tmp_path / "upload-demo"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (root / "link.txt").symlink_to(outside)
    graph, result = _run()
    with pytest.raises(RunSourceFileError):
        resolve_run_source_file(tmp_path, graph, result, "link.txt")


def test_requires_source_artifact_from_this_run(tmp_path: Path):
    graph, result = _run()
    result["outputs"]["src"]["status"] = "failed"
    with pytest.raises(RunSourceFileError):
        resolve_run_source_file(tmp_path, graph, result, "App.kt")
