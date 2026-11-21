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
    try:
        (root / "link.txt").symlink_to(outside)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Creating symlinks requires Windows Developer Mode or elevated privileges")
        raise
    graph, result = _run()
    with pytest.raises(RunSourceFileError):
        resolve_run_source_file(tmp_path, graph, result, "link.txt")


def test_requires_source_artifact_from_this_run(tmp_path: Path):
    graph, result = _run()
    result["outputs"]["src"]["status"] = "failed"
    with pytest.raises(RunSourceFileError):
        resolve_run_source_file(tmp_path, graph, result, "App.kt")



def test_resolves_source_file_from_saved_project_workspace(tmp_path: Path):
    root = tmp_path / "projects" / "project-demo"
    root.mkdir(parents=True)
    (root / "README.md").write_text("# Project", encoding="utf-8")
    graph, result = _run(source_name="projects/project-demo")
    resolved = resolve_run_source_file(tmp_path, graph, result, "README.md")
    assert resolved == root / "README.md"


def test_rejects_project_artifact_outside_project_namespace(tmp_path: Path):
    graph, result = _run(source_name="projects/../outside")
    with pytest.raises(RunSourceFileError):
        resolve_run_source_file(tmp_path, graph, result, "secret.txt")


def test_resolves_file_relative_to_wrapped_project_root(tmp_path: Path):
    artifact = tmp_path / "projects" / "project-demo"
    project = artifact / "training-project"
    (project / "src" / "main" / "kotlin").mkdir(parents=True)
    expected = project / "src" / "main" / "kotlin" / "DepotStatusClient.kt"
    expected.write_text("class DepotStatusClient", encoding="utf-8")
    graph, result = _run(source_name="projects/project-demo")
    resolved = resolve_run_source_file(tmp_path, graph, result, "src/main/kotlin/DepotStatusClient.kt")
    assert resolved == expected


def test_resolves_file_using_explicit_project_subdirectory(tmp_path: Path):
    artifact = tmp_path / "projects" / "project-demo"
    project = artifact / "training-project"
    (project / "src").mkdir(parents=True)
    expected = project / "src" / "Main.kt"
    expected.write_text("class Main", encoding="utf-8")
    graph, result = _run(source_name="projects/project-demo")
    result["outputs"]["src"]["project_subdirectory"] = "training-project"
    resolved = resolve_run_source_file(tmp_path, graph, result, "src/Main.kt")
    assert resolved == expected
