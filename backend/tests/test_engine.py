from pathlib import Path

from app.config import settings
from app.workflows.engine import execute_graph
from app.workflows.registry import registry
from app.workflows.schemas import WorkflowGraph


def test_workspace_source_runs_secrets_scanner_and_merges_findings(tmp_path, monkeypatch):
    project = tmp_path / "sample"
    project.mkdir()
    (project / "application.yml").write_text(
        'spring:\n  datasource:\n    password: "VeryStrongPasswordValue123"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))

    graph = WorkflowGraph(
        name="Secrets test",
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "scan", "type": "scan.secrets"},
            {"id": "merge", "type": "findings.merge"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
            {"id": "e3", "source": "scan", "target": "merge"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "completed"
    assert result["outputs"]["source"]["status"] == "ready"
    assert result["outputs"]["scan"]["summary"]["total"] == 1
    finding = result["outputs"]["merge"]["findings"][0]
    assert finding["category"] == "SECRET"
    assert finding["path"] == "application.yml"
    assert "VeryStrongPasswordValue123" not in str(result)


def test_workspace_source_rejects_path_traversal(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setattr(settings, "workspace_root", str(workspace))

    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "../outside"}},
            {"id": "scan", "type": "scan.secrets"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "failed"
    assert result["outputs"]["source"]["status"] == "failed"
    assert result["outputs"]["scan"]["status"] == "blocked"


def test_workspace_source_rejects_absolute_paths(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setattr(settings, "workspace_root", str(workspace))

    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": str(outside)}},
            {"id": "scan", "type": "scan.secrets"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "failed"
    assert result["outputs"]["source"]["status"] == "failed"


def test_git_source_is_passed_to_secrets_scanner(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    repository = workspace / "git-test"
    repository.mkdir(parents=True)
    (repository / "application.yml").write_text(
        'spring:\n  datasource:\n    password: "GitSourcePasswordValue123"',
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "workspace_root", str(workspace))
    monkeypatch.setattr(settings, "allowed_targets", "https://github.com/example/repo")
    monkeypatch.setattr(
        "app.workflows.engine.clone_allowed_repository",
        lambda **kwargs: {
            "path": "git-test",
            "source": "git",
            "repository": "https://github.com/example/repo",
            "ref": "main",
        },
    )

    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.git", "config": {"url": "https://github.com/example/repo", "ref": "main"}},
            {"id": "scan", "type": "scan.secrets"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "completed"
    assert result["outputs"]["source"]["status"] == "ready"
    assert result["outputs"]["scan"]["summary"]["total"] == 1


def test_sca_node_runs_against_workspace_source(tmp_path, monkeypatch):
    project = tmp_path / "sample"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        'dependencies { implementation("org.apache.commons:commons-text:1.9") }\\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))

    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "sca", "type": "scan.sca"},
            {"id": "merge", "type": "findings.merge"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "sca"},
            {"id": "e3", "source": "sca", "target": "merge"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "completed"
    assert result["outputs"]["sca"]["summary"]["total"] == 1
    assert result["outputs"]["merge"]["findings"][0]["advisory_id"] == "GHSA-599f-7c49-w659"



def test_sast_node_runs_against_workspace_source(tmp_path, monkeypatch):
    project = tmp_path / "sample"
    source = project / "src/main/kotlin/demo"
    source.mkdir(parents=True)
    (source / "LookupController.kt").write_text(
        """class LookupController {
    fun find(@RequestParam frameTag: String): List<String> =
        jdbc.queryForList("SELECT code FROM repair_ticket WHERE frame_tag = '$frameTag'", String::class.java)
}
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))
    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "sast", "type": "scan.sast"},
            {"id": "merge", "type": "findings.merge"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "sast"},
            {"id": "e3", "source": "sast", "target": "merge"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "completed"
    assert result["outputs"]["sast"]["summary"]["total"] == 1
    assert result["outputs"]["merge"]["findings"][0]["category"] == "SAST"



def test_engine_reports_node_timing_and_progress():
    graph = WorkflowGraph(
        name="Telemetry",
        nodes=[{"id": "trigger", "type": "trigger.manual"}],
        edges=[],
    )
    progress = []

    result = execute_graph(graph, registry, on_progress=progress.append)

    assert result["status"] == "completed"
    assert result["trace"][0]["node_id"] == "trigger"
    assert result["trace"][0]["duration_ms"] >= 0
    assert progress
    assert progress[0]["completed_nodes"] == 1
    assert progress[0]["total_nodes"] == 1
    assert progress[0]["status"] == "running"
