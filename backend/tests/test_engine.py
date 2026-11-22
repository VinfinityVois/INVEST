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



def test_downstream_is_blocked_when_upstream_source_is_unconfigured():
    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {}},
            {"id": "scan", "type": "scan.secrets"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["outputs"]["source"]["status"] == "configuration_required"
    assert result["outputs"]["scan"]["status"] == "blocked"
    scan_trace = next(item for item in result["trace"] if item["node_id"] == "scan")
    assert scan_trace["diagnostic_level"] == "blocked"
    assert scan_trace["reason_code"] == "UPSTREAM_SOURCE_UNAVAILABLE"


def test_unconfigured_source_is_reported_as_partial_with_actionable_status():
    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {}},
            {"id": "scan", "type": "scan.secrets"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "partial"
    assert result["outputs"]["source"]["status"] == "configuration_required"
    assert result["outputs"]["scan"]["status"] == "blocked"


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
    assert progress[0]["total_findings"] == 0
    assert progress[0]["severity"] == {}



def test_ai_explanation_result_is_exposed_in_node_trace_and_progress(tmp_path, monkeypatch):
    import app.workflows.engine as engine

    project = tmp_path / "sample"
    project.mkdir()
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))
    monkeypatch.setattr(engine, "explain_findings", lambda findings, config: {
        "status": "completed",
        "findings": findings,
        "explanations": [{
            "fingerprint": "fp-1",
            "root_cause": "Небезопасная конкатенация SQL.",
            "impact": "Возможна SQL-инъекция.",
            "recommendation": "Используйте параметры запроса.",
            "confidence": 0.9,
            "evidence_limits": "Проверен только локальный контекст.",
        }],
        "explained_count": 1,
    })
    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "scan", "type": "scan.secrets"},
            {"id": "merge", "type": "findings.merge"},
            {"id": "ai", "type": "ai.explain"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
            {"id": "e3", "source": "scan", "target": "merge"},
            {"id": "e4", "source": "merge", "target": "ai"},
        ],
    )
    progress = []

    result = execute_graph(graph, registry, on_progress=progress.append)

    assert result["trace"][-1]["explained_count"] == 1
    assert progress[-1]["node_results"]["ai"]["explained_count"] == 1
    assert progress[-1]["node_results"]["ai"]["explanations"][0]["root_cause"] == "Небезопасная конкатенация SQL."


def test_ci_gate_blocks_workflow_on_critical_findings(tmp_path, monkeypatch):
    from app.config import settings
    import app.workflows.engine as engine

    project = tmp_path / "sample"
    project.mkdir()
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))
    monkeypatch.setattr(engine, "scan_directory", lambda _path, **_kwargs: [{
        "fingerprint": "critical-1",
        "rule_id": "TEST_CRITICAL",
        "severity": "CRITICAL",
        "path": "src/main.kt",
        "line": 10,
        "message": "Synthetic critical finding",
    }])
    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "scan", "type": "scan.secrets"},
            {"id": "merge", "type": "findings.merge"},
            {"id": "gate", "type": "ci.gate"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
            {"id": "e3", "source": "scan", "target": "merge"},
            {"id": "e4", "source": "merge", "target": "gate"},
        ],
    )

    progress = []
    result = execute_graph(graph, registry, on_progress=progress.append)

    assert result["status"] == "failed"
    assert result["security_gate"]["decision"] == "BLOCK"
    assert result["outputs"]["gate"]["status"] == "blocked"
    assert result["outputs"]["gate"]["counts"]["CRITICAL"] == 1
    assert progress[-1]["node_results"]["scan"]["severity"]["CRITICAL"] == 1
    assert progress[-1]["node_results"]["merge"]["severity"]["CRITICAL"] == 1


def test_engine_trace_contains_actionable_diagnostics_for_blocked_and_unconfigured_nodes():
    graph = WorkflowGraph(
        name="Diagnostics",
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {}},
            {"id": "scan", "type": "scan.secrets"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
        ],
    )

    result = execute_graph(graph, registry)
    trace = {item["node_id"]: item for item in result["trace"]}

    assert trace["source"]["diagnostic_level"] == "warning"
    assert trace["source"]["reason_code"] == "NODE_CONFIGURATION_REQUIRED"
    assert trace["source"]["reason"] == result["outputs"]["source"]["message"]
    assert trace["scan"]["diagnostic_level"] == "blocked"
    assert trace["scan"]["reason_code"] == "UPSTREAM_SOURCE_UNAVAILABLE"
    assert trace["scan"]["reason"] == result["outputs"]["scan"]["message"]



def test_engine_stops_between_nodes_when_cancellation_is_requested():
    graph = WorkflowGraph(
        name="Cooperative cancellation",
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {}},
            {"id": "scan", "type": "scan.secrets"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
        ],
    )
    checks = {"count": 0}

    def should_cancel():
        checks["count"] += 1
        return checks["count"] > 1

    result = execute_graph(graph, registry, should_cancel=should_cancel)

    assert result["status"] == "cancelled"
    assert [item["node_id"] for item in result["trace"]] == ["trigger"]
    assert "source" not in result["outputs"]


def test_engine_executes_only_selected_node_and_its_upstream_dependencies(monkeypatch):
    graph = WorkflowGraph(
        name="Selective",
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {}},
            {"id": "secrets", "type": "scan.secrets"},
            {"id": "sca", "type": "scan.sca"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "secrets"},
            {"id": "e3", "source": "source", "target": "sca"},
        ],
    )
    result = execute_graph(graph, registry, target_node_ids=["secrets"])
    assert result["status"] == "partial"
    assert result["order"] == ["trigger", "source", "secrets"]
    assert set(result["outputs"]) == {"trigger", "source", "secrets"}
    assert result["execution_scope"]["requested_node_ids"] == ["secrets"]


def test_scanner_cache_reuses_only_matching_source_and_force_full_scan_bypasses_it(tmp_path, monkeypatch):
    import app.workflows.engine as engine

    project = tmp_path / "sample"
    project.mkdir()
    source_file = project / "app.kt"
    source_file.write_text("class App {}", encoding="utf-8")
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))
    calls = {"count": 0}

    def fake_scan(_root, **_kwargs):
        calls["count"] += 1
        return []

    monkeypatch.setattr(engine, "scan_directory", fake_scan)
    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "scan", "type": "scan.secrets"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
        ],
    )

    first = execute_graph(graph, registry)
    assert calls["count"] == 1
    assert first["cache_summary"]["misses"] == 1
    assert first["cache_entries"]

    second = execute_graph(graph, registry, cache_entries=first["cache_entries"], cache_metadata=first["cache_metadata"])
    assert calls["count"] == 1
    assert second["trace"][-1]["cached"] is True
    assert second["trace"][-1]["cache_age_seconds"] >= 0
    assert second["cache_metadata"]["scan"]["cached_at"]
    assert second["cache_summary"]["hits"] == 1

    source_file.write_text("class App { fun changed() {} }", encoding="utf-8")
    changed = execute_graph(graph, registry, cache_entries=first["cache_entries"], cache_metadata=first["cache_metadata"])
    assert calls["count"] == 2
    assert changed["trace"][-1]["cached"] is False

    forced = execute_graph(graph, registry, cache_entries=first["cache_entries"], force_full_scan=True)
    assert calls["count"] == 3
    assert forced["cache_summary"]["force_full_scan"] is True
    assert forced["cache_summary"]["hits"] == 0

    reset_one = execute_graph(graph, registry, cache_entries=first["cache_entries"], force_node_ids=["scan"])
    assert calls["count"] == 4
    assert reset_one["trace"][-1]["cached"] is False
    assert reset_one["trace"][-1]["cache_bypass_reason"] == "Кэш блока сброшен пользователем"


def test_scanner_cache_expires_after_ttl_and_rescans(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    import app.workflows.engine as engine

    project = tmp_path / "sample"
    project.mkdir()
    (project / "app.kt").write_text("class App {}", encoding="utf-8")
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))
    calls = {"count": 0}
    monkeypatch.setattr(engine, "scan_directory", lambda _root, **_kwargs: calls.__setitem__("count", calls["count"] + 1) or [])
    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "scan", "type": "scan.secrets"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
        ],
    )
    first = execute_graph(graph, registry)
    expired_metadata = {
        "scan": {
            **first["cache_metadata"]["scan"],
            "cached_at": (datetime.now(timezone.utc) - timedelta(seconds=engine.CACHE_TTL_SECONDS + 5)).isoformat(),
        }
    }
    expired = execute_graph(graph, registry, cache_entries=first["cache_entries"], cache_metadata=expired_metadata)
    assert calls["count"] == 2
    assert expired["trace"][-1]["cached"] is False
    assert expired["trace"][-1]["cache_bypass_reason"] == "Срок действия кэша истёк"
    assert expired["cache_metadata"]["scan"]["cached_at"] != expired_metadata["scan"]["cached_at"]


def test_workflow_scans_gates_and_delivers_ai_report_to_webhook(tmp_path, monkeypatch):
    import app.workflows.engine as engine

    project = tmp_path / "sample"
    project.mkdir()
    (project / "App.kt").write_text("class App {}", encoding="utf-8")
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))
    monkeypatch.setattr(engine, "scan_directory", lambda *_args, **_kwargs: [{
        "fingerprint": "finding-1", "rule_id": "demo.secret", "severity": "CRITICAL",
        "path": "App.kt", "line": 1, "message": "Synthetic critical finding",
    }])
    monkeypatch.setattr(engine, "explain_findings", lambda findings, _config: {
        "status": "completed", "findings": findings,
        "explanations": [{"fingerprint": "finding-1", "root_cause": "Example cause",
                          "impact": "Example impact", "recommendation": "Example fix"}],
        "explained_count": 1,
    })
    delivered = {}
    monkeypatch.setattr(engine, "deliver_webhook", lambda url, payload, **_kwargs: delivered.update(
        url=url, payload=payload
    ) or {"http_status": 200, "delivered": True})

    graph = WorkflowGraph(
        name="Security scan, gate and notification",
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "scan", "type": "scan.secrets"},
            {"id": "merge", "type": "findings.merge"},
            {"id": "gate", "type": "ci.gate"},
            {"id": "ai", "type": "ai.explain"},
            {"id": "notify", "type": "notify.webhook", "config": {"url": "https://webhook.site/demo-id"}},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
            {"id": "e3", "source": "scan", "target": "merge"},
            {"id": "e4", "source": "merge", "target": "gate"},
            {"id": "e5", "source": "scan", "target": "ai"},
            {"id": "e6", "source": "ai", "target": "notify"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "failed"
    assert result["security_gate"]["decision"] == "BLOCK"
    assert result["outputs"]["gate"]["status"] == "blocked"
    assert delivered["url"] == "https://webhook.site/demo-id"
    assert delivered["payload"]["summary"]["total_findings"] == 1
    assert delivered["payload"]["ai_summary"]
    assert result["outputs"]["notify"]["delivered"] is True



def test_schedule_trigger_executes_as_workflow_event():
    graph = WorkflowGraph(
        nodes=[{"id": "schedule", "type": "trigger.schedule", "config": {"cron": "*/5 * * * *", "timezone": "UTC"}}],
        edges=[],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "completed"
    assert result["outputs"]["schedule"]["status"] == "completed"



def test_git_source_scans_only_safe_configured_subdirectory(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    repository = workspace / "git-test"
    target = repository / "training-project"
    target.mkdir(parents=True)
    (target / "application.yml").write_text(
        'spring:\n  datasource:\n    password: "TrainingProjectSecretValue123"\n',
        encoding="utf-8",
    )
    (repository / "outside.yml").write_text(
        'spring:\n  datasource:\n    password: "OutsideProjectSecretValue123"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "workspace_root", str(workspace))
    monkeypatch.setattr(settings, "allowed_targets", "https://github.com/example/training")
    monkeypatch.setattr(
        "app.workflows.engine.clone_allowed_repository",
        lambda **kwargs: {
            "path": "git-test",
            "source": "git",
            "repository": "https://github.com/example/training",
            "ref": "fe1fcbe212669783480666b9b60147c8a8c6eef4",
        },
    )

    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.git", "config": {
                "url": "https://github.com/example/training",
                "ref": "fe1fcbe212669783480666b9b60147c8a8c6eef4",
                "subdirectory": "training-project",
            }},
            {"id": "scan", "type": "scan.secrets"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "completed"
    findings = result["outputs"]["scan"]["findings"]
    assert any(item["path"] == "application.yml" for item in findings)
    assert all("outside.yml" not in item["path"] for item in findings)


def test_git_source_rejects_parent_traversal_subdirectory(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    (workspace / "git-test").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setattr(settings, "workspace_root", str(workspace))
    monkeypatch.setattr(settings, "allowed_targets", "https://github.com/example/training")
    monkeypatch.setattr(
        "app.workflows.engine.clone_allowed_repository",
        lambda **kwargs: {"path": "git-test", "source": "git", "repository": "https://github.com/example/training", "ref": None},
    )

    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.git", "config": {
                "url": "https://github.com/example/training",
                "subdirectory": "../outside",
            }},
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



def test_logic_compare_routes_matching_and_nonmatching_findings(tmp_path, monkeypatch):
    project = tmp_path / "sample"
    project.mkdir()
    (project / "high.txt").write_text("high", encoding="utf-8")
    (project / "low.txt").write_text("low", encoding="utf-8")
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))
    monkeypatch.setattr(
        "app.workflows.engine.scan_directory",
        lambda *_args, **_kwargs: [
            {"fingerprint": "high", "rule_id": "TEST_HIGH", "severity": "HIGH", "path": "high.txt", "line": 1},
            {"fingerprint": "low", "rule_id": "TEST_LOW", "severity": "LOW", "path": "low.txt", "line": 1},
        ],
    )

    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "scan", "type": "scan.secrets"},
            {"id": "compare", "type": "logic.compare", "config": {
                "field": "severity", "operator": "equals", "value": "HIGH",
            }},
            {"id": "true", "type": "findings.merge"},
            {"id": "false", "type": "findings.merge"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
            {"id": "e3", "source": "scan", "target": "compare"},
            {"id": "e4", "source": "compare", "source_handle": "true", "target": "true"},
            {"id": "e5", "source": "compare", "source_handle": "false", "target": "false"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "completed"
    assert [item["fingerprint"] for item in result["outputs"]["true"]["findings"]] == ["high"]
    assert [item["fingerprint"] for item in result["outputs"]["false"]["findings"]] == ["low"]
    assert result["outputs"]["compare"]["summary"] == {"total": 2, "matched": 1, "unmatched": 1}


def test_logic_compare_partitions_findings_and_routes_true_false_handles(tmp_path, monkeypatch):
    import app.workflows.engine as engine

    project = tmp_path / "sample"
    project.mkdir()
    (project / "App.kt").write_text("class App {}", encoding="utf-8")
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))
    monkeypatch.setattr(engine, "scan_directory", lambda *_args, **_kwargs: [
        {"fingerprint": "high", "rule_id": "demo.high", "severity": "HIGH", "path": "App.kt"},
        {"fingerprint": "low", "rule_id": "demo.low", "severity": "LOW", "path": "App.kt"},
    ])

    graph = WorkflowGraph(
        name="Compare findings",
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "scan", "type": "scan.secrets"},
            {"id": "compare", "type": "logic.compare", "config": {
                "field": "severity", "operator": "greater_or_equal", "value": "HIGH"
            }},
            {"id": "true-output", "type": "findings.merge"},
            {"id": "false-output", "type": "findings.merge"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
            {"id": "e3", "source": "scan", "target": "compare"},
            {"id": "e4", "source": "compare", "source_handle": "true", "target": "true-output"},
            {"id": "e5", "source": "compare", "source_handle": "false", "target": "false-output"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["outputs"]["compare"]["summary"] == {"total": 2, "matched": 1, "unmatched": 1}
    assert [item["fingerprint"] for item in result["outputs"]["true-output"]["findings"]] == ["high"]
    assert [item["fingerprint"] for item in result["outputs"]["false-output"]["findings"]] == ["low"]


def test_logic_compare_count_operator_uses_total_finding_count(tmp_path, monkeypatch):
    import app.workflows.engine as engine

    project = tmp_path / "sample"
    project.mkdir()
    (project / "App.kt").write_text("class App {}", encoding="utf-8")
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))
    monkeypatch.setattr(engine, "scan_directory", lambda *_args, **_kwargs: [
        {"fingerprint": "one", "severity": "HIGH"},
        {"fingerprint": "two", "severity": "LOW"},
    ])

    graph = WorkflowGraph(
        name="Compare finding count",
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "scan", "type": "scan.secrets"},
            {"id": "compare", "type": "logic.compare", "config": {
                "field": "count", "operator": "greater_than", "value": "1"
            }},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
            {"id": "e3", "source": "scan", "target": "compare"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["outputs"]["compare"]["branch"] == "true"
    assert len(result["outputs"]["compare"]["matched_findings"]) == 2
    assert result["outputs"]["compare"]["unmatched_findings"] == []



def test_scanner_config_filters_test_paths_and_low_confidence_findings():
    from app.workflows.engine import _filter_scanner_findings

    findings = [
        {"path": "src/main/App.kt", "confidence": 0.9},
        {"path": "src/test/AppTest.kt", "confidence": 0.99},
        {"path": "src/main/Weak.kt", "confidence": 0.2},
    ]

    filtered = _filter_scanner_findings(
        findings, {"include_tests": False, "min_confidence": 0.4}, "sast"
    )

    assert filtered == [findings[0]]


def test_scanner_config_can_include_tests_and_zero_confidence_threshold():
    from app.workflows.engine import _filter_scanner_findings

    findings = [
        {"path": "src/main/App.kt", "confidence": 0.1},
        {"path": "src/test/AppTest.kt", "confidence": 0.2},
    ]

    filtered = _filter_scanner_findings(
        findings, {"include_tests": True, "min_confidence": 0}, "secrets"
    )

    assert filtered == findings


def test_sast_rule_pack_filters_findings_to_selected_rule_ids():
    from app.workflows.engine import _filter_scanner_findings

    findings = [
        {"rule_id": "kotlin.jdbc.sql-injection", "severity": "LOW", "confidence": 0.96},
        {"rule_id": "kotlin.spring.idor.unscoped-object-read", "severity": "LOW", "confidence": 0.84},
    ]
    filtered = _filter_scanner_findings(findings, {"rule_packs": ["sast-injection"]}, "sast")
    assert [item["rule_id"] for item in filtered] == ["kotlin.jdbc.sql-injection"]
    assert filtered[0]["severity"] == "HIGH"
    assert filtered[0]["cwe"] == ["CWE-89"]



def test_ai_provider_failure_keeps_scanner_results_and_marks_run_partial(tmp_path, monkeypatch):
    import app.workflows.engine as engine

    project = tmp_path / "sample"
    project.mkdir()
    (project / "application.yml").write_text("spring: {}\n", encoding="utf-8")
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))
    monkeypatch.setattr(engine, "scan_directory", lambda *_args, **_kwargs: [
        {"fingerprint": "finding-1", "rule_id": "TEST_SECRET", "severity": "HIGH", "path": "application.yml", "line": 1}
    ])
    monkeypatch.setattr(engine, "explain_findings", lambda findings, _config: {
        "status": "failed",
        "message": "AI provider timeout",
        "findings": findings,
        "explanations": [],
        "analyzed_count": len(findings),
        "explained_count": 0,
    })

    graph = WorkflowGraph(
        name="AI provider outage",
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "scan", "type": "scan.secrets"},
            {"id": "ai", "type": "ai.explain"},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
            {"id": "e3", "source": "scan", "target": "ai"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "partial"
    assert result["outputs"]["scan"]["summary"]["total"] == 1
    assert result["outputs"]["ai"]["status"] == "failed"
    assert result["outputs"]["ai"]["findings"][0]["fingerprint"] == "finding-1"
    assert result["trace"][-1]["diagnostic_level"] == "error"



def test_logic_regex_node_splits_findings_by_pattern(tmp_path, monkeypatch):
    import app.workflows.engine as engine

    project = tmp_path / "sample"
    project.mkdir()
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))
    monkeypatch.setattr(engine, "scan_directory", lambda _path, **_kwargs: [
        {"fingerprint": "sql-1", "rule_id": "SQL_INJECTION", "severity": "HIGH", "message": "Possible SQL injection"},
        {"fingerprint": "secret-1", "rule_id": "SECRET", "severity": "MEDIUM", "message": "Hardcoded credential"},
    ])
    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "scan", "type": "scan.secrets"},
            {"id": "regex", "type": "logic.regex", "config": {"field": "message", "pattern": r"(?i)sql\s+injection"}},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
            {"id": "e3", "source": "scan", "target": "regex"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "completed"
    assert result["outputs"]["regex"]["summary"] == {"total": 2, "matched": 1, "unmatched": 1}
    assert [item["fingerprint"] for item in result["outputs"]["regex"]["matched_findings"]] == ["sql-1"]
    assert [item["fingerprint"] for item in result["outputs"]["regex"]["unmatched_findings"]] == ["secret-1"]


def test_logic_regex_node_rejects_invalid_pattern_without_crashing(tmp_path, monkeypatch):
    import app.workflows.engine as engine

    project = tmp_path / "sample"
    project.mkdir()
    monkeypatch.setattr(settings, "workspace_root", str(tmp_path))
    monkeypatch.setattr(engine, "scan_directory", lambda _path, **_kwargs: [
        {"fingerprint": "one", "message": "finding"}
    ])
    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.upload", "config": {"path": "sample"}},
            {"id": "scan", "type": "scan.secrets"},
            {"id": "regex", "type": "logic.regex", "config": {"field": "message", "pattern": "("}},
        ],
        edges=[
            {"id": "e1", "source": "trigger", "target": "source"},
            {"id": "e2", "source": "source", "target": "scan"},
            {"id": "e3", "source": "scan", "target": "regex"},
        ],
    )

    result = execute_graph(graph, registry)

    assert result["status"] == "failed"
    assert result["outputs"]["regex"]["status"] == "failed"
    assert result["outputs"]["regex"]["reason_code"] == "INVALID_REGEX"
