import pytest

from app.ai.workflow_generation import WorkflowGenerationError, normalize_generated_graph


def _valid_raw():
    return {
        "name": "Kotlin security review",
        "nodes": [
            {"id": "trigger", "type": "trigger.manual", "config": {}},
            {"id": "source", "type": "source.upload", "config": {"path": "/etc/passwd"}},
            {"id": "secrets", "type": "scan.secrets", "config": {}},
            {"id": "merge", "type": "findings.merge", "config": {}},
        ],
        "edges": [
            {"source": "trigger", "target": "source"},
            {"source": "source", "target": "secrets"},
            {"source": "secrets", "target": "merge"},
        ],
    }


def test_ai_generated_graph_is_normalized_and_validated():
    graph = normalize_generated_graph(_valid_raw(), "Build a Kotlin security workflow")
    assert graph.name == "Kotlin security review"
    assert [node.id for node in graph.nodes] == ["ai-1", "ai-2", "ai-3", "ai-4"]
    assert graph.nodes[1].config["path"] == ""
    assert graph.edges[0].source == "ai-1"
    assert graph.edges[0].target == "ai-2"


def test_ai_generated_graph_rejects_unknown_node_types():
    raw = _valid_raw()
    raw["nodes"][2]["type"] = "execute.shell"
    with pytest.raises(WorkflowGenerationError, match="Недопустимый тип блока"):
        normalize_generated_graph(raw, "Build a Kotlin security workflow")


def test_ai_generated_graph_rejects_unknown_config_keys():
    raw = _valid_raw()
    raw["nodes"][2]["config"] = {"api_key": "should-not-be-here"}
    with pytest.raises(WorkflowGenerationError, match="Неизвестные поля конфигурации"):
        normalize_generated_graph(raw, "Build a Kotlin security workflow")


def test_ai_generated_graph_rejects_incompatible_ports():
    raw = _valid_raw()
    raw["edges"][0] = {"source": "trigger", "target": "secrets"}
    with pytest.raises(WorkflowGenerationError, match="не прошёл проверку"):
        normalize_generated_graph(raw, "Build a Kotlin security workflow")


def test_ai_generated_graph_rejects_duplicate_ids_and_oversized_graphs():
    raw = _valid_raw()
    raw["nodes"][1]["id"] = "trigger"
    with pytest.raises(WorkflowGenerationError, match="повторяющиеся ID"):
        normalize_generated_graph(raw, "Build a Kotlin security workflow")
    raw = _valid_raw()
    raw["nodes"] = raw["nodes"][:1]
    with pytest.raises(WorkflowGenerationError, match="от 2 до 30"):
        normalize_generated_graph(raw, "Build a Kotlin security workflow")


def test_ai_generated_graph_blanks_external_destinations():
    raw = _valid_raw()
    raw["nodes"].append({"id": "explain", "type": "ai.explain", "config": {}})
    raw["nodes"].append({"id": "webhook", "type": "notify.webhook",
                         "config": {"url": "https://attacker.example/collect"}})
    raw["edges"].append({"source": "merge", "target": "explain"})
    raw["edges"].append({"source": "explain", "target": "webhook"})
    graph = normalize_generated_graph(raw, "Build a Kotlin security workflow")
    webhook = next(node for node in graph.nodes if node.type == "notify.webhook")
    assert webhook.config["url"] == ""


def test_ai_generated_graph_rejects_disconnected_nodes():
    raw = _valid_raw()
    raw["nodes"].append({"id": "orphan", "type": "scan.sast", "config": {}})
    with pytest.raises(WorkflowGenerationError, match="соединены с триггером"):
        normalize_generated_graph(raw, "Build a Kotlin security workflow")


def test_ai_generated_graph_fills_required_webhook_url_with_empty_value():
    raw = _valid_raw()
    raw["nodes"].append({"id": "explain", "type": "ai.explain", "config": {}})
    raw["nodes"].append({"id": "webhook", "type": "notify.webhook", "config": {}})
    raw["edges"].append({"source": "merge", "target": "explain"})
    raw["edges"].append({"source": "explain", "target": "webhook"})
    graph = normalize_generated_graph(raw, "Build a Kotlin security workflow")
    webhook = next(node for node in graph.nodes if node.type == "notify.webhook")
    assert webhook.config == {"url": ""}
