import json
from pathlib import Path

from app.workflows.registry import registry
from app.workflows.schemas import WorkflowGraph
from app.workflows.validator import validate_graph


def test_demo_workflow_is_valid_and_pins_training_repository():
    root = Path(__file__).resolve().parents[2]
    graph_data = json.loads((root / "examples" / "demo-workflow.json").read_text(encoding="utf-8"))
    graph = WorkflowGraph.model_validate(graph_data)

    validation = validate_graph(graph, registry)

    assert validation.valid, validation.model_dump()
    source = next(node for node in graph.nodes if node.type == "source.git")
    assert source.config["url"] == "https://github.com/TBagirov/training"
    assert source.config["ref"] == "fe1fcbe212669783480666b9b60147c8a8c6eef4"
    assert source.config["subdirectory"] == "training-project""
    assert {node.type for node in graph.nodes} >= {
        "trigger.manual", "source.git", "scan.secrets", "scan.sca", "scan.sast",
        "findings.merge", "ai.explain", "notify.webhook",
    }
