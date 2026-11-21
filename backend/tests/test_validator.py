from app.workflows.registry import registry
from app.workflows.schemas import WorkflowGraph
from app.workflows.validator import validate_graph

def test_manual_source_to_secrets_is_valid():
    graph=WorkflowGraph(
        nodes=[
            {"id":"t","type":"trigger.manual"},
            {"id":"src","type":"source.git"},
            {"id":"s","type":"scan.secrets"},
        ],
        edges=[
            {"id":"e1","source":"t","target":"src"},
            {"id":"e2","source":"src","target":"s"},
        ],
    )
    assert validate_graph(graph,registry).valid

def test_unknown_node_rejected():
    graph=WorkflowGraph(nodes=[{"id":"x","type":"fake.node"}],edges=[])
    result=validate_graph(graph,registry)
    assert not result.valid and any(x.code=="unknown_node_type" for x in result.issues)

def test_cycles_rejected():
    graph=WorkflowGraph(
        nodes=[{"id":"t","type":"trigger.manual"},{"id":"src","type":"source.git"}],
        edges=[{"id":"a","source":"t","target":"src"},{"id":"b","source":"src","target":"t"}],
    )
    result=validate_graph(graph,registry)
    assert not result.valid and any(x.code=="cycle_detected" for x in result.issues)


from app.workflows.engine import resolve_execution_scope


def test_selected_node_scope_includes_all_upstream_dependencies_only():
    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.git"},
            {"id": "secrets", "type": "scan.secrets"},
            {"id": "sca", "type": "scan.sca"},
            {"id": "merge", "type": "findings.merge"},
            {"id": "gate", "type": "ci.gate"},
        ],
        edges=[
            {"id": "a", "source": "trigger", "target": "source"},
            {"id": "b", "source": "source", "target": "secrets"},
            {"id": "c", "source": "source", "target": "sca"},
            {"id": "d", "source": "secrets", "target": "merge"},
            {"id": "e", "source": "sca", "target": "merge"},
            {"id": "f", "source": "merge", "target": "gate"},
        ],
    )
    assert resolve_execution_scope(graph, ["secrets"]) == ["trigger", "source", "secrets"]
    assert resolve_execution_scope(graph, ["gate"]) == ["trigger", "source", "secrets", "sca", "merge", "gate"]


import pytest
from pydantic import ValidationError


def test_workflow_graph_rejects_excessive_node_count():
    with pytest.raises(ValidationError):
        WorkflowGraph(nodes=[{"id": f"node-{index}", "type": "trigger.manual"} for index in range(501)], edges=[])


def test_workflow_graph_rejects_excessive_edge_count():
    with pytest.raises(ValidationError):
        WorkflowGraph(
            nodes=[{"id": "source", "type": "source.git"}],
            edges=[{"id": f"edge-{index}", "source": "source", "target": "source"} for index in range(2001)],
        )


def test_workflow_graph_rejects_oversized_node_configuration():
    with pytest.raises(ValidationError):
        WorkflowGraph(
            nodes=[{"id": "source", "type": "source.git", "config": {f"option-{index}": index for index in range(101)}}],
            edges=[],
        )


def test_duplicate_edge_ids_are_rejected():
    graph = WorkflowGraph(
        nodes=[
            {"id": "trigger", "type": "trigger.manual"},
            {"id": "source", "type": "source.git"},
            {"id": "secrets", "type": "scan.secrets"},
        ],
        edges=[
            {"id": "duplicate", "source": "trigger", "target": "source"},
            {"id": "duplicate", "source": "source", "target": "secrets"},
        ],
    )
    result = validate_graph(graph, registry)
    assert not result.valid
    assert any(issue.code == "duplicate_edge_id" for issue in result.issues)
