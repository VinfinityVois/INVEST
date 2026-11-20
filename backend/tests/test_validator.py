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
