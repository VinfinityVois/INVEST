from app.workflows.registry import registry
from app.workflows.schemas import WorkflowGraph
from app.workflows.validator import validate_graph

def test_manual_to_secrets_is_valid():
    graph=WorkflowGraph(nodes=[{"id":"t","type":"trigger.manual"},{"id":"s","type":"scan.secrets"}],edges=[{"id":"e","source":"t","target":"s"}])
    assert validate_graph(graph,registry).valid

def test_unknown_node_rejected():
    graph=WorkflowGraph(nodes=[{"id":"x","type":"fake.node"}],edges=[])
    result=validate_graph(graph,registry)
    assert not result.valid and any(x.code=="unknown_node_type" for x in result.issues)

def test_cycles_rejected():
    graph=WorkflowGraph(nodes=[{"id":"t","type":"trigger.manual"},{"id":"s","type":"scan.secrets"}],edges=[{"id":"a","source":"t","target":"s"},{"id":"b","source":"s","target":"t"}])
    result=validate_graph(graph,registry)
    assert not result.valid and any(x.code=="cycle_detected" for x in result.issues)
