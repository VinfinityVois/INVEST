import app.workflows.presets as presets_module
from app.rules_loader import rule_packs
from app.workflows.presets import list_presets, load_preset
from app.workflows.registry import registry
from app.workflows.schemas import WorkflowGraph
from app.workflows.templates import clone_graph, sanitize_graph
from app.workflows.validator import validate_graph


def test_builtin_pr_gate_preset_is_registered():
    presets = list_presets()

    assert any(item["id"] == "pr-gate" and item["node_count"] == 7 for item in presets)


def test_builtin_pr_gate_graph_is_valid_and_uses_registered_packs():
    preset = load_preset("pr-gate")
    graph = WorkflowGraph.model_validate(preset["graph"])
    validation = validate_graph(graph, registry)

    assert validation.valid, validation.model_dump()
    assert sum(node.type == "ci.gate" for node in graph.nodes) == 1
    assert {node.type for node in graph.nodes} >= {
        "trigger.manual", "source.git", "scan.secrets", "scan.sca",
        "scan.sast", "findings.merge", "ci.gate",
    }
    assert rule_packs.resolve(["sca-spring-boot"], analyzer="sca")


def test_every_builtin_preset_graph_is_valid():
    for metadata in list_presets():
        preset = load_preset(metadata["id"])
        graph = WorkflowGraph.model_validate(preset["graph"])
        validation = validate_graph(graph, registry)

        assert validation.valid, f"{metadata['id']}: {validation.model_dump()}"
        assert len(graph.nodes) == metadata["node_count"]


def test_all_nodes_lab_covers_every_registered_node_type():
    preset = load_preset("all-nodes-lab")
    graph = WorkflowGraph.model_validate(preset["graph"])
    node_types = {node.type for node in graph.nodes}
    registered_types = {manifest.type for manifest in registry.all()}
    validation = validate_graph(graph, registry)

    assert validation.valid, validation.model_dump()
    assert len(graph.nodes) == len(registered_types) == 15
    assert node_types == registered_types
    assert len({node.id for node in graph.nodes}) == len(graph.nodes)


def test_builtin_pr_gate_clone_gets_fresh_graph_ids():
    preset = load_preset("pr-gate")
    source = sanitize_graph(preset["graph"])
    cloned = clone_graph(source, "PR Gate copy")

    assert cloned["name"] == "PR Gate copy"
    assert {node["id"] for node in cloned["nodes"]}.isdisjoint(
        {node["id"] for node in source["nodes"]}
    )
    assert len({edge["id"] for edge in cloned["edges"]}) == len(cloned["edges"])


def test_preset_root_skips_empty_preferred_directory(tmp_path):
    preferred = tmp_path / "backend" / "presets"
    fallback = tmp_path / "presets"
    preferred.mkdir(parents=True)
    fallback.mkdir()

    (fallback / "manifest.json").write_text(
        '{"formatVersion": 1, "presets": []}',
        encoding="utf-8",
    )

    selected = presets_module._select_preset_root((preferred, fallback))

    assert selected == fallback
    assert presets_module.list_presets(selected) == []
