from collections import defaultdict, deque
from pathlib import Path

from app.config import settings
from app.scanners.secrets import scan_directory
from .registry import NodeRegistry
from .schemas import WorkflowGraph
from .validator import validate_graph


class WorkflowExecutionError(RuntimeError):
    pass


def _workspace_source(relative_path: str) -> Path:
    """Resolve an uploaded project directory strictly inside WORKSPACE_ROOT."""
    workspace = Path(settings.workspace_root).resolve()
    unresolved = workspace / relative_path
    if any(part.is_symlink() for part in [unresolved, *unresolved.parents] if part != workspace.parent):
        raise WorkflowExecutionError("Symlinks are not allowed in source paths")
    candidate = unresolved.resolve(strict=True)
    if not candidate.is_relative_to(workspace):
        raise WorkflowExecutionError("Source path is outside the configured workspace")
    if candidate.is_symlink() or not candidate.is_dir():
        raise WorkflowExecutionError("Source must be a directory inside the workspace")
    return candidate


def execute_graph(graph: WorkflowGraph, registry: NodeRegistry):
    validation = validate_graph(graph, registry)
    if not validation.valid:
        raise WorkflowExecutionError(
            "; ".join(i.message for i in validation.issues if i.severity == "error")
        )

    nodes = {node.id: node for node in graph.nodes}
    outgoing = defaultdict(list)
    incoming = defaultdict(list)
    indegree = {node.id: 0 for node in graph.nodes}
    for edge in graph.edges:
        outgoing[edge.source].append(edge.target)
        incoming[edge.target].append(edge.source)
        indegree[edge.target] += 1

    queue = deque(node_id for node_id, degree in indegree.items() if degree == 0)
    order = []
    while queue:
        current = queue.popleft()
        order.append(current)
        for target in outgoing[current]:
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)

    trace = []
    outputs = {}
    artifacts = {}
    for node_id in order:
        node = nodes[node_id]
        parents = [outputs[parent] for parent in incoming[node_id] if parent in outputs]

        if node.type == "trigger.manual":
            output = {"status": "completed", "triggered": True}
        elif node.type == "source.upload":
            relative_path = node.config.get("path")
            if not isinstance(relative_path, str) or not relative_path.strip():
                output = {"status": "configuration_required", "message": "Укажите относительный путь к каталогу внутри WORKSPACE_ROOT."}
            else:
                try:
                    source_root = _workspace_source(relative_path)
                    artifacts[node_id] = source_root
                    output = {"status": "ready", "source": "workspace-upload", "path": relative_path}
                except (OSError, WorkflowExecutionError) as exc:
                    output = {"status": "failed", "message": str(exc)}
        elif node.type == "source.git":
            output = {"status": "adapter_required", "message": "Git source adapter ещё не подключён."}
        elif node.type == "scan.secrets":
            source_node = next(
                (parent for parent in incoming[node_id] if parent in artifacts), None
            )
            if source_node is None:
                output = {"status": "blocked", "findings": [], "message": "Нет доступного source-каталога."}
            else:
                findings = scan_directory(artifacts[source_node])
                output = {"status": "completed", "findings": findings, "summary": {"total": len(findings)}}
        elif node.type in {"scan.sca", "scan.sast"}:
            output = {"status": "scanner_pending", "findings": []}
        elif node.type == "findings.merge":
            merged = []
            for parent in parents:
                merged.extend(parent.get("findings", []))
            unique = {}
            for finding in merged:
                unique.setdefault(finding.get("fingerprint") or repr(finding), finding)
            output = {"status": "completed", "findings": list(unique.values()), "summary": {"total": len(unique)}}
        elif node.type == "logic.if":
            output = {"status": "completed", "branch": "false"}
        elif node.type == "ai.explain":
            output = {"status": "llm_profile_required"}
        else:
            output = {"status": "adapter_required"}

        outputs[node_id] = output
        trace.append({
            "node_id": node_id,
            "type": node.type,
            "status": output.get("status", "completed"),
            **({"findings": output["summary"]["total"]} if "summary" in output else {}),
        })

    failed = any(item["status"] in {"failed", "blocked"} for item in outputs.values())
    pending = any(item["status"] in {"adapter_required", "scanner_pending", "llm_profile_required", "configuration_required"} for item in outputs.values())
    status = "failed" if failed else ("partial" if pending else "completed")
    return {"status": status, "order": order, "trace": trace, "outputs": outputs}
