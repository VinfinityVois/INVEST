from collections import defaultdict, deque
from pathlib import Path
from time import perf_counter

from app.config import settings
from app.ai.explanations import explain_findings
from app.policies.security_gate import evaluate_security_gate
from app.scanners.secrets import scan_directory
from app.scanners.presentation import enrich_finding
from app.scanners.sca import scan_gradle_project
from app.scanners.sast import scan_kotlin_project
from app.sources.git import GitSourceError, clone_allowed_repository
from .registry import NodeRegistry
from .schemas import WorkflowGraph
from .validator import validate_graph


class WorkflowExecutionError(RuntimeError):
    pass


def _workspace_source(relative_path: str) -> Path:
    """Resolve an uploaded project directory strictly inside WORKSPACE_ROOT."""
    workspace = Path(settings.workspace_root).resolve()
    relative = Path(relative_path)
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise WorkflowExecutionError("Source path must be a safe relative path")
    unresolved = workspace.joinpath(relative)
    current = unresolved
    while current != workspace:
        if current.is_symlink():
            raise WorkflowExecutionError("Symlinks are not allowed in source paths")
        current = current.parent
    candidate = unresolved.resolve(strict=True)
    if not candidate.is_relative_to(workspace):
        raise WorkflowExecutionError("Source path is outside the configured workspace")
    if candidate.is_symlink() or not candidate.is_dir():
        raise WorkflowExecutionError("Source must be a directory inside the workspace")
    return candidate


def execute_graph(graph: WorkflowGraph, registry: NodeRegistry, on_progress=None, finding_states=None):
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
        node_started = perf_counter()
        node = nodes[node_id]
        parents = [outputs[parent] for parent in incoming[node_id] if parent in outputs]

        def report_scanner_progress(progress):
            if on_progress is None:
                return
            observed = {}
            for node_output in outputs.values():
                for finding in node_output.get("findings", []):
                    fingerprint = finding.get("fingerprint") or repr(sorted(finding.items()))
                    observed.setdefault(str(fingerprint), finding)
            current_trace = list(trace) + [{
                "node_id": node_id,
                "type": node.type,
                "status": "running",
                "duration_ms": round((perf_counter() - node_started) * 1000, 2),
            }]
            try:
                on_progress({
                    "status": "running",
                    "completed_nodes": len(trace),
                    "total_nodes": len(order),
                    "current_node": node_id,
                    "scanner_progress": progress,
                    "total_findings": len(observed),
                    "severity": {
                        level: sum(1 for item in observed.values() if str(item.get("severity", "UNKNOWN")).upper() == level)
                        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                    },
                    "trace": current_trace,
                })
            except Exception:
                pass

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
            try:
                source = clone_allowed_repository(
                    url=node.config.get("url", ""),
                    ref=node.config.get("ref"),
                    workspace_root=settings.workspace_root,
                    allowed_targets=settings.allowed_target_list,
                )
                artifacts[node_id] = _workspace_source(source["path"])
                output = {"status": "ready", **source}
            except (GitSourceError, OSError, WorkflowExecutionError) as exc:
                output = {"status": "failed", "message": str(exc)}
        elif node.type == "scan.secrets":
            source_node = next(
                (parent for parent in incoming[node_id] if parent in artifacts), None
            )
            if source_node is None:
                output = {"status": "blocked", "findings": [], "message": "Нет доступного source-каталога."}
            else:
                findings = [enrich_finding(item, artifacts[source_node]) for item in scan_directory(artifacts[source_node], on_progress=report_scanner_progress)]
                output = {"status": "completed", "findings": findings, "summary": {"total": len(findings)}}
        elif node.type == "scan.sca":
            source_node = next(
                (parent for parent in incoming[node_id] if parent in artifacts), None
            )
            if source_node is None:
                output = {"status": "blocked", "findings": [], "message": "Нет доступного source-каталога."}
            else:
                findings = [enrich_finding(item, artifacts[source_node]) for item in scan_gradle_project(artifacts[source_node], on_progress=report_scanner_progress)]
                output = {"status": "completed", "findings": findings, "summary": {"total": len(findings)}}
        elif node.type == "scan.sast":
            source_node = next(
                (parent for parent in incoming[node_id] if parent in artifacts), None
            )
            if source_node is None:
                output = {"status": "blocked", "findings": [], "message": "Нет доступного source-каталога."}
            else:
                findings = [enrich_finding(item, artifacts[source_node]) for item in scan_kotlin_project(artifacts[source_node], on_progress=report_scanner_progress)]
                output = {"status": "completed", "findings": findings, "summary": {"total": len(findings)}}
        elif node.type == "findings.merge":
            merged = []
            for parent in parents:
                merged.extend(parent.get("findings", []))
            unique = {}
            for finding in merged:
                unique.setdefault(finding.get("fingerprint") or repr(finding), finding)
            output = {"status": "completed", "findings": list(unique.values()), "summary": {"total": len(unique)}}
        elif node.type == "ci.gate":
            merged = []
            for parent in parents:
                merged.extend(parent.get("findings", []))
            unique = {}
            for finding in merged:
                unique.setdefault(finding.get("fingerprint") or repr(sorted(finding.items())), finding)
            try:
                evaluation = evaluate_security_gate(list(unique.values()), node.config, finding_states)
                output = {
                    "status": "blocked" if evaluation["blocked"] else "completed",
                    "decision": evaluation["decision"],
                    "findings": list(unique.values()),
                    "summary": {"total": len(unique)},
                    **evaluation,
                }
            except ValueError as exc:
                output = {"status": "failed", "decision": "INVALID_POLICY", "message": str(exc), "findings": []}
        elif node.type == "logic.if":
            output = {"status": "completed", "branch": "false"}
        elif node.type == "ai.explain":
            merged = []
            for parent in parents:
                merged.extend(parent.get("findings", []))
            unique = {}
            for finding in merged:
                unique.setdefault(finding.get("fingerprint") or repr(sorted(finding.items())), finding)
            try:
                output = explain_findings(list(unique.values()), node.config)
            except ValueError as exc:
                output = {"status": "failed", "message": str(exc), "findings": list(unique.values()), "explanations": []}
        else:
            output = {"status": "adapter_required"}

        outputs[node_id] = output
        trace.append({
            "node_id": node_id,
            "type": node.type,
            "status": output.get("status", "completed"),
            "duration_ms": round((perf_counter() - node_started) * 1000, 2),
            **({"findings": output["summary"]["total"]} if "summary" in output else {}),
            **({"message": output["message"]} if output.get("message") else {}),
            **({"explained_count": output.get("explained_count", len(output.get("explanations", [])))} if node.type == "ai.explain" else {}),
        })
        if on_progress is not None:
            try:
                observed_findings = {}
                for node_output in outputs.values():
                    for finding in node_output.get("findings", []):
                        fingerprint = finding.get("fingerprint") or repr(sorted(finding.items()))
                        observed_findings.setdefault(str(fingerprint), finding)
                severity_counts = {}
                for finding in observed_findings.values():
                    severity = str(finding.get("severity", "UNKNOWN")).upper()
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                on_progress({
                    "status": "running",
                    "completed_nodes": len(trace),
                    "total_nodes": len(order),
                    "current_node": node_id,
                    "total_findings": len(observed_findings),
                    "severity": severity_counts,
                    "trace": list(trace),
                    "node_results": {
                        key: {
                            "status": value.get("status"),
                            **({"message": value["message"]} if value.get("message") else {}),
                            **({"findings": value["summary"]["total"]} if isinstance(value.get("summary"), dict) else {}),
                            **({"explained_count": value.get("explained_count", len(value.get("explanations", [])))} if key in nodes and nodes[key].type == "ai.explain" else {}),
                            **({"total_findings": len(value.get("findings", []))} if key in nodes and nodes[key].type == "ai.explain" else {}),
                        } for key, value in outputs.items()
                    },
                })
            except Exception:
                # Progress reporting must never break a security scan.
                pass

    failed = any(item["status"] in {"failed", "blocked"} for item in outputs.values())
    pending = any(item["status"] in {"adapter_required", "scanner_pending", "llm_profile_required", "configuration_required"} for item in outputs.values())
    status = "failed" if failed else ("partial" if pending else "completed")
    gate_results = [value for value in outputs.values() if "decision" in value]
    security_gate = gate_results[-1] if gate_results else None
    return {"status": status, "order": order, "trace": trace, "outputs": outputs, "security_gate": security_gate}
