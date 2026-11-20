from collections import defaultdict, deque
from datetime import datetime, timezone
import copy
import hashlib
import json
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


CACHE_SCHEMA_VERSION = "node-cache-v1"
SCANNER_CACHE_VERSION = "2026-11-21.1"
CACHEABLE_NODE_TYPES = {"scan.secrets", "scan.sca", "scan.sast"}
MAX_CACHE_ENTRY_BYTES = 2_000_000
CACHE_TTL_SECONDS = 24 * 60 * 60


def _source_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    skipped = {".git", "node_modules", ".gradle", "build", "dist", "target", ".venv"}
    files = []
    for path in root.rglob("*"):
        if any(part in skipped for part in path.parts) or path.is_symlink() or not path.is_file():
            continue
        try:
            if not path.resolve(strict=True).is_relative_to(root) or path.stat().st_size > 1_000_000:
                continue
            files.append(path)
        except OSError:
            continue
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        try:
            relative = path.relative_to(root).as_posix().encode("utf-8")
            content = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in content[:8192]:
            continue
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()




def _bounded_cache_entries(entries: dict | None) -> dict:
    bounded = {}
    total_bytes = 0
    for key, value in (entries or {}).items():
        if not isinstance(key, str) or not isinstance(value, dict) or value.get("status") != "completed":
            continue
        try:
            size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError):
            continue
        if size > MAX_CACHE_ENTRY_BYTES or len(bounded) >= 100 or total_bytes + size > 20_000_000:
            continue
        bounded[key] = value
        total_bytes += size
    return bounded


def _node_cache_components(node, source_root: Path) -> dict:
    config_encoded = json.dumps(node.config, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return {
        "schema_version": CACHE_SCHEMA_VERSION,
        "scanner_version": SCANNER_CACHE_VERSION,
        "node_type": node.type,
        "config_hash": hashlib.sha256(config_encoded).hexdigest(),
        "source_hash": _source_fingerprint(source_root),
    }


def _node_cache_key(node, source_root: Path) -> str:
    encoded = json.dumps(_node_cache_components(node, source_root), sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _cache_age_seconds(cached_at: str) -> float | None:
    try:
        timestamp = datetime.fromisoformat(cached_at.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - timestamp).total_seconds())
    except (TypeError, ValueError):
        return None


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


def resolve_execution_scope(graph: WorkflowGraph, target_node_ids: list[str]) -> list[str]:
    """Return the selected nodes and every upstream dependency in stable graph order."""
    nodes = {node.id for node in graph.nodes}
    requested = list(dict.fromkeys(target_node_ids or []))
    if not requested:
        return [node.id for node in graph.nodes]
    unknown = sorted(set(requested) - nodes)
    if unknown:
        raise WorkflowExecutionError("Unknown target node ids: " + ", ".join(unknown))
    incoming = defaultdict(list)
    indegree = {node.id: 0 for node in graph.nodes}
    outgoing = defaultdict(list)
    for edge in graph.edges:
        incoming[edge.target].append(edge.source)
        outgoing[edge.source].append(edge.target)
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
    included = set()
    stack = list(requested)
    while stack:
        current = stack.pop()
        if current in included:
            continue
        included.add(current)
        stack.extend(incoming[current])
    return [node_id for node_id in order if node_id in included]



def _condition_context(parents: list[dict]) -> dict:
    findings = []
    for parent in parents:
        findings.extend(item for item in parent.get("findings", []) if isinstance(item, dict))
    severities = {}
    for finding in findings:
        level = str(finding.get("severity", "UNKNOWN")).upper()
        severities[level] = severities.get(level, 0) + 1
    return {
        "findings": findings,
        "finding_count": len(findings),
        "critical_count": severities.get("CRITICAL", 0),
        "high_count": severities.get("HIGH", 0),
        "medium_count": severities.get("MEDIUM", 0),
        "low_count": severities.get("LOW", 0),
        "info_count": severities.get("INFO", 0),
        "severity_counts": severities,
    }


def _condition_value(context: dict, field: str):
    value = context
    for part in field.split("."):
        if isinstance(value, dict):
            value = value.get(part)
        elif isinstance(value, list) and part.isdigit():
            index = int(part)
            value = value[index] if 0 <= index < len(value) else None
        else:
            return None
    return value


def _evaluate_condition(config: dict, parents: list[dict]) -> tuple[bool, str | None]:
    """Evaluate a small deterministic condition DSL over upstream findings."""
    field = config.get("field", "finding_count")
    operator = config.get("operator", "gt")
    expected = config.get("value", 0)
    if not isinstance(field, str) or not field or len(field) > 160:
        return False, "Поле условия должно быть непустой строкой длиной до 160 символов."
    actual = _condition_value(_condition_context(parents), field)
    if operator == "exists":
        return actual is not None, None
    if operator in {"eq", "ne"}:
        result = actual == expected
        return (result if operator == "eq" else not result), None
    if operator in {"contains", "not_contains"}:
        try:
            result = expected in actual
        except (TypeError, ValueError):
            return False, "Операция contains применима только к строкам, спискам и словарям."
        return (result if operator == "contains" else not result), None
    if operator == "regex":
        import re
        if not isinstance(actual, str) or not isinstance(expected, str) or len(expected) > 256:
            return False, "Для regex нужны строковое поле и шаблон длиной до 256 символов."
        try:
            return re.search(expected, actual) is not None, None
        except re.error as exc:
            return False, "Некорректное регулярное выражение: " + str(exc)
    if operator in {"gt", "gte", "lt", "lte"}:
        try:
            left, right = float(actual), float(expected)
        except (TypeError, ValueError):
            return False, "Числовое сравнение требует числовых значений."
        return {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right}[operator], None
    return False, "Неподдерживаемый оператор условия: " + str(operator)



def _active_parent_ids(edges, outputs: dict) -> list[str]:
    active = []
    for edge in edges:
        parent_output = outputs.get(edge.source)
        if parent_output is None or parent_output.get("status") == "skipped":
            continue
        selected_branch = parent_output.get("branch")
        if selected_branch and edge.source_handle and edge.source_handle != selected_branch:
            continue
        active.append(edge.source)
    return list(dict.fromkeys(active))


def execute_graph(graph: WorkflowGraph, registry: NodeRegistry, on_progress=None, finding_states=None, should_cancel=None, target_node_ids=None, cache_entries=None, force_full_scan=False, force_node_ids=None, cache_metadata=None):
    validation = validate_graph(graph, registry)
    if not validation.valid:
        raise WorkflowExecutionError(
            "; ".join(i.message for i in validation.issues if i.severity == "error")
        )

    nodes = {node.id: node for node in graph.nodes}
    outgoing = defaultdict(list)
    incoming = defaultdict(list)
    incoming_edges = defaultdict(list)
    indegree = {node.id: 0 for node in graph.nodes}
    for edge in graph.edges:
        outgoing[edge.source].append(edge.target)
        incoming[edge.target].append(edge.source)
        incoming_edges[edge.target].append(edge)
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

    requested_node_ids = list(dict.fromkeys(target_node_ids or []))
    included_node_ids = set()
    if requested_node_ids:
        unknown = sorted(set(requested_node_ids) - set(nodes))
        if unknown:
            raise WorkflowExecutionError("Unknown target node ids: " + ", ".join(unknown))
        stack = list(requested_node_ids)
        while stack:
            current = stack.pop()
            if current in included_node_ids:
                continue
            included_node_ids.add(current)
            stack.extend(incoming[current])
        order = [node_id for node_id in order if node_id in included_node_ids]

    trace = []
    outputs = {}
    artifacts = {}
    reusable_cache = {} if force_full_scan else _bounded_cache_entries(cache_entries)
    next_cache_entries = dict(reusable_cache)
    reusable_metadata = {} if force_full_scan else dict(cache_metadata or {})
    next_cache_metadata = dict(reusable_metadata)
    forced_nodes = set(force_node_ids or [])
    cancelled = False
    for node_id in order:
        if should_cancel is not None:
            try:
                if should_cancel():
                    cancelled = True
                    break
            except Exception:
                # A transient status lookup failure must not abort a security scan.
                pass
        node_started = perf_counter()
        node = nodes[node_id]
        cache_hit = False
        cache_bypass_reason = None
        active_parent_ids = _active_parent_ids(incoming_edges[node_id], outputs)
        parents = [outputs[parent] for parent in active_parent_ids if parent in outputs]
        if incoming_edges[node_id] and not parents:
            output = {"status": "skipped", "message": "Ветка workflow не выбрана предыдущим условным блоком."}
            outputs[node_id] = output
            trace.append({"node_id": node_id, "type": node.type, "status": "skipped", "diagnostic_level": "info", "duration_ms": 0})
            continue

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
                output = {"status": "configuration_required", "message": "Выберите источник проекта: загрузите ZIP-архив или настройте Git-репозиторий."}
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
        elif node.type in CACHEABLE_NODE_TYPES:
            source_node = next((parent for parent in incoming[node_id] if parent in artifacts), None)
            if source_node is None:
                output = {"status": "blocked", "findings": [], "message": "Нет доступного source-каталога."}
            else:
                source_root = artifacts[source_node]
                components = _node_cache_components(node, source_root)
                cache_key = _node_cache_key(node, source_root)
                cached_output = reusable_cache.get(cache_key)
                metadata = reusable_metadata.get(node_id)
                cache_age_seconds = None
                if node_id in forced_nodes:
                    cache_bypass_reason = "Кэш блока сброшен пользователем"
                elif force_full_scan:
                    cache_bypass_reason = "Запрошен полный анализ"
                elif isinstance(metadata, dict) and metadata.get("cache_key") != cache_key:
                    if metadata.get("scanner_version") != components["scanner_version"] or metadata.get("schema_version") != components["schema_version"]:
                        cache_bypass_reason = "Обновилась версия сканера или формат кэша"
                    elif metadata.get("config_hash") != components["config_hash"]:
                        cache_bypass_reason = "Изменилась конфигурация блока"
                    elif metadata.get("source_hash") != components["source_hash"]:
                        cache_bypass_reason = "Изменилось содержимое исходного проекта"
                    else:
                        cache_bypass_reason = "Нет метаданных актуальности кэша"
                elif not isinstance(metadata, dict):
                    cache_bypass_reason = "Нет метаданных актуальности кэша"
                elif not (isinstance(cached_output, dict) and cached_output.get("status") == "completed"):
                    cache_bypass_reason = "Нет сохранённого результата"
                else:
                    cache_age_seconds = _cache_age_seconds(metadata.get("cached_at"))
                    if cache_age_seconds is None:
                        cache_bypass_reason = "Не удалось определить возраст кэша"
                    elif cache_age_seconds >= CACHE_TTL_SECONDS:
                        cache_bypass_reason = "Срок действия кэша истёк"
                cache_is_usable = (
                    node_id not in forced_nodes
                    and not force_full_scan
                    and isinstance(cached_output, dict)
                    and cached_output.get("status") == "completed"
                    and cache_bypass_reason is None
                )
                if cache_is_usable:
                    output = copy.deepcopy(cached_output)
                    cache_hit = True
                else:
                    if node.type == "scan.secrets":
                        raw_findings = scan_directory(source_root, on_progress=report_scanner_progress)
                    elif node.type == "scan.sca":
                        raw_findings = scan_gradle_project(source_root, on_progress=report_scanner_progress)
                    else:
                        raw_findings = scan_kotlin_project(source_root, on_progress=report_scanner_progress)
                    findings = [enrich_finding(item, source_root) for item in raw_findings]
                    output = {"status": "completed", "findings": findings, "summary": {"total": len(findings)}}
                    try:
                        if len(json.dumps(output, ensure_ascii=False).encode("utf-8")) <= MAX_CACHE_ENTRY_BYTES:
                            next_cache_entries[cache_key] = copy.deepcopy(output)
                            next_cache_metadata[node_id] = {
                                **components,
                                "cache_key": cache_key,
                                "cached_at": datetime.now(timezone.utc).isoformat(),
                            }
                    except (TypeError, ValueError):
                        pass
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
                    "message": (
                        "Проверка остановлена политикой: найдены уязвимости выше допустимого порога."
                        if evaluation["blocked"]
                        else "Проверка политики завершена: критичных блокирующих находок нет."
                    ),
                }
            except ValueError as exc:
                output = {"status": "failed", "decision": "INVALID_POLICY", "message": str(exc), "findings": []}
        elif node.type == "logic.if":
            matched, error = _evaluate_condition(node.config, parents)
            if error:
                output = {"status": "failed", "reason_code": "INVALID_CONDITION", "message": error, "branch": "false"}
            else:
                output = {
                    "status": "completed",
                    "branch": "true" if matched else "false",
                    "condition": {
                        "field": node.config.get("field", "finding_count"),
                        "operator": node.config.get("operator", "gt"),
                        "matched": matched,
                    },
                }
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
        node_status = output.get("status", "completed")
        diagnostic_level = (
            "error" if node_status == "failed"
            else "blocked" if node_status == "blocked"
            else "warning" if node_status in {"configuration_required", "adapter_required", "scanner_pending", "llm_profile_required"}
            or output.get("decision") == "WARN"
            else "info"
        )
        diagnostic_code = output.get("reason_code")
        if not diagnostic_code and node_status == "blocked":
            diagnostic_code = "UPSTREAM_SOURCE_UNAVAILABLE" if node.type.startswith("scan.") else "UPSTREAM_STEP_BLOCKED"
        elif not diagnostic_code and node_status == "configuration_required":
            diagnostic_code = "NODE_CONFIGURATION_REQUIRED"
        elif not diagnostic_code and node_status == "failed":
            diagnostic_code = "NODE_EXECUTION_FAILED"
        elif not diagnostic_code and output.get("decision") == "WARN":
            diagnostic_code = "SECURITY_GATE_WARNING"
        trace.append({
            "node_id": node_id,
            "type": node.type,
            "status": node_status,
            "cached": cache_hit,
            **({"cache_age_seconds": round(cache_age_seconds, 2)} if cache_hit and cache_age_seconds is not None else {}),
            **({"cache_bypass_reason": cache_bypass_reason} if node.type in CACHEABLE_NODE_TYPES and not cache_hit and cache_bypass_reason else {}),
            "diagnostic_level": diagnostic_level,
            **({"reason_code": diagnostic_code} if diagnostic_code else {}),
            **({"reason": str(output["message"])[:500]} if output.get("message") else {}),
            "duration_ms": round((perf_counter() - node_started) * 1000, 2),
            **({"findings": output["summary"]["total"]} if "summary" in output else {}),
            **({"message": output["message"]} if output.get("message") else {}),
            **({
                "explained_count": output.get("explained_count", len(output.get("explanations", []))),
                "analyzed_count": output.get("analyzed_count", 0),
                "skipped_count": output.get("skipped_count", 0),
                "coverage": output.get("coverage", 0),
                "provider": output.get("provider"),
                "model": output.get("model"),
                "provider_request_ms": output.get("provider_request_ms"),
                "provider_attempts": output.get("provider_attempts"),
                "provider_http_status": output.get("provider_http_status"),
                "provider_error_code": output.get("provider_error_code"),
            } if node.type == "ai.explain" else {}),
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
                            **({"reason_code": value["reason_code"]} if value.get("reason_code") else {}),
                            **({"findings": value["summary"]["total"]} if isinstance(value.get("summary"), dict) else {}),
                            **({"severity": {
                                severity: sum(1 for finding in value.get("findings", []) if str(finding.get("severity", "UNKNOWN")).upper() == severity)
                                for severity in sorted({str(finding.get("severity", "UNKNOWN")).upper() for finding in value.get("findings", [])})
                            }} if isinstance(value.get("findings"), list) and value.get("findings") else {}),
                            **({
                                "explained_count": value.get("explained_count", len(value.get("explanations", []))),
                                "analyzed_count": value.get("analyzed_count", 0),
                                "skipped_count": value.get("skipped_count", 0),
                                "unexplained_count": value.get("unexplained_count", 0),
                                "coverage": value.get("coverage", 0),
                                "provider": value.get("provider"),
                                "model": value.get("model"),
                                "provider_request_ms": value.get("provider_request_ms"),
                                "provider_attempts": value.get("provider_attempts"),
                                "provider_http_status": value.get("provider_http_status"),
                                "provider_error_code": value.get("provider_error_code"),
                            } if key in nodes and nodes[key].type == "ai.explain" else {}),
                            **({"total_findings": len(value.get("findings", []))} if key in nodes and nodes[key].type == "ai.explain" else {}),
                            **({"explanations": [
                                {
                                    "root_cause": str(item.get("root_cause", ""))[:240],
                                    "impact": str(item.get("impact", ""))[:180],
                                    "recommendation": str(item.get("recommendation", ""))[:240],
                                } for item in value.get("explanations", [])[:3]
                            ]} if key in nodes and nodes[key].type == "ai.explain" else {}),
                        } for key, value in outputs.items()
                    },
                })
            except Exception:
                # Progress reporting must never break a security scan.
                pass

    failed = any(
        item.get("status") == "failed"
        or (nodes[node_id].type == "ci.gate" and item.get("status") == "blocked")
        for node_id, item in outputs.items()
    )
    pending = any(item["status"] in {"adapter_required", "scanner_pending", "llm_profile_required", "configuration_required"} for item in outputs.values())
    status = "cancelled" if cancelled else ("failed" if failed else ("partial" if pending else "completed"))
    gate_results = [value for value in outputs.values() if "decision" in value]
    security_gate = gate_results[-1] if gate_results else None
    return {"status": status, "order": order, "execution_scope": {"requested_node_ids": requested_node_ids, "included_node_ids": order}, "trace": trace, "outputs": outputs, "security_gate": security_gate, "cache_entries": next_cache_entries, "cache_metadata": next_cache_metadata, "cache_summary": {"enabled": not force_full_scan, "force_full_scan": bool(force_full_scan), "hits": sum(1 for item in trace if item.get("cached")), "misses": sum(1 for item in trace if item.get("type") in CACHEABLE_NODE_TYPES and not item.get("cached"))}}
