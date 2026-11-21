from collections import defaultdict, deque
from .registry import NodeRegistry
from .schemas import WorkflowGraph, ValidationIssue, ValidationResult

def validate_graph(graph: WorkflowGraph, registry: NodeRegistry) -> ValidationResult:
    issues = []
    by_id = {n.id:n for n in graph.nodes}
    if len(by_id) != len(graph.nodes):
        issues.append(ValidationIssue(code="duplicate_node_id",message="Идентификаторы нод должны быть уникальными."))
    manifests = {}
    for node in graph.nodes:
        manifest = registry.get(node.type)
        if manifest is None:
            issues.append(ValidationIssue(code="unknown_node_type",message=f"Неизвестный тип ноды: {node.type}",node_id=node.id))
        else: manifests[node.id] = manifest
    adjacency = defaultdict(list)
    indegree = {n.id:0 for n in graph.nodes}
    seen = set()
    seen_edge_ids = set()
    for edge in graph.edges:
        if edge.id in seen_edge_ids:
            issues.append(ValidationIssue(code="duplicate_edge_id",message="Идентификаторы связей должны быть уникальными.",edge_id=edge.id))
        seen_edge_ids.add(edge.id)
        if edge.source not in by_id or edge.target not in by_id:
            issues.append(ValidationIssue(code="dangling_edge",message="Связь ссылается на отсутствующую ноду.",edge_id=edge.id)); continue
        key=(edge.source,edge.target,edge.source_handle,edge.target_handle)
        if key in seen: issues.append(ValidationIssue(code="duplicate_edge",message="Повторяющаяся связь.",edge_id=edge.id))
        seen.add(key)
        src,dst=manifests.get(edge.source),manifests.get(edge.target)
        if src and dst:
            sh=edge.source_handle or (src.outputs[0].name if len(src.outputs)==1 else None)
            th=edge.target_handle or (dst.inputs[0].name if len(dst.inputs)==1 else None)
            op=next((p for p in src.outputs if p.name==sh),None)
            ip=next((p for p in dst.inputs if p.name==th),None)
            if op is None or ip is None: issues.append(ValidationIssue(code="invalid_port",message="Неизвестный или неоднозначный порт.",edge_id=edge.id))
            elif op.data_type != ip.data_type: issues.append(ValidationIssue(code="port_type_mismatch",message=f"Несовместимые типы: {op.data_type} → {ip.data_type}.",edge_id=edge.id))
        adjacency[edge.source].append(edge.target); indegree[edge.target]+=1
    queue=deque(k for k,v in indegree.items() if v==0); visited=0
    while queue:
        current=queue.popleft(); visited+=1
        for nxt in adjacency[current]:
            indegree[nxt]-=1
            if indegree[nxt]==0: queue.append(nxt)
    if visited != len(graph.nodes): issues.append(ValidationIssue(code="cycle_detected",message="Циклические workflow пока не поддерживаются."))
    if graph.nodes and not any(n.type=="trigger.manual" for n in graph.nodes):
        issues.append(ValidationIssue(code="missing_trigger",message="Добавьте Manual trigger.",severity="warning"))
    return ValidationResult(valid=not any(i.severity=="error" for i in issues),issues=issues)
