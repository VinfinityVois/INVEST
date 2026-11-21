from collections import defaultdict, deque
from .registry import NodeRegistry
from .schemas import WorkflowGraph, ValidationIssue, ValidationResult



def _validate_config_value(value, schema, path):
    issues = []
    expected = schema.get("type")
    valid_type = True
    if expected == "string": valid_type = isinstance(value, str)
    elif expected == "integer": valid_type = isinstance(value, int) and not isinstance(value, bool)
    elif expected == "number": valid_type = isinstance(value, (int, float)) and not isinstance(value, bool)
    elif expected == "boolean": valid_type = isinstance(value, bool)
    elif expected == "array": valid_type = isinstance(value, list)
    elif expected == "object": valid_type = isinstance(value, dict)
    if expected and not valid_type:
        return [f"{path}: ожидается {expected}."]
    if not valid_type:
        return issues
    if "enum" in schema and value not in schema["enum"]:
        issues.append(f"{path}: значение отсутствует в допустимом списке.")
    if expected in {"integer", "number"}:
        if "minimum" in schema and value < schema["minimum"]: issues.append(f"{path}: значение меньше {schema['minimum']}.")
        if "maximum" in schema and value > schema["maximum"]: issues.append(f"{path}: значение больше {schema['maximum']}.")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]: issues.append(f"{path}: значение должно быть больше {schema['exclusiveMinimum']}.")
        if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]: issues.append(f"{path}: значение должно быть меньше {schema['exclusiveMaximum']}.")
    if expected == "string":
        if "minLength" in schema and len(value) < schema["minLength"]: issues.append(f"{path}: слишком короткое значение.")
        if "maxLength" in schema and len(value) > schema["maxLength"]: issues.append(f"{path}: превышена максимальная длина.")
        if schema.get("pattern"):
            import re
            try:
                if re.search(schema["pattern"], value) is None: issues.append(f"{path}: значение не соответствует формату.")
            except re.error:
                issues.append(f"{path}: некорректный pattern в config_schema.")
    if expected == "array":
        if "minItems" in schema and len(value) < schema["minItems"]: issues.append(f"{path}: недостаточно элементов.")
        if "maxItems" in schema and len(value) > schema["maxItems"]: issues.append(f"{path}: слишком много элементов.")
        item_schema = schema.get("items", {})
        for index, item in enumerate(value): issues.extend(_validate_config_value(item, item_schema, f"{path}[{index}]"))
    if expected == "object":
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value or value[key] is None: issues.append(f"{path}.{key}: обязательное поле отсутствует.")
        for key, item in value.items():
            if key in properties: issues.extend(_validate_config_value(item, properties[key], f"{path}.{key}"))
    return issues

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
        else:
            manifests[node.id] = manifest
            for message in _validate_config_value(node.config, manifest.config_schema, "config"):
                # Incomplete nodes are valid drafts; required values are checked again at execution.
                severity = "warning" if "обязательное поле" in message else "error"
                issues.append(ValidationIssue(code="invalid_node_config", message=message, node_id=node.id, severity=severity))
    adjacency = defaultdict(list)
    indegree = {n.id:0 for n in graph.nodes}
    seen = set()
    for edge in graph.edges:
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
    if graph.nodes and not any(n.type in {"trigger.manual", "trigger.schedule"} for n in graph.nodes):
        issues.append(ValidationIssue(code="missing_trigger",message="Добавьте Manual trigger или Schedule trigger.",severity="warning"))
    return ValidationResult(valid=not any(i.severity=="error" for i in issues),issues=issues)
