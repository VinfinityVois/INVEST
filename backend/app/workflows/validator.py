from collections import defaultdict, deque
from urllib.parse import urlsplit
from .registry import NodeRegistry
from .schemas import WorkflowGraph, ValidationIssue, ValidationResult


def _config_schema_errors(value, schema, path="config"):
    """Validate the JSON-Schema subset used by node manifests."""
    if not isinstance(schema, dict):
        return [f"{path}: схема конфигурации некорректна."]
    errors = []
    expected_type = schema.get("type")
    type_matches = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "null": lambda item: item is None,
    }
    if isinstance(expected_type, list):
        if not any(type_name in type_matches and type_matches[type_name](value) for type_name in expected_type):
            return [f"{path}: ожидается один из типов {', '.join(expected_type)}."]
    elif expected_type in type_matches and not type_matches[expected_type](value):
        return [f"{path}: ожидается тип {expected_type}."]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: значение не входит в допустимый список.")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: значение меньше минимума {schema['minimum']}.")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: значение больше максимума {schema['maximum']}.")
    if isinstance(value, str):
        if schema.get("format") == "uri":
            parsed = urlsplit(value)
            if not parsed.scheme or any(character.isspace() for character in value):
                errors.append(f"{path}: ожидается корректный URI.")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: строка короче {schema['minLength']} символов.")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: строка длиннее {schema['maxLength']} символов.")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for required in schema.get("required", []):
            if required not in value:
                errors.append(f"{path}.{required}: обязательное поле отсутствует.")
        for key, item in value.items():
            child_schema = properties.get(key)
            if child_schema is not None:
                errors.extend(_config_schema_errors(item, child_schema, f"{path}.{key}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}.{key}: неизвестное поле.")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: элементов меньше {schema['minItems']}.")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: элементов больше {schema['maxItems']}.")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(_config_schema_errors(item, item_schema, f"{path}[{index}]"))
    return errors


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
            for message in _config_schema_errors(node.config, manifest.config_schema):
                issues.append(ValidationIssue(code="invalid_node_config", message=message, node_id=node.id))
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
