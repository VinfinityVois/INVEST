"""Sanitization and safe cloning helpers for the public template library."""
import copy
import re
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

SENSITIVE_KEY = re.compile(
    r"(?:secret|password|passwd|token|api[_-]?key|credential|authorization|private[_-]?key|access[_-]?key)",
    re.IGNORECASE,
)


def _sanitize_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        host = parsed.hostname
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    except (ValueError, TypeError):
        return ""


def _clean_value(value, node_type: str, key: str = ""):
    if SENSITIVE_KEY.search(key):
        return None
    lowered = key.lower()
    if node_type == "notify.webhook" and lowered in {"url", "endpoint", "webhook"}:
        return "https://example.invalid/replace-with-your-webhook"
    if node_type == "source.upload" and lowered in {"path", "workspace_path"}:
        return None
    if node_type == "source.git" and lowered == "url" and isinstance(value, str):
        return _sanitize_url(value)
    if isinstance(value, dict):
        cleaned = {}
        for child_key, child_value in value.items():
            result = _clean_value(child_value, node_type, str(child_key))
            if result is not None:
                cleaned[str(child_key)] = result
        return cleaned
    if isinstance(value, list):
        return [item for item in (_clean_value(child, node_type) for child in value) if item is not None]
    return value


def sanitize_graph(graph: dict) -> dict:
    """Return a deep-copied graph with credential-like values and local paths removed."""
    result = copy.deepcopy(graph)
    for node in result.get("nodes", []):
        if not isinstance(node, dict):
            continue
        config = node.get("config")
        node["config"] = _clean_value(config if isinstance(config, dict) else {}, str(node.get("type", "")))
    return result


def clone_graph(graph: dict, name: str) -> dict:
    """Create fresh node/edge identities; never execute a template as part of cloning."""
    result = copy.deepcopy(graph)
    result["name"] = name
    node_ids = {}
    for node in result.get("nodes", []):
        old_id = str(node.get("id", ""))
        new_id = str(uuid4())
        if old_id:
            node_ids[old_id] = new_id
        node["id"] = new_id
    for edge in result.get("edges", []):
        edge["id"] = str(uuid4())
        edge["source"] = node_ids.get(str(edge.get("source")), "")
        edge["target"] = node_ids.get(str(edge.get("target")), "")
    return result
