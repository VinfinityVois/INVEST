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
        # Strip user-info, query and fragment; preserve only a public host/path reference.
        host = parsed.hostname
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    except (ValueError, TypeError):
        return ""


def sanitize_graph(graph: dict) -> dict:
    """Return a deep-copied graph with credential-like values and local paths removed."""
    result = copy.deepcopy(graph)
    for node in result.get("nodes", []):
        if not isinstance(node, dict):
            continue
        node_type = str(node.get("type", ""))
        config = node.get("config")
        if not isinstance(config, dict):
            node["config"] = {}
            continue
        cleaned = {}
        for key, value in config.items():
            key_text = str(key)
            if SENSITIVE_KEY.search(key_text):
                continue
            if node_type == "notify.webhook" and key_text.lower() in {"url", "endpoint", "webhook"}:
                continue
            if node_type == "source.upload" and key_text.lower() in {"path", "workspace_path"}:
                continue
            if node_type == "source.git" and key_text.lower() == "url" and isinstance(value, str):
                cleaned[key_text] = _sanitize_url(value)
                continue
            cleaned[key_text] = value
        node["config"] = cleaned
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
