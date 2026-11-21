"""Load the repository-owned built-in workflow preset catalog safely."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_MODULE_PATH = Path(__file__).resolve()
# In the repository, presets/ is next to backend/. In the Docker image,
# Dockerfile copies presets/ into /app/presets beside the application package.
_PRESET_ROOT_CANDIDATES = (_MODULE_PATH.parents[2] / "presets", _MODULE_PATH.parents[3] / "presets")
PRESETS_ROOT = next((candidate for candidate in _PRESET_ROOT_CANDIDATES if candidate.is_dir()), _PRESET_ROOT_CANDIDATES[0])
_PRESET_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_MAX_MANIFEST_BYTES = 128_000
_MAX_PRESET_BYTES = 512_000


class PresetError(ValueError):
    """Raised when the built-in preset catalog is malformed."""


def _read_json(path: Path, root: Path, max_bytes: int) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PresetError("Preset catalog entry is not a regular file")
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise PresetError("Preset path escapes the catalog root")
        if resolved.stat().st_size > max_bytes:
            raise PresetError("Preset file exceeds the size limit")
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PresetError(f"Cannot read preset catalog: {exc}") from exc
    if not isinstance(payload, dict):
        raise PresetError("Preset document must be a JSON object")
    return payload


def list_presets(root: Path = PRESETS_ROOT) -> list[dict[str, Any]]:
    catalog_root = Path(root).resolve()
    manifest = _read_json(catalog_root / "manifest.json", catalog_root, _MAX_MANIFEST_BYTES)
    if manifest.get("formatVersion") != 1 or not isinstance(manifest.get("presets"), list):
        raise PresetError("Unsupported preset manifest")
    result = []
    seen = set()
    for item in manifest["presets"]:
        if not isinstance(item, dict):
            raise PresetError("Invalid preset manifest entry")
        preset_id, filename = item.get("id"), item.get("file")
        if not isinstance(preset_id, str) or not _PRESET_ID.fullmatch(preset_id) or preset_id in seen:
            raise PresetError("Invalid or duplicate preset id")
        if not isinstance(filename, str) or Path(filename).name != filename or not filename.endswith(".json"):
            raise PresetError(f"Invalid preset file for {preset_id}")
        if not isinstance(item.get("name"), str) or not item["name"].strip():
            raise PresetError(f"Missing preset name for {preset_id}")
        seen.add(preset_id)
        result.append({
            "id": preset_id,
            "name": item["name"][:120],
            "version": item.get("version", 1),
            "category": str(item.get("category", "general"))[:60],
            "description": str(item.get("description", ""))[:1000],
            "tags": [str(tag)[:40] for tag in item.get("tags", []) if isinstance(tag, str)][:20],
            "setup_required": [str(field)[:120] for field in item.get("setup_required", []) if isinstance(field, str)][:20],
            "node_count": item.get("node_count", 0),
            "file": filename,
        })
    return result


def load_preset(preset_id: str, root: Path = PRESETS_ROOT) -> dict[str, Any]:
    if not isinstance(preset_id, str) or not _PRESET_ID.fullmatch(preset_id):
        raise PresetError("Invalid preset id")
    catalog_root = Path(root).resolve()
    metadata = next((item for item in list_presets(catalog_root) if item["id"] == preset_id), None)
    if metadata is None:
        raise PresetError(f"Unknown preset: {preset_id}")
    payload = _read_json(catalog_root / metadata["file"], catalog_root, _MAX_PRESET_BYTES)
    if not isinstance(payload.get("nodes"), list) or not isinstance(payload.get("edges"), list):
        raise PresetError(f"Preset graph is malformed: {preset_id}")
    graph = {
        "name": str(payload.get("name") or metadata["name"])[:200],
        "nodes": payload["nodes"],
        "edges": payload["edges"],
    }
    return {**metadata, "graph": graph}
