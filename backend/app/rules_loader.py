"""Load trusted, repository-owned rule packs without executing rule content."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


RULES_ROOT = Path(__file__).resolve().parents[2] / "rules"
_PACK_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_MAX_PACK_BYTES = 512_000
_MAX_RULES_PER_PACK = 500
_MAX_REGEX_LENGTH = 400


class RulePackError(ValueError):
    """Raised when a built-in rule pack is malformed or incompatible."""


class RulePackRegistry:
    def __init__(self, root: Path = RULES_ROOT):
        self.root = Path(root).resolve()
        self._packs: dict[str, dict[str, Any]] = {}
        self._paths: dict[str, Path] = {}
        self.reload()

    def reload(self) -> None:
        packs: dict[str, dict[str, Any]] = {}
        paths: dict[str, Path] = {}
        if not self.root.exists():
            self._packs, self._paths = {}, {}
            return
        for path in sorted(self.root.rglob("*")):
            if path.suffix.lower() not in {".yml", ".yaml", ".json"}:
                continue
            if path.is_symlink() or not path.is_file():
                continue
            try:
                if not path.resolve(strict=True).is_relative_to(self.root):
                    continue
                if path.stat().st_size > _MAX_PACK_BYTES:
                    raise RulePackError(f"Rule pack is too large: {path.name}")
                raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
                raise RulePackError(f"Cannot read rule pack {path.name}: {exc}") from exc
            if not isinstance(raw, dict) or not raw.get("pack_id"):
                # Historical descriptive files without pack_id remain inert.
                continue
            pack_id = raw["pack_id"]
            if not isinstance(pack_id, str) or not _PACK_ID.fullmatch(pack_id):
                raise RulePackError(f"Invalid pack_id in {path.name}")
            if pack_id in packs:
                raise RulePackError(f"Duplicate rule pack id: {pack_id}")
            analyzer = raw.get("analyzer")
            if analyzer not in {"secrets", "sca", "sast", "policy"}:
                raise RulePackError(f"Unsupported analyzer for {pack_id}")
            packs[pack_id] = raw
            paths[pack_id] = path
        self._packs, self._paths = packs, paths
        # Resolve every pack at load time so broken inheritance fails early.
        for pack_id in packs:
            self.resolve([pack_id])

    def _resolve_one(self, pack_id: str, stack: tuple[str, ...]) -> dict[str, Any]:
        if pack_id in stack:
            raise RulePackError("Rule pack inheritance cycle: " + " -> ".join((*stack, pack_id)))
        raw = self._packs.get(pack_id)
        if raw is None:
            raise RulePackError(f"Unknown rule pack: {pack_id}")
        merged = dict(raw)
        patterns: dict[str, dict[str, Any]] = {}
        rules: dict[str, dict[str, Any]] = {}
        for parent_id in raw.get("extends", []):
            if not isinstance(parent_id, str):
                raise RulePackError(f"Invalid extends entry in {pack_id}")
            parent = self._resolve_one(parent_id, (*stack, pack_id))
            if parent["analyzer"] != raw["analyzer"]:
                raise RulePackError(f"Analyzer mismatch in {pack_id} extends {parent_id}")
            for item in parent.get("patterns", []):
                patterns[item["id"]] = item
            for item in parent.get("rules", []):
                rules[item["id"]] = item
        for key, target in (("patterns", patterns), ("rules", rules)):
            entries = raw.get(key, [])
            if not isinstance(entries, list):
                raise RulePackError(f"{pack_id}.{key} must be a list")
            for item in entries:
                if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                    raise RulePackError(f"Invalid {key} entry in {pack_id}")
                target[item["id"]] = item
            if len(target) > _MAX_RULES_PER_PACK:
                raise RulePackError(f"Too many rules in {pack_id}")
            merged[key] = list(target.values())
        return merged

    def resolve(self, pack_ids: list[str] | None = None, analyzer: str | None = None) -> list[dict[str, Any]]:
        selected = list(dict.fromkeys(pack_ids or []))
        if not selected:
            selected = [
                pack_id for pack_id, raw in sorted(self._packs.items())
                if raw.get("analyzer") == analyzer and not raw.get("extends")
            ][:1]
        resolved = []
        for pack_id in selected:
            pack = self._resolve_one(pack_id, ())
            if analyzer and pack["analyzer"] != analyzer:
                raise RulePackError(f"Pack {pack_id} is for {pack['analyzer']}, not {analyzer}")
            for pattern in pack.get("patterns", []):
                expression = pattern.get("regex")
                if not isinstance(expression, str) or not expression or len(expression) > _MAX_REGEX_LENGTH:
                    raise RulePackError(f"Invalid regex in {pack_id}:{pattern.get('id')}")
                try:
                    re.compile(expression)
                except re.error as exc:
                    raise RulePackError(f"Invalid regex in {pack_id}:{pattern.get('id')}: {exc}") from exc
            resolved.append(pack)
        return resolved

    def list(self, analyzer: str | None = None) -> list[dict[str, Any]]:
        result = []
        for pack_id, raw in sorted(self._packs.items()):
            if analyzer and raw["analyzer"] != analyzer:
                continue
            resolved = self._resolve_one(pack_id, ())
            result.append({
                "id": pack_id,
                "title": str(raw.get("title", pack_id))[:120],
                "analyzer": raw["analyzer"],
                "version": raw.get("version", 1),
                "rule_count": len(resolved.get("patterns", [])) + len(resolved.get("rules", [])),
                "extends": list(raw.get("extends", [])),
            })
        return result


rule_packs = RulePackRegistry()
