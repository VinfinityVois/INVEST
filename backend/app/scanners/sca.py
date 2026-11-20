"""Static Gradle/Maven SCA scanner. Reads project metadata only; never runs Gradle."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path

from app.config import settings
from app.scanners.secrets import MAX_FILE_BYTES, MAX_FILES, SKIP_DIRS

DATA_FILE = Path(__file__).resolve().parents[3] / "data" / "maven-advisories.json"
DEPENDENCY_CALL = re.compile(
    r"(?P<call>\b(?:implementation|api|runtimeOnly|compileOnly|testImplementation|testRuntimeOnly|runtimeClasspath|compileClasspath)\s*\(\s*"
    r"(?P<quote>['\"])(?P<coordinate>[^'\"\r\n]+)(?P=quote)\s*\)"
    r"|\badd\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"](?P<add_coordinate>[^'\"\r\n]+)['\"]\s*,?\s*\))",
    re.MULTILINE | re.DOTALL,
)
COORDINATE = re.compile(r"^([^:\s]+):([^:\s]+)(?::([^:\s]+))?$")
CONSTANT = re.compile(r"(?m)^\s*(?:val|def)\s+([A-Za-z_]\w*)\s*=\s*['\"]([^'\"]+)['\"]")
PROPERTY_CONSTANT = re.compile(
    r'(?m)^\s*(?:val|def)\s+([A-Za-z_]\w*)\s*=\s*providers\.gradleProperty\(["\']([^"\']+)["\']\)\.get\(\)'
)
LOCK_ENTRY = re.compile(r"^([^:#=]+):([^:#=]+):([^=]+)=([^\s]+)$")


def _read_text(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _dependency_blocks(text: str):
    for match in re.finditer(r"\bdependencies\s*\{", text):
        start = match.end()
        depth = 1
        quote = None
        escaped = False
        index = start
        while index < len(text) and depth:
            char = text[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in {"'", '"'}:
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            index += 1
        if depth == 0:
            yield start, index - 1, text[start:index - 1]


def _load_properties(path: Path) -> dict[str, str]:
    result = {}
    text = _read_text(path)
    if text is None:
        return result
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def _resolve_variables(build_text: str, properties: dict[str, str]) -> dict[str, str]:
    values = {name: value for name, value in CONSTANT.findall(build_text)}
    for name, property_name in PROPERTY_CONSTANT.findall(build_text):
        if property_name in properties:
            values[name] = properties[property_name]
    return values


def _load_lockfile(path: Path) -> dict[tuple[str, str], str]:
    result = {}
    text = _read_text(path)
    if text is None:
        return result
    for line in text.splitlines():
        match = LOCK_ENTRY.match(line.strip())
        if match:
            group, artifact, version, _configuration = match.groups()
            result[(group, artifact)] = version
    return result


def _numeric_version(value: str) -> tuple[int, ...] | None:
    if not re.fullmatch(r"\d+(?:\.\d+)*", value):
        return None
    return tuple(int(part) for part in value.split("."))


def _compare_versions(left: str, right: str) -> int | None:
    a, b = _numeric_version(left), _numeric_version(right)
    if a is None or b is None:
        return None
    width = max(len(a), len(b))
    a += (0,) * (width - len(a))
    b += (0,) * (width - len(b))
    return (a > b) - (a < b)


def _affected(version: str, ranges: list[dict]) -> bool:
    for item in ranges:
        lower = item.get("lower")
        upper = item.get("upper")
        if lower is not None:
            comparison = _compare_versions(version, lower)
            if comparison is None or comparison < 0 or (comparison == 0 and not item.get("lowerInclusive", False)):
                continue
        if upper is not None:
            comparison = _compare_versions(version, upper)
            if comparison is None or comparison > 0 or (comparison == 0 and not item.get("upperInclusive", False)):
                continue
        return True
    return False


def _load_advisories(path: Path | None = None) -> dict[tuple[str, str], list[dict]]:
    source = path or DATA_FILE
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    index: dict[tuple[str, str], list[dict]] = {}
    if payload.get("ecosystem") != "Maven" or payload.get("formatVersion") != 1:
        return {}
    for advisory in payload.get("vulnerabilities", []):
        key = (advisory.get("group"), advisory.get("artifact"))
        if not all(key):
            continue
        index.setdefault(key, []).append(advisory)
    return index


def _make_finding(group: str, artifact: str, version: str, advisory: dict, path: str, line: int) -> dict:
    rule_id = f"sca.maven.{group}.{artifact}.{advisory['id']}"
    identity = f"{rule_id}:{path}:{line}:{version}"
    fingerprint = hmac.new(settings.app_secret_key.encode(), identity.encode(), hashlib.sha256).hexdigest()
    fixed = advisory.get("fixedVersions", [])
    aliases = advisory.get("aliases", [])
    ids = [advisory["id"], *aliases]
    return {
        "rule_id": rule_id,
        "class": "dependency-vulnerability",
        "category": "SCA",
        "path": path,
        "line": line,
        "severity": advisory.get("severity", "MEDIUM"),
        "confidence": 0.99,
        "message": f"{group}:{artifact}:{version} попадает в опубликованный диапазон {advisory['id']}.",
        "group": group,
        "artifact": artifact,
        "version": version,
        "advisory_id": advisory["id"],
        "cve": next((value for value in aliases if value.startswith("CVE-")), None),
        "aliases": aliases,
        "fixed_versions": fixed,
        "affected_ranges": advisory.get("ranges", []),
        "sources": advisory.get("sources", []),
        "fingerprint": fingerprint,
    }


def scan_gradle_project(root: str | Path, advisories_path: Path | None = None) -> list[dict]:
    project = Path(root).resolve()
    advisory_index = _load_advisories(advisories_path)
    findings: dict[str, dict] = {}
    visited = 0

    for build_file in project.rglob("build.gradle*"):
        if any(part in SKIP_DIRS for part in build_file.parts) or build_file.is_symlink():
            continue
        visited += 1
        if visited > MAX_FILES:
            break
        build_text = _read_text(build_file)
        if build_text is None:
            continue

        properties = _load_properties(build_file.parent / "gradle.properties")
        constants = _resolve_variables(build_text, properties)
        locked = _load_lockfile(build_file.parent / "gradle.lockfile")
        relative_path = build_file.relative_to(project).as_posix()

        for block_start, _block_end, block in _dependency_blocks(build_text):
            for match in DEPENDENCY_CALL.finditer(block):
                coordinate = match.group("coordinate") or match.group("add_coordinate")
                if not coordinate:
                    continue
                coordinate = re.sub(
                    r"\$\{?([A-Za-z_]\w*)\}?",
                    lambda item: constants.get(item.group(1), item.group(0)),
                    coordinate,
                )
                parsed = COORDINATE.match(coordinate)
                if not parsed:
                    continue
                group, artifact, declared_version = parsed.groups()
                version = locked.get((group, artifact), declared_version)
                if not version or "$" in version:
                    continue
                coordinate_start = match.start("coordinate") if match.group("coordinate") is not None else match.start("add_coordinate")
                line = build_text.count("\n", 0, block_start + coordinate_start) + 1
                for advisory in advisory_index.get((group, artifact), []):
                    if _affected(version, advisory.get("ranges", [])):
                        finding = _make_finding(group, artifact, version, advisory, relative_path, line)
                        findings.setdefault(finding["fingerprint"], finding)

    return sorted(findings.values(), key=lambda item: (item["path"], item["line"], item["rule_id"]))
