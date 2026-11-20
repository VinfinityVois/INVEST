"""Static Gradle/Maven SCA scanner. Reads project metadata only; never runs Gradle."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

from app.config import settings
from app.scanners.secrets import MAX_FILE_BYTES, MAX_FILES, SKIP_DIRS

DATA_FILE = Path(__file__).resolve().parents[3] / "data" / "maven-advisories.json"
SPRING_BOOT_BOM_FILE = Path(__file__).resolve().parents[3] / "data" / "spring-boot-managed-versions.json"
DEPENDENCY_CALL = re.compile(
    r"(?P<call>\b[A-Za-z_]\w*\s*\(\s*(?P<quote>['\"])(?P<coordinate>[^'\"\r\n]+)(?P=quote)\s*\)"
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


def _load_lockfile_entries(path: Path) -> list[tuple[str, str, str, int]]:
    """Return every resolved module/version row from a Gradle lockfile."""
    entries = []
    text = _read_text(path)
    if text is None:
        return entries
    for line_number, line in enumerate(text.splitlines(), 1):
        match = LOCK_ENTRY.match(line.strip())
        if match:
            group, artifact, version, _configuration = match.groups()
            entries.append((group, artifact, version, line_number))
    return entries


def _load_lockfile(path: Path) -> dict[tuple[str, str], str]:
    """Return only unambiguous versions; configurations may resolve differently."""
    versions: dict[tuple[str, str], set[str]] = {}
    for group, artifact, version, _line in _load_lockfile_entries(path):
        versions.setdefault((group, artifact), set()).add(version)
    return {coordinate: next(iter(values)) for coordinate, values in versions.items() if len(values) == 1}


def _find_project_lockfile(build_dir: Path, project_root: Path) -> Path | None:
    """Find the nearest Gradle lockfile without traversing outside the project."""
    current = build_dir
    while current == project_root or project_root in current.parents:
        candidate = current / "gradle.lockfile"
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
        if current == project_root:
            break
        current = current.parent
    return None


def _load_project_lockfile(build_dir: Path, project_root: Path) -> dict[tuple[str, str], str]:
    path = _find_project_lockfile(build_dir, project_root)
    return _load_lockfile(path) if path else {}


def _catalog_alias_key(value: str) -> str:
    """Normalize Gradle catalog aliases and generated accessor paths."""
    return re.sub(r"[-_.]+", ".", value).strip(".")


def _load_version_catalog(path: Path) -> dict[str, object]:
    """Read Gradle's TOML version catalog without evaluating Gradle expressions."""
    text = _read_text(path)
    if text is None:
        return {}
    try:
        payload = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, TypeError):
        return {}

    versions = payload.get("versions", {})
    libraries = payload.get("libraries", {})
    bundles = payload.get("bundles", {})
    if not isinstance(versions, dict) or not isinstance(libraries, dict) or not isinstance(bundles, dict):
        return {}

    result: dict[str, object] = {}
    for alias, entry in libraries.items():
        if not isinstance(alias, str) or not isinstance(entry, dict):
            continue
        module = entry.get("module")
        group, artifact = None, None
        if isinstance(module, str) and module.count(":") == 1:
            group, artifact = module.split(":", 1)
        else:
            group, artifact = entry.get("group"), entry.get("name")
        if not isinstance(group, str) or not isinstance(artifact, str) or not group or not artifact:
            continue

        version = entry.get("version")
        if isinstance(version, str):
            resolved_version = version
        elif isinstance(version, dict):
            # "require" and "prefer" are selection constraints, not proof of the
            # resolved version. Only an exact numeric "strictly" value is safe
            # to use without a lockfile.
            resolved_version = None
            reference = version.get("ref")
            if isinstance(reference, str):
                candidate = versions.get(reference)
                if isinstance(candidate, dict):
                    candidate = candidate.get("strictly")
                if isinstance(candidate, str) and _numeric_version(candidate):
                    resolved_version = candidate
            else:
                candidate = version.get("strictly")
                if isinstance(candidate, str) and _numeric_version(candidate):
                    resolved_version = candidate
        elif isinstance(entry.get("version.ref"), str):
            candidate = versions.get(entry["version.ref"])
            if isinstance(candidate, dict):
                candidate = candidate.get("strictly")
            resolved_version = candidate if isinstance(candidate, str) and _numeric_version(candidate) else None
        else:
            resolved_version = None

        result[_catalog_alias_key(alias)] = (group, artifact, resolved_version if isinstance(resolved_version, str) else None)

    # Expand bundles only when every referenced library resolves uniquely.
    for bundle_name, aliases in bundles.items():
        if not isinstance(bundle_name, str) or not isinstance(aliases, list) or not aliases:
            continue
        expanded = []
        valid = True
        for library_alias in aliases:
            if not isinstance(library_alias, str):
                valid = False
                break
            dependency = result.get(_catalog_alias_key(library_alias))
            if not isinstance(dependency, tuple):
                valid = False
                break
            expanded.append(dependency)
        if valid:
            result[_catalog_alias_key(f"bundles.{bundle_name}")] = expanded
    return result


def _load_version_catalogs(project_root: Path, build_dir: Path) -> dict[str, dict[str, object]]:
    """Load conventional and statically declared custom Gradle version catalogs."""
    roots = {project_root / "gradle", build_dir / "gradle"}
    catalog_files: set[Path] = set()
    for directory in roots:
        if directory.is_dir() and not directory.is_symlink():
            try:
                catalog_files.update(path for path in directory.glob("*.versions.toml") if not path.is_symlink())
            except OSError:
                continue

    settings_text = ""
    for settings_file in (project_root / "settings.gradle", project_root / "settings.gradle.kts",
                          build_dir / "settings.gradle", build_dir / "settings.gradle.kts"):
        content = _read_text(settings_file)
        if content:
            settings_text += "\n" + content

    result: dict[str, dict[str, tuple[str, str, str | None]]] = {}
    for catalog_file in catalog_files:
        catalog_name = catalog_file.name.removesuffix(".versions.toml")
        declarations = re.findall(
            rf"\bcreate\s*\(\s*['\"]([A-Za-z_]\w*)['\"]\s*\)\s*\{{(?:(?!\}}).)*?from\s*\(\s*files\s*\(\s*['\"][^'\"]*{re.escape(catalog_file.name)}['\"]",
            settings_text,
            re.DOTALL,
        )
        if len(set(declarations)) == 1:
            catalog_name = declarations[0]
        elif len(set(declarations)) > 1 or catalog_file.name != "libs.versions.toml":
            # Gradle auto-imports only libs.versions.toml. Other catalogs must
            # be explicitly declared in settings.gradle(.kts).
            continue
        result[catalog_name] = _load_version_catalog(catalog_file)
    if "libs" not in result:
        default_catalog = project_root / "gradle" / "libs.versions.toml"
        if default_catalog.is_file():
            result["libs"] = _load_version_catalog(default_catalog)
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


def _load_spring_boot_boms(path: Path | None = None) -> dict[str, dict[tuple[str, str], str]]:
    """Load the curated, version-pinned Spring Boot managed-version snapshot."""
    source = path or SPRING_BOOT_BOM_FILE
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if payload.get("formatVersion") != 1 or payload.get("ecosystem") != "Maven":
        return {}
    result: dict[str, dict[tuple[str, str], str]] = {}
    for bom_version, entry in payload.get("boms", {}).items():
        if not isinstance(bom_version, str) or not isinstance(entry, dict):
            continue
        managed = entry.get("managed", {})
        if not isinstance(managed, dict):
            continue
        versions: dict[tuple[str, str], str] = {}
        for coordinate, version in managed.items():
            parsed = COORDINATE.match(coordinate) if isinstance(coordinate, str) else None
            if parsed and parsed.group(3) is None and isinstance(version, str) and _numeric_version(version):
                versions[(parsed.group(1), parsed.group(2))] = version
        if versions:
            result[bom_version] = versions
    return result


def _spring_boot_bom_versions(build_text: str, constants: dict[str, str], snapshots: dict[str, dict[tuple[str, str], str]]) -> dict[tuple[str, str], str]:
    """Resolve only explicit Spring Boot BOM imports covered by the local snapshot."""
    pattern = re.compile(
        r"\b(?:platform|enforcedPlatform|mavenBom)\s*\(\s*['\"]org\.springframework\.boot:spring-boot-dependencies:([^'\"]+)['\"]\s*\)"
    )
    versions: dict[tuple[str, str], set[str]] = {}
    for match in pattern.finditer(build_text):
        bom_version = re.sub(
            r"\$\{?([A-Za-z_]\w*)\}?",
            lambda item: constants.get(item.group(1), item.group(0)),
            match.group(1),
        )
        for coordinate, managed_version in snapshots.get(bom_version, {}).items():
            versions.setdefault(coordinate, set()).add(managed_version)
    # Conflicting imported BOMs are ambiguous; don't guess which one wins.
    return {coordinate: next(iter(values)) for coordinate, values in versions.items() if len(values) == 1}


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



MAVEN_TREE_COORDINATE = re.compile(
    r"(?P<group>[A-Za-z0-9_.-]+):(?P<artifact>[A-Za-z0-9_.-]+):(?P<type>[A-Za-z0-9_.-]+):(?:(?:[A-Za-z0-9_.-]+):)?(?P<version>[^:\s]+):(?P<scope>compile|runtime|test|provided|system|import)\b"
)


def _maven_child(element, name):
    if element is None:
        return None
    return next((child for child in list(element) if child.tag.rsplit("}", 1)[-1] == name), None)


def _maven_children(element, name):
    if element is None:
        return []
    return [child for child in list(element) if child.tag.rsplit("}", 1)[-1] == name]


def _maven_text(element, name):
    child = _maven_child(element, name)
    value = (child.text or "").strip() if child is not None else ""
    return value or None


def _maven_resolve(value, properties):
    if not value:
        return None
    result = value.strip()
    for _ in range(8):
        updated = re.sub(r"\$" + r"\{([^}]+)\}", lambda m: properties.get(m.group(1), m.group(0)), result)
        if updated == result:
            break
        result = updated
    return result if "$" + "{" not in result else None


def _maven_profile_sections(pom_path, pom):
    yield pom
    active = set()
    profiles = _maven_child(pom, "profiles")
    for profile in _maven_children(profiles, "profile"):
        activation = _maven_child(profile, "activation")
        if _maven_text(activation, "activeByDefault") == "true":
            profile_id = _maven_text(profile, "id")
            if profile_id:
                active.add(profile_id)
    config = _read_text(pom_path.parent / ".mvn" / "maven.config") or ""
    for match in re.finditer(r"(?:^|\s)-P(?:\s+|=)([A-Za-z0-9_,.-]+)", config):
        active.update(match.group(1).split(","))
    for profile in _maven_children(profiles, "profile"):
        if _maven_text(profile, "id") in active:
            yield profile


def _maven_managed(pom_path, pom, properties, snapshots=None):
    result: dict[tuple[str, str], set[str]] = {}
    snapshots = snapshots or {}
    for section in _maven_profile_sections(pom_path, pom):
        management = _maven_child(section, "dependencyManagement")
        dependencies = _maven_child(management, "dependencies")
        for dep in _maven_children(dependencies, "dependency"):
            group = _maven_resolve(_maven_text(dep, "groupId"), properties)
            artifact = _maven_resolve(_maven_text(dep, "artifactId"), properties)
            version = _maven_resolve(_maven_text(dep, "version"), properties)
            if not group or not artifact:
                continue
            if (_maven_text(dep, "type") or "jar") == "pom" and _maven_text(dep, "scope") == "import":
                if group == "org.springframework.boot" and artifact == "spring-boot-dependencies" and version:
                    for coordinate, managed_version in snapshots.get(version, {}).items():
                        result.setdefault(coordinate, set()).add(managed_version)
            elif version:
                result.setdefault((group, artifact), set()).add(version)
    return {key: next(iter(values)) for key, values in result.items() if len(values) == 1}


def _maven_properties(pom, inherited=None):
    values = dict(inherited or {})
    props = _maven_child(pom, "properties")
    for child in list(props) if props is not None else []:
        value = (child.text or "").strip()
        if value:
            values[child.tag.rsplit("}", 1)[-1]] = value
    for key, name in (("groupId", "project.groupId"), ("artifactId", "project.artifactId"), ("version", "project.version")):
        value = _maven_text(pom, key)
        if value:
            values.setdefault(name, value)
            values.setdefault("pom." + key, value)
    return values


def scan_maven_project(root: str | Path, advisories_path: Path | None = None, on_progress=None) -> list[dict]:
    project = Path(root).resolve()
    advisories = _load_advisories(advisories_path)
    bom_snapshots = _load_spring_boot_boms()
    findings = {}
    pom_files = [p for p in project.rglob("pom.xml") if not p.is_symlink() and not any(x in SKIP_DIRS for x in p.parts)][:MAX_FILES]
    tree_files = [p for p in project.rglob("*dependency-tree*.txt") if p.is_file() and not p.is_symlink() and not any(x in SKIP_DIRS for x in p.parts)][:max(0, MAX_FILES-len(pom_files))]
    total = len(pom_files) + len(tree_files)
    for index, pom_path in enumerate(pom_files, 1):
        source = _read_text(pom_path)
        if source is None:
            continue
        try:
            pom = ET.fromstring(source)
        except ET.ParseError:
            continue
        props = _maven_properties(pom)
        parent = _maven_child(pom, "parent")
        if parent is not None:
            rel = _maven_text(parent, "relativePath")
            parent_path = (pom_path.parent / (rel if rel is not None else "../pom.xml")).resolve()
            parent_source = _read_text(parent_path) if parent_path.is_file() and not parent_path.is_symlink() else None
            if parent_source:
                try:
                    props = _maven_properties(ET.fromstring(parent_source), props)
                except ET.ParseError:
                    pass
        managed = _maven_managed(pom_path, pom, props, bom_snapshots)
        relative = pom_path.relative_to(project).as_posix()
        for section in _maven_profile_sections(pom_path, pom):
            deps = _maven_child(section, "dependencies")
            for dep in _maven_children(deps, "dependency"):
                group = _maven_resolve(_maven_text(dep, "groupId"), props)
                artifact = _maven_resolve(_maven_text(dep, "artifactId"), props)
                version = _maven_resolve(_maven_text(dep, "version"), props)
                version = version or managed.get((group, artifact))
                if not group or not artifact or not version:
                    continue
                line_match = re.search(rf"<(?:[\w.-]+:)?groupId>\s*{re.escape(group)}\s*</(?:[\w.-]+:)?groupId>\s*<(?:[\w.-]+:)?artifactId>\s*{re.escape(artifact)}\s*</", source)
                line = source.count("\n", 0, line_match.start()) + 1 if line_match else 1
                for advisory in advisories.get((group, artifact), []):
                    if _affected(version, advisory.get("ranges", [])):
                        finding = _make_finding(group, artifact, version, advisory, relative, line)
                        findings.setdefault(finding["fingerprint"], finding)
        if on_progress:
            try:
                on_progress({"files_scanned": index, "total_files": total, "current_file": relative})
            except Exception:
                pass
    for index, tree_path in enumerate(tree_files, len(pom_files) + 1):
        source = _read_text(tree_path)
        if source is None:
            continue
        relative = tree_path.relative_to(project).as_posix()
        for line_no, line in enumerate(source.splitlines(), 1):
            for match in MAVEN_TREE_COORDINATE.finditer(line):
                group, artifact, version = match.group("group", "artifact", "version")
                for advisory in advisories.get((group, artifact), []):
                    if _affected(version, advisory.get("ranges", [])):
                        finding = _make_finding(group, artifact, version, advisory, relative, line_no)
                        findings.setdefault(finding["fingerprint"], finding)
        if on_progress:
            try:
                on_progress({"files_scanned": index, "total_files": total, "current_file": relative})
            except Exception:
                pass
    return sorted(findings.values(), key=lambda x: (x["path"], x["line"], x["rule_id"]))


def scan_project(root: str | Path, advisories_path: Path | None = None, on_progress=None) -> list[dict]:
    combined = scan_gradle_project(root, advisories_path=advisories_path, on_progress=on_progress)
    combined.extend(scan_maven_project(root, advisories_path=advisories_path, on_progress=on_progress))
    return sorted({x["fingerprint"]: x for x in combined}.values(), key=lambda x: (x["path"], x["line"], x["rule_id"]))


def scan_gradle_project(root: str | Path, advisories_path: Path | None = None, on_progress=None) -> list[dict]:
    project = Path(root).resolve()
    advisory_index = _load_advisories(advisories_path)
    bom_snapshots = _load_spring_boot_boms()
    findings: dict[str, dict] = {}
    candidates = [
        path for path in project.rglob("build.gradle*")
        if not any(part in SKIP_DIRS for part in path.parts) and not path.is_symlink()
    ][:MAX_FILES]
    total_files = len(candidates)
    declared_coordinates: set[tuple[str, str]] = set()
    lockfile_paths: set[Path] = set()

    for visited, build_file in enumerate(candidates, 1):
        build_text = _read_text(build_file)
        if build_text is None:
            continue

        properties = _load_properties(build_file.parent / "gradle.properties")
        constants = _resolve_variables(build_text, properties)
        lockfile_path = _find_project_lockfile(build_file.parent, project)
        locked = _load_lockfile(lockfile_path) if lockfile_path else {}
        if lockfile_path:
            lockfile_paths.add(lockfile_path)
        managed_versions = _spring_boot_bom_versions(build_text, constants, bom_snapshots)
        catalogs = _load_version_catalogs(project, build_file.parent)
        relative_path = build_file.relative_to(project).as_posix()

        for block_start, _block_end, block in _dependency_blocks(build_text):
            # Version-catalog accessors: default/custom catalogs and add("configuration", libs.alias).
            alias_pattern = re.compile(
                r"\b[A-Za-z_]\w*\s*\(\s*(?P<catalog>[A-Za-z_]\w*)((?:\.[A-Za-z_]\w*)+)\s*\)"
                r"|\badd\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(?P<add_catalog>[A-Za-z_]\w*)((?:\.[A-Za-z_]\w*)+)\s*\)"
            )
            for alias_match in alias_pattern.finditer(block):
                catalog_name = alias_match.group("catalog") or alias_match.group("add_catalog")
                accessor = alias_match.group(2) or alias_match.group(4)
                normalized = _catalog_alias_key(accessor.lstrip("."))
                catalog = catalogs.get(catalog_name, {})
                candidates = [entry for key, entry in catalog.items() if key == normalized]
                if len(candidates) != 1:
                    continue
                catalog_entries = candidates[0] if isinstance(candidates[0], list) else [candidates[0]]
                line = build_text.count("\n", 0, block_start + alias_match.start()) + 1
                for group, artifact, declared_version in catalog_entries:
                    declared_coordinates.add((group, artifact))
                    version = locked.get((group, artifact), declared_version or managed_versions.get((group, artifact)))
                    if not version or "$" in version:
                        continue
                    for advisory in advisory_index.get((group, artifact), []):
                        if _affected(version, advisory.get("ranges", [])):
                            finding = _make_finding(group, artifact, version, advisory, relative_path, line)
                            findings.setdefault(finding["fingerprint"], finding)

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
                declared_coordinates.add((group, artifact))
                version = locked.get((group, artifact), declared_version or managed_versions.get((group, artifact)))
                if not version or "$" in version:
                    continue
                coordinate_start = match.start("coordinate") if match.group("coordinate") is not None else match.start("add_coordinate")
                line = build_text.count("\n", 0, block_start + coordinate_start) + 1
                for advisory in advisory_index.get((group, artifact), []):
                    if _affected(version, advisory.get("ranges", [])):
                        finding = _make_finding(group, artifact, version, advisory, relative_path, line)
                        findings.setdefault(finding["fingerprint"], finding)
        if on_progress:
            try:
                on_progress({"files_scanned": visited, "total_files": total_files, "current_file": relative_path})
            except Exception:
                pass

    # Scan each lockfile once, after collecting direct coordinates from every module.
    for lockfile_path in sorted(lockfile_paths):
        lockfile_relative = lockfile_path.relative_to(project).as_posix()
        for group, artifact, version, lock_line in _load_lockfile_entries(lockfile_path):
            if (group, artifact) in declared_coordinates:
                continue
            for advisory in advisory_index.get((group, artifact), []):
                if _affected(version, advisory.get("ranges", [])):
                    finding = _make_finding(group, artifact, version, advisory, lockfile_relative, lock_line)
                    findings.setdefault(finding["fingerprint"], finding)

    return sorted(findings.values(), key=lambda item: (item["path"], item["line"], item["rule_id"]))
