from pathlib import Path

from app.scanners.sca import _affected, scan_gradle_project


def test_scans_gradle_kotlin_literals_constants_and_gradle_properties(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        'val archiveFormatVersion = "1.25.0"\n'
        'val manifestVersion = providers.gradleProperty("legacyManifestJsonVersion").get()\n'
        'dependencies {\n'
        '    implementation("org.apache.commons:commons-text:1.9")\n'
        '    implementation("org.jsoup:jsoup:1.14.1")\n'
        '    implementation("org.apache.commons:commons-compress:$archiveFormatVersion")\n'
        '    add(\n'
        '        "implementation",\n'
        '        "commons-net:commons-net:3.8.0",\n'
        '    )\n'
        '    implementation("org.json:json:$manifestVersion")\n'
        '    implementation("org.apache.commons:commons-lang3:3.20.0")\n'
        '}\n',
        encoding="utf-8",
    )
    (project / "gradle.properties").write_text("legacyManifestJsonVersion=20230227\n", encoding="utf-8")

    findings = scan_gradle_project(project)

    assert {item["advisory_id"] for item in findings} == {
        "GHSA-599f-7c49-w659",
        "GHSA-m72m-mhq2-9p6c",
        "GHSA-4g9r-vxhx-9pgx",
        "GHSA-cgp8-4m63-fhh5",
        "GHSA-4jq9-2xhw-jpx7",
    }
    by_artifact = {item["artifact"]: item for item in findings}
    assert by_artifact["commons-text"]["line"] == 4
    assert by_artifact["commons-compress"]["version"] == "1.25.0"
    assert by_artifact["commons-net"]["line"] == 9
    assert by_artifact["json"]["version"] == "20230227"
    assert "commons-lang3" not in by_artifact


def test_gradle_lockfile_version_overrides_declared_version(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        'dependencies { implementation("org.apache.commons:commons-text:1.9") }\n',
        encoding="utf-8",
    )
    (project / "gradle.lockfile").write_text(
        "org.apache.commons:commons-text:1.10.0=runtimeClasspath\n",
        encoding="utf-8",
    )

    assert scan_gradle_project(project) == []


def test_numeric_advisory_range_boundaries():
    range_data = [{"lower": "1.5", "lowerInclusive": True, "upper": "1.10.0", "upperInclusive": False}]
    assert _affected("1.5", range_data)
    assert _affected("1.9", range_data)
    assert not _affected("1.10.0", range_data)
    assert not _affected("1.4.99", range_data)


def test_gradle_version_catalog_resolves_aliases_and_version_refs(tmp_path):
    project = tmp_path / "project"
    (project / "gradle").mkdir(parents=True)
    (project / "gradle" / "libs.versions.toml").write_text(
        '[versions]\n'
        'commonsText = "1.9"\n'
        'jsonVersion = { strictly = "20230227" }\n'
        '[libraries]\n'
        'commons-text = { module = "org.apache.commons:commons-text", version.ref = "commonsText" }\n'
        'json-lib = { group = "org.json", name = "json", version = { ref = "jsonVersion" } }\n'
        'unversioned-lib = { module = "org.apache.commons:commons-lang3" }\n',
        encoding="utf-8",
    )
    (project / "build.gradle.kts").write_text(
        'dependencies {\n'
        '    implementation(libs.commons.text)\n'
        '    api(libs.json.lib)\n'
        '    implementation(libs.unversioned.lib)\n'
        '    implementation(libs.unknown.alias)\n'
        '}\n',
        encoding="utf-8",
    )

    findings = scan_gradle_project(project)
    by_artifact = {item["artifact"]: item for item in findings}

    assert set(by_artifact) == {"commons-text", "json"}
    assert by_artifact["commons-text"]["version"] == "1.9"
    assert by_artifact["commons-text"]["line"] == 2
    assert by_artifact["json"]["version"] == "20230227"
    assert by_artifact["json"]["line"] == 3


def test_gradle_version_catalog_lockfile_version_takes_precedence(tmp_path):
    project = tmp_path / "project"
    (project / "gradle").mkdir(parents=True)
    (project / "gradle" / "libs.versions.toml").write_text(
        '[libraries]\n'
        'commons-text = { module = "org.apache.commons:commons-text", version = "1.9" }\n',
        encoding="utf-8",
    )
    (project / "build.gradle.kts").write_text(
        'dependencies { implementation(libs.commons.text) }\n',
        encoding="utf-8",
    )
    (project / "gradle.lockfile").write_text(
        "org.apache.commons:commons-text:1.10.0=runtimeClasspath\n",
        encoding="utf-8",
    )

    assert scan_gradle_project(project) == []


def test_malformed_gradle_version_catalog_is_ignored(tmp_path):
    project = tmp_path / "project"
    (project / "gradle").mkdir(parents=True)
    (project / "gradle" / "libs.versions.toml").write_text(
        '[libraries\ncommons-text = "not valid TOML"\n',
        encoding="utf-8",
    )
    (project / "build.gradle.kts").write_text(
        'dependencies { implementation(libs.commons.text) }\n',
        encoding="utf-8",
    )

    assert scan_gradle_project(project) == []


def test_gradle_subproject_uses_root_catalog_and_lockfile(tmp_path):
    project = tmp_path / "project"
    (project / "gradle").mkdir(parents=True)
    (project / "service").mkdir()
    (project / "gradle" / "libs.versions.toml").write_text(
        '[libraries]\n'
        'commons-text = { module = "org.apache.commons:commons-text", version = "1.9" }\n',
        encoding="utf-8",
    )
    (project / "service" / "build.gradle.kts").write_text(
        'dependencies { implementation(libs.commons.text) }\n',
        encoding="utf-8",
    )
    (project / "gradle.lockfile").write_text(
        "org.apache.commons:commons-text:1.10.0=runtimeClasspath\n",
        encoding="utf-8",
    )

    assert scan_gradle_project(project) == []
