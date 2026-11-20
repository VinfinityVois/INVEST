from pathlib import Path

from app.scanners.sca import _affected, scan_gradle_project, scan_maven_project, scan_project


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


def test_spring_boot_bom_supplies_versions_for_unversioned_dependencies(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        'val bootBomVersion = "3.2.0"\n'
        'dependencies {\n'
        '    implementation(platform("org.springframework.boot:spring-boot-dependencies:$bootBomVersion"))\n'
        '    implementation("org.apache.commons:commons-lang3")\n'
        '    implementation("com.fasterxml.jackson.core:jackson-databind")\n'
        '    implementation("com.google.code.gson:gson")\n'
        '}\n',
        encoding="utf-8",
    )

    findings = scan_gradle_project(project)
    by_artifact = {item["artifact"]: item for item in findings}

    assert by_artifact["commons-lang3"]["version"] == "3.13.0"
    assert by_artifact["jackson-databind"]["version"] == "2.15.3"
    assert "gson" not in by_artifact


def test_spring_boot_bom_does_not_override_explicit_or_locked_versions(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        'dependencies {\n'
        '    implementation(enforcedPlatform("org.springframework.boot:spring-boot-dependencies:3.2.0"))\n'
        '    implementation("org.apache.commons:commons-lang3:3.20.0")\n'
        '    implementation("com.fasterxml.jackson.core:jackson-databind")\n'
        '}\n',
        encoding="utf-8",
    )
    (project / "gradle.lockfile").write_text(
        "com.fasterxml.jackson.core:jackson-databind:2.18.8=runtimeClasspath\n",
        encoding="utf-8",
    )

    assert scan_gradle_project(project) == []


def test_spring_boot_bom_unknown_version_is_not_guessed(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        'dependencies {\n'
        '    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.6.0"))\n'
        '    implementation("org.apache.commons:commons-lang3")\n'
        '}\n',
        encoding="utf-8",
    )

    assert scan_gradle_project(project) == []


def test_gradle_lockfile_scans_vulnerable_transitive_dependencies(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        'dependencies { implementation("org.springframework.boot:spring-boot-starter-web:3.2.0") }\n',
        encoding="utf-8",
    )
    (project / "gradle.lockfile").write_text(
        '# This is a Gradle lockfile\n'
        'org.springframework.boot:spring-boot-starter-web:3.2.0=runtimeClasspath\n'
        'org.apache.commons:commons-lang3:3.17.0=runtimeClasspath\n'
        'org.yaml:snakeyaml:2.2=runtimeClasspath\n',
        encoding="utf-8",
    )

    findings = scan_gradle_project(project)

    assert len(findings) == 1
    assert findings[0]["artifact"] == "commons-lang3"
    assert findings[0]["version"] == "3.17.0"
    assert findings[0]["path"] == "gradle.lockfile"
    assert findings[0]["line"] == 3


def test_gradle_lockfile_does_not_duplicate_direct_dependency_findings(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        'dependencies { implementation("org.apache.commons:commons-lang3:3.17.0") }\n',
        encoding="utf-8",
    )
    (project / "gradle.lockfile").write_text(
        "org.apache.commons:commons-lang3:3.17.0=runtimeClasspath\n",
        encoding="utf-8",
    )

    findings = scan_gradle_project(project)

    assert len(findings) == 1
    assert findings[0]["path"] == "build.gradle.kts"


def test_gradle_lockfile_ambiguous_versions_are_not_used_as_override(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        'dependencies { implementation("org.apache.commons:commons-lang3") }\n',
        encoding="utf-8",
    )
    (project / "gradle.lockfile").write_text(
        "org.apache.commons:commons-lang3:3.17.0=runtimeClasspath\n"
        "org.apache.commons:commons-lang3:3.20.0=testRuntimeClasspath\n",
        encoding="utf-8",
    )

    assert scan_gradle_project(project) == []


def test_root_lockfile_does_not_duplicate_direct_findings_across_subprojects(tmp_path):
    project = tmp_path / "project"
    (project / "service-a").mkdir(parents=True)
    (project / "service-b").mkdir()
    (project / "service-a" / "build.gradle.kts").write_text(
        'dependencies { implementation("org.apache.commons:commons-lang3:3.17.0") }\n',
        encoding="utf-8",
    )
    (project / "service-b" / "build.gradle.kts").write_text(
        'dependencies { }\n',
        encoding="utf-8",
    )
    (project / "gradle.lockfile").write_text(
        "org.apache.commons:commons-lang3:3.17.0=runtimeClasspath\n",
        encoding="utf-8",
    )

    findings = scan_gradle_project(project)

    assert len(findings) == 1
    assert findings[0]["path"] == "service-a/build.gradle.kts"


def test_spring_boot_bom_35_snapshot_uses_tagged_managed_versions(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        'dependencies {\n'
        '    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.5.0"))\n'
        '    implementation("org.apache.commons:commons-lang3")\n'
        '    implementation("com.fasterxml.jackson.core:jackson-databind")\n'
        '    implementation("com.google.code.gson:gson")\n'
        '}\n',
        encoding="utf-8",
    )

    findings = scan_gradle_project(project)
    by_artifact = {item["artifact"]: item for item in findings}

    assert by_artifact["commons-lang3"]["version"] == "3.17.0"
    assert by_artifact["jackson-databind"]["version"] == "2.19.0"
    assert "gson" not in by_artifact


def test_gradle_custom_catalog_and_nonstandard_configuration_are_scanned(tmp_path):
    project = tmp_path / "project"
    (project / "gradle").mkdir(parents=True)
    (project / "settings.gradle.kts").write_text(
        'dependencyResolutionManagement {\n'
        '  versionCatalogs {\n'
        '    create("quality") { from(files("gradle/quality.versions.toml")) }\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    (project / "gradle" / "quality.versions.toml").write_text(
        '[libraries]\n'
        'commons = { module = "org.apache.commons:commons-lang3", version = "3.17.0" }\n',
        encoding="utf-8",
    )
    (project / "build.gradle.kts").write_text(
        'dependencies {\n'
        '  kapt(quality.commons)\n'
        '}\n',
        encoding="utf-8",
    )

    findings = scan_gradle_project(project)

    assert len(findings) == 1
    assert findings[0]["artifact"] == "commons-lang3"
    assert findings[0]["version"] == "3.17.0"


def test_gradle_add_configuration_accepts_version_catalog_accessor(tmp_path):
    project = tmp_path / "project"
    (project / "gradle").mkdir(parents=True)
    (project / "gradle" / "libs.versions.toml").write_text(
        '[libraries]\n'
        'commons = { module = "org.apache.commons:commons-lang3", version = "3.17.0" }\n',
        encoding="utf-8",
    )
    (project / "build.gradle.kts").write_text(
        'dependencies { add("annotationProcessor", libs.commons) }\n',
        encoding="utf-8",
    )

    findings = scan_gradle_project(project)

    assert len(findings) == 1
    assert findings[0]["artifact"] == "commons-lang3"
    assert findings[0]["version"] == "3.17.0"


def test_gradle_unknown_custom_catalog_is_not_guessed(tmp_path):
    project = tmp_path / "project"
    (project / "gradle").mkdir(parents=True)
    (project / "gradle" / "quality.versions.toml").write_text(
        '[libraries]\n'
        'commons = { module = "org.apache.commons:commons-lang3", version = "3.17.0" }\n',
        encoding="utf-8",
    )
    (project / "build.gradle.kts").write_text(
        'dependencies { kapt(quality.commons) }\n',
        encoding="utf-8",
    )

    assert scan_gradle_project(project) == []


def test_gradle_catalog_prefer_and_range_are_not_treated_as_resolved_versions(tmp_path):
    project = tmp_path / "project"
    (project / "gradle").mkdir(parents=True)
    (project / "gradle" / "libs.versions.toml").write_text(
        '[versions]\n'
        'preferred = { prefer = "3.17.0" }\n'
        'bounded = { strictly = "[3.0, 4.0)" }\n'
        '[libraries]\n'
        'preferred-commons = { module = "org.apache.commons:commons-lang3", version.ref = "preferred" }\n'
        'bounded-commons = { module = "org.apache.commons:commons-lang3", version.ref = "bounded" }\n',
        encoding="utf-8",
    )
    (project / "build.gradle.kts").write_text(
        'dependencies {\n'
        '  implementation(libs.preferred.commons)\n'
        '  implementation(libs.bounded.commons)\n'
        '}\n',
        encoding="utf-8",
    )

    assert scan_gradle_project(project) == []


def test_gradle_catalog_strict_exact_version_is_usable_without_lockfile(tmp_path):
    project = tmp_path / "project"
    (project / "gradle").mkdir(parents=True)
    (project / "gradle" / "libs.versions.toml").write_text(
        '[versions]\n'
        'commons = { strictly = "3.17.0", prefer = "3.20.0" }\n'
        '[libraries]\n'
        'commons = { module = "org.apache.commons:commons-lang3", version.ref = "commons" }\n',
        encoding="utf-8",
    )
    (project / "build.gradle.kts").write_text(
        'dependencies { implementation(libs.commons) }\n',
        encoding="utf-8",
    )

    findings = scan_gradle_project(project)

    assert len(findings) == 1
    assert findings[0]["version"] == "3.17.0"


def test_gradle_version_catalog_bundle_expands_to_vulnerable_libraries(tmp_path):
    project = tmp_path / "project"
    (project / "gradle").mkdir(parents=True)
    (project / "gradle" / "libs.versions.toml").write_text(
        '[libraries]\n'
        'commons = { module = "org.apache.commons:commons-lang3", version = "3.17.0" }\n'
        '[bundles]\n'
        'backend = ["commons"]\n',
        encoding="utf-8",
    )
    (project / "build.gradle.kts").write_text(
        'dependencies { implementation(libs.bundles.backend) }\n',
        encoding="utf-8",
    )

    findings = scan_gradle_project(project)

    assert len(findings) == 1
    assert findings[0]["artifact"] == "commons-lang3"
    assert findings[0]["version"] == "3.17.0"


def test_gradle_version_catalog_bundle_with_unknown_alias_is_ignored(tmp_path):
    project = tmp_path / "project"
    (project / "gradle").mkdir(parents=True)
    (project / "gradle" / "libs.versions.toml").write_text(
        '[libraries]\n'
        'commons = { module = "org.apache.commons:commons-lang3", version = "3.17.0" }\n'
        '[bundles]\n'
        'backend = ["commons", "missing-library"]\n',
        encoding="utf-8",
    )
    (project / "build.gradle.kts").write_text(
        'dependencies { implementation(libs.bundles.backend) }\n',
        encoding="utf-8",
    )

    assert scan_gradle_project(project) == []


def test_maven_pom_resolves_properties_and_dependency_management(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "pom.xml").write_text(
        "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
        "<modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>app</artifactId><version>1</version>"
        "<properties><jackson.version>2.9.10.3</jackson.version></properties>"
        "<dependencyManagement><dependencies>"
        "<dependency><groupId>com.google.code.gson</groupId><artifactId>gson</artifactId><version>2.8.8</version></dependency>"
        "</dependencies></dependencyManagement>"
        "<dependencies>"
        "<dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>$" "{jackson.version}</version></dependency>"
        "<dependency><groupId>com.google.code.gson</groupId><artifactId>gson</artifactId></dependency>"
        "</dependencies></project>",
        encoding="utf-8",
    )

    findings = scan_maven_project(project)

    assert {item["artifact"] for item in findings} == {"jackson-databind", "gson"}
    assert {item["version"] for item in findings} >= {"2.9.10.3", "2.8.8"}
    assert all(item["path"] == "pom.xml" for item in findings)


def test_maven_spring_boot_bom_supplies_managed_versions(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>app</artifactId>"
        "<dependencyManagement><dependencies><dependency>"
        "<groupId>org.springframework.boot</groupId><artifactId>spring-boot-dependencies</artifactId>"
        "<version>3.5.0</version><type>pom</type><scope>import</scope>"
        "</dependency></dependencies></dependencyManagement>"
        "<dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId>"
        "<artifactId>jackson-databind</artifactId></dependency></dependencies></project>",
        encoding="utf-8",
    )

    findings = scan_maven_project(project)

    assert any(item["artifact"] == "jackson-databind" and item["version"] == "2.19.0" for item in findings)


def test_maven_profiles_only_scan_active_by_default_or_explicit_profiles(tmp_path):
    project = tmp_path / "project"
    (project / ".mvn").mkdir(parents=True)
    (project / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>app</artifactId>"
        "<profiles>"
        "<profile><id>default-vulnerable</id><activation><activeByDefault>true</activeByDefault></activation>"
        "<dependencies><dependency><groupId>com.google.code.gson</groupId><artifactId>gson</artifactId><version>2.8.8</version></dependency></dependencies></profile>"
        "<profile><id>prod-vulnerable</id><properties><jackson.profile.version>2.9.10.3</jackson.profile.version></properties>"
        "<dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId>"
        "<artifactId>jackson-databind</artifactId><version>$" "{jackson.profile.version}</version></dependency></dependencies></profile>"
        "</profiles></project>",
        encoding="utf-8",
    )
    assert {item["artifact"] for item in scan_maven_project(project)} == {"gson"}
    (project / ".mvn" / "maven.config").write_text("-P prod-vulnerable\n", encoding="utf-8")

    findings = scan_maven_project(project)

    assert {item["artifact"] for item in findings} == {"jackson-databind"}


def test_maven_dependency_tree_finds_transitive_dependencies(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "dependency-tree.txt").write_text(
        "demo:app:jar:1.0:compile\n"
        "+- org.apache.commons:commons-text:jar:1.9:compile\n"
        "\\- org.apache.commons:commons-lang3:jar:3.17.0:runtime\n",
        encoding="utf-8",
    )

    findings = scan_maven_project(project)

    assert any(item["artifact"] == "commons-text" and item["version"] == "1.9" for item in findings)
    assert all(item["path"] == "dependency-tree.txt" for item in findings)


def test_maven_unresolved_versions_and_inactive_profiles_are_not_guessed(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>app</artifactId>"
        "<dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId>"
        "<artifactId>jackson-databind</artifactId><version>$" "{missing.version}</version></dependency></dependencies>"
        "<profiles><profile><id>inactive</id><dependencies><dependency>"
        "<groupId>com.google.code.gson</groupId><artifactId>gson</artifactId><version>2.8.8</version>"
        "</dependency></dependencies></profile></profiles></project>",
        encoding="utf-8",
    )

    assert scan_maven_project(project) == []


def test_combined_sca_scans_gradle_and_maven_projects(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle").write_text(
        'dependencies { implementation("org.apache.commons:commons-text:1.9") }\n',
        encoding="utf-8",
    )
    (project / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>app</artifactId>"
        "<dependencies><dependency><groupId>com.google.code.gson</groupId><artifactId>gson</artifactId>"
        "<version>2.8.8</version></dependency></dependencies></project>",
        encoding="utf-8",
    )

    findings = scan_project(project)

    assert {item["artifact"] for item in findings} == {"commons-text", "gson"}


def test_maven_parent_relative_path_cannot_read_outside_project(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>parent</artifactId>"
        "<properties><inherited.version>2.9.10.3</inherited.version></properties></project>",
        encoding="utf-8",
    )
    project = tmp_path / "project"
    project.mkdir()
    (project / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>demo</groupId>"
        "<artifactId>parent</artifactId><version>1</version><relativePath>../outside/pom.xml</relativePath>"
        "</parent><artifactId>app</artifactId><dependencies><dependency>"
        "<groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId>"
        "<version>$" "{inherited.version}</version></dependency></dependencies></project>",
        encoding="utf-8",
    )

    assert scan_maven_project(project) == []


def test_maven_child_inherits_parent_dependency_management(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "parent-pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>parent</artifactId>"
        "<version>1</version><dependencyManagement><dependencies><dependency>"
        "<groupId>com.google.code.gson</groupId><artifactId>gson</artifactId><version>2.8.8</version>"
        "</dependency></dependencies></dependencyManagement></project>",
        encoding="utf-8",
    )
    (project / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>demo</groupId><artifactId>parent</artifactId>"
        "<version>1</version><relativePath>parent-pom.xml</relativePath></parent><artifactId>app</artifactId>"
        "<dependencies><dependency><groupId>com.google.code.gson</groupId><artifactId>gson</artifactId>"
        "</dependency></dependencies></project>",
        encoding="utf-8",
    )

    findings = scan_maven_project(project)

    assert any(item["artifact"] == "gson" and item["version"] == "2.8.8" for item in findings)


def test_maven_inherits_dependency_management_through_multiple_local_parents(tmp_path):
    project = tmp_path / "project"
    (project / "module").mkdir(parents=True)
    (project / "grandparent.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>grandparent</artifactId>"
        "<version>1</version><dependencyManagement><dependencies><dependency>"
        "<groupId>com.google.code.gson</groupId><artifactId>gson</artifactId><version>2.8.8</version>"
        "</dependency></dependencies></dependencyManagement></project>",
        encoding="utf-8",
    )
    (project / "parent.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>demo</groupId>"
        "<artifactId>grandparent</artifactId><version>1</version><relativePath>grandparent.xml</relativePath>"
        "</parent><groupId>demo</groupId><artifactId>parent</artifactId><version>1</version></project>",
        encoding="utf-8",
    )
    (project / "module" / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>demo</groupId>"
        "<artifactId>parent</artifactId><version>1</version><relativePath>../parent.xml</relativePath>"
        "</parent><artifactId>app</artifactId><dependencies><dependency>"
        "<groupId>com.google.code.gson</groupId><artifactId>gson</artifactId></dependency>"
        "</dependencies></project>",
        encoding="utf-8",
    )

    findings = scan_maven_project(project / "module")

    assert any(item["artifact"] == "gson" and item["version"] == "2.8.8" for item in findings)


def test_maven_empty_parent_relative_path_disables_local_parent_lookup(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>parent</artifactId>"
        "<version>1</version><properties><inherited.version>2.9.10.3</inherited.version></properties></project>",
        encoding="utf-8",
    )
    (project / "module").mkdir()
    (project / "module" / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>demo</groupId><artifactId>parent</artifactId>"
        "<version>1</version><relativePath/></parent><artifactId>app</artifactId><dependencies><dependency>"
        "<groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId>"
        "<version>$" "{inherited.version}</version></dependency></dependencies></project>",
        encoding="utf-8",
    )

    assert scan_maven_project(project / "module") == []
