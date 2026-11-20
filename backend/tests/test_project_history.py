from app.main import _project_file_snapshot, _project_snapshot_diff


def test_project_snapshot_detects_content_changes_and_ignores_git(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / ".git").mkdir()
    (root / "src" / "Main.kt").write_text("fun main() = Unit", encoding="utf-8")
    (root / "README.md").write_text("old", encoding="utf-8")
    (root / ".git" / "config").write_text("internal", encoding="utf-8")

    before = _project_file_snapshot(root)
    (root / "src" / "Main.kt").write_text("fun main() = Two", encoding="utf-8")
    (root / "README.md").unlink()
    (root / "new.txt").write_text("new", encoding="utf-8")
    after = _project_file_snapshot(root)

    assert set(before) == {"src/Main.kt", "README.md"}
    assert set(after) == {"src/Main.kt", "new.txt"}
    diff = _project_snapshot_diff(before, after)
    assert diff["added_count"] == 1
    assert diff["removed_count"] == 1
    assert diff["changed_count"] == 1
    assert diff["added_files"] == ["new.txt"]
    assert diff["removed_files"] == ["README.md"]
    assert diff["changed_files"] == ["src/Main.kt"]


def test_project_snapshot_diff_limits_path_samples():
    before = {f"old-{index}.txt": {"size": 1, "sha256": "a"} for index in range(60)}
    after = {f"new-{index}.txt": {"size": 1, "sha256": "b"} for index in range(60)}

    diff = _project_snapshot_diff(before, after)

    assert diff["added_count"] == 60
    assert diff["removed_count"] == 60
    assert len(diff["added_files"]) == 50
    assert len(diff["removed_files"]) == 50
    assert diff["sample_truncated"] is True


from pathlib import PurePosixPath

from app.main import _project_content_is_safe, _project_path_is_sensitive


def test_project_editor_blocks_secret_paths_in_nested_directories():
    assert _project_path_is_sensitive(PurePosixPath("config/private/app.yaml"))
    assert _project_path_is_sensitive(PurePosixPath("src/.env.production"))
    assert not _project_path_is_sensitive(PurePosixPath("src/application.yaml"))


def test_project_editor_rejects_secret_like_content():
    assert _project_content_is_safe("name: sample\nversion: 1.0\n")
    assert not _project_content_is_safe("API_TOKEN=example-secret-value\n")
    assert not _project_content_is_safe("token: unquoted-secret-value\\n")
    assert not _project_content_is_safe("-----BEGIN RSA PRIVATE KEY-----\\n")



def test_project_export_excludes_secret_paths_and_secret_like_content():
    from pathlib import PurePosixPath
    from app.main import _project_export_file_is_safe

    assert not _project_export_file_is_safe(PurePosixPath("config/.env"), 20, "API_TOKEN=secret")
    assert not _project_export_file_is_safe(PurePosixPath("config/app.yaml"), 30, "API_TOKEN=example-secret-value")
    assert _project_export_file_is_safe(PurePosixPath("src/application.yaml"), 20, "name: sample")
    assert _project_export_file_is_safe(PurePosixPath("assets/logo.png"), 1024)
    assert not _project_export_file_is_safe(PurePosixPath("docs/large.txt"), 1_000_001)
    assert not _project_export_file_is_safe(PurePosixPath("archive.bin"), 512 * 1024 * 1024 + 1)



def test_cache_telemetry_summary_counts_only_scanner_nodes_and_reports_hit_rate():
    from app.main import _cache_telemetry_summary

    summary = _cache_telemetry_summary([
        {"type": "trigger.manual", "cached": False},
        {"type": "scan.secrets", "cached": True},
        {"type": "scan.sca", "cached": False},
        {"type": "scan.sast", "cached": True},
        {"type": "findings.merge", "cached": False},
    ])

    assert summary["scanner_blocks"] == 3
    assert summary["cache_hits"] == 2
    assert summary["fresh_scans"] == 1
    assert summary["hit_rate"] == 0.6667
    assert summary["ttl_seconds"] == 86400


def test_cache_telemetry_summary_handles_empty_or_missing_trace():
    from app.main import _cache_telemetry_summary

    assert _cache_telemetry_summary([])["hit_rate"] == 0.0
    assert _cache_telemetry_summary([{"type": "scan.secrets"}])["fresh_scans"] == 1


def test_scanner_run_comparison_reports_cache_and_finding_deltas():
    from app.main import _compare_scanner_runs

    before = {
        "trace": [{"node_id": "secrets", "type": "scan.secrets", "cached": True, "cache_age_seconds": 120}, {"node_id": "sca", "type": "scan.sca", "cached": False}],
        "outputs": {"secrets": {"findings": [{"fingerprint": "same"}, {"fingerprint": "old"}]}, "sca": {"findings": [{"fingerprint": "dep-a"}]}},
        "cache_metadata": {"secrets": {"source_hash": "source-a"}},
    }
    after = {
        "trace": [{"node_id": "secrets", "type": "scan.secrets", "cached": False}, {"node_id": "sca", "type": "scan.sca", "cached": True, "cache_age_seconds": 30}, {"node_id": "sast", "type": "scan.sast", "cached": False}],
        "outputs": {"secrets": {"findings": [{"fingerprint": "same"}, {"fingerprint": "new"}]}, "sca": {"findings": [{"fingerprint": "dep-a"}]}, "sast": {"findings": []}},
        "cache_metadata": {"secrets": {"source_hash": "source-b"}},
    }
    comparison = _compare_scanner_runs(before, after)
    assert comparison["cache_comparison"] == {"before_hits": 1, "after_hits": 1, "delta_hits": 0, "before_scanners": 2, "after_scanners": 3}
    by_node = {item["node_id"]: item for item in comparison["scanner_comparison"]}
    assert by_node["secrets"]["added_findings"] == 1
    assert by_node["secrets"]["removed_findings"] == 1
    assert by_node["secrets"]["source_changed"] is True
    assert by_node["secrets"]["before_cache_age_seconds"] == 120
    assert by_node["sca"]["after_cached"] is True
    assert by_node["sast"]["before_present"] is False


def test_scanner_run_comparison_handles_missing_metadata():
    from app.main import _compare_scanner_runs
    comparison = _compare_scanner_runs(
        {"trace": [{"node_id": "sca", "type": "scan.sca", "cached": False}]},
        {"trace": [{"node_id": "sca", "type": "scan.sca", "cached": True}]},
    )
    assert comparison["cache_comparison"]["delta_hits"] == 1
    assert comparison["scanner_comparison"][0]["source_changed"] is None
    assert comparison["scanner_comparison"][0]["added_findings"] == 0



def test_run_source_manifest_diff_and_finding_correlation():
    from app.main import _compare_source_manifests, _annotate_finding_source_relation

    before = {"source_manifests": {"source": {
        "complete": True,
        "files": {
            "src/Main.kt": {"size": 10, "sha256": "old"},
            "README.md": {"size": 4, "sha256": "same"},
            "obsolete.kt": {"size": 2, "sha256": "gone"},
        },
    }}}
    after = {"source_manifests": {"source": {
        "complete": True,
        "files": {
            "src/Main.kt": {"size": 11, "sha256": "new"},
            "README.md": {"size": 4, "sha256": "same"},
            "new.kt": {"size": 3, "sha256": "added"},
        },
    }}}

    comparison = _compare_source_manifests(before, after)
    assert comparison["status"] == "complete"
    assert comparison["added_count"] == 1
    assert comparison["removed_count"] == 1
    assert comparison["modified_count"] == 1
    assert comparison["added_files"] == ["new.kt"]
    assert comparison["removed_files"] == ["obsolete.kt"]
    assert comparison["modified_files"] == ["src/Main.kt"]

    findings = _annotate_finding_source_relation([
        {"path": "new.kt"}, {"path": "src/Main.kt"},
        {"path": "obsolete.kt"}, {"path": "README.md"},
    ], comparison)
    assert [item["source_relation"] for item in findings] == [
        "added_file", "modified_file", "removed_file", "unchanged_file"
    ]


def test_run_source_manifest_missing_or_incomplete_stays_unknown():
    from app.main import _compare_source_manifests, _annotate_finding_source_relation

    missing = _compare_source_manifests({}, {})
    assert missing["status"] == "unavailable"
    assert _annotate_finding_source_relation([{"path": "src/Main.kt"}], missing)[0]["source_relation"] == "unknown"

    incomplete = _compare_source_manifests(
        {"source_manifests": {"source": {"complete": False, "reason": "limit", "files": {}}}},
        {"source_manifests": {"source": {"complete": True, "files": {"src/Main.kt": {"sha256": "x", "size": 1}}}}},
    )
    assert incomplete["status"] == "unavailable"
    assert _annotate_finding_source_relation([{"path": "src/Main.kt"}], incomplete)[0]["source_relation"] == "unknown"


def test_source_file_manifest_hashes_files_and_excludes_generated_dirs(tmp_path):
    from app.workflows.engine import _source_file_manifest

    (tmp_path / "src").mkdir()
    (tmp_path / ".git").mkdir()
    (tmp_path / "src" / "Main.kt").write_text("fun main() = Unit", encoding="utf-8")
    (tmp_path / ".git" / "config").write_text("ignored", encoding="utf-8")

    manifest = _source_file_manifest(tmp_path)
    assert manifest["complete"] is True
    assert set(manifest["files"]) == {"src/Main.kt"}
    assert manifest["files"]["src/Main.kt"]["size"] == len("fun main() = Unit")
    assert len(manifest["files"]["src/Main.kt"]["sha256"]) == 64
