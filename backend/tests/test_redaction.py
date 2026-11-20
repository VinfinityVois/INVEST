import json
from app.security.redaction import redact_text

def test_redacts_assignments_and_known_token_shapes():
    source = "api_key=super-secret-value AKIA1234567890ABCDEF"
    result = redact_text(source)
    assert "super-secret-value" not in result
    assert "AKIA1234567890ABCDEF" not in result
    assert "[REDACTED]" in result


def test_safe_report_value_redacts_secret_fields_and_bounds_nested_content():
    from app.main import _safe_report_value

    value = _safe_report_value({
        "api_key": "super-secret-value",
        "message": "token=ghp_abcdefghijklmnopqrstuvwxyz012345 api_key=inline-secret-value",
        "nested": [{"password": "hunter2", "text": "safe"}],
    })

    assert value["api_key"] == "[REDACTED]"
    assert "super-secret-value" not in json.dumps(value)
    assert "ghp_abcdefghijklmnopqrstuvwxyz012345" not in json.dumps(value)
    assert "inline-secret-value" not in json.dumps(value)
    assert value["nested"][0]["password"] == "[REDACTED]"
    assert value["nested"][0]["text"] == "safe"


def test_workflow_graph_diff_reports_node_and_edge_changes_without_exposing_secrets():
    from app.main import _compare_workflow_graphs

    before = {
        "name": "Old",
        "nodes": [
            {"id": "source", "type": "source.git", "config": {"url": "https://example.test", "api_key": "secret-value"}},
            {"id": "scan", "type": "scan.secrets", "config": {"depth": 2}},
        ],
        "edges": [{"id": "e1", "source": "source", "target": "scan"}],
    }
    after = {
        "name": "New",
        "nodes": [
            {"id": "source", "type": "source.git", "config": {"url": "https://example.test", "api_key": "other-secret"}},
            {"id": "report", "type": "report.export", "config": {}},
        ],
        "edges": [{"id": "e2", "source": "source", "target": "report"}],
    }
    diff = _compare_workflow_graphs(before, after)
    assert diff["name_changed"] is True
    assert diff["summary"] == {"added_nodes": 1, "removed_nodes": 1, "changed_nodes": 1, "added_edges": 1, "removed_edges": 1}
    serialized = json.dumps(diff)
    assert "secret-value" not in serialized
    assert "other-secret" not in serialized
    assert diff["nodes"]["changed"][0]["changes"][0]["after"]["api_key"] == "[REDACTED]"



def test_run_snapshot_diff_tracks_finding_lifecycle_and_node_changes():
    from app.main import _compare_run_snapshots

    before = {
        "run": {"status": "completed"},
        "findings": [
            {"fingerprint": "same", "rule_id": "R1", "severity": "HIGH", "path": "a.py", "line": 4},
            {"fingerprint": "gone", "rule_id": "R2", "severity": "LOW", "path": "b.py", "line": 8},
        ],
        "telemetry": {"trace": [{"node_id": "scan", "status": "completed", "duration_ms": 10, "findings": 2}]},
    }
    after = {
        "run": {"status": "completed"},
        "findings": [
            {"fingerprint": "same", "rule_id": "R1", "severity": "CRITICAL", "path": "a.py", "line": 4},
            {"fingerprint": "new", "rule_id": "R3", "severity": "MEDIUM", "path": "c.py", "line": 2},
        ],
        "telemetry": {"trace": [{"node_id": "scan", "status": "completed", "duration_ms": 15, "findings": 2}]},
    }
    diff = _compare_run_snapshots(before, after)
    assert diff["findings"]["summary"] == {"new": 1, "not_observed_before": 0, "persisting": 1, "disappeared": 1, "not_observed": 0}
    assert diff["findings"]["persisting"][0]["severity_changed"] is True
    assert diff["findings"]["absence_confirmed"] is True
    assert diff["nodes"][0]["fields"]["duration_ms"] == {"before": 10, "after": 15}


def test_partial_run_does_not_mark_missing_findings_as_disappeared():
    from app.main import _compare_run_snapshots

    before = {
        "run": {"status": "completed"},
        "findings": [{"fingerprint": "old", "rule_id": "R1", "severity": "HIGH", "path": "a.py", "line": 1}],
        "telemetry": {"trace": []},
    }
    after = {"run": {"status": "partial"}, "findings": [], "telemetry": {"trace": []}}
    diff = _compare_run_snapshots(before, after)
    assert diff["findings"]["disappeared"] == []
    assert len(diff["findings"]["not_observed"]) == 1
    assert diff["findings"]["absence_confirmed"] is False


def test_truncated_previous_run_does_not_claim_new_findings():
    from app.main import _compare_run_snapshots

    before = {
        "run": {"status": "completed"},
        "findings_truncated": True,
        "findings": [],
        "telemetry": {"trace": []},
    }
    after = {
        "run": {"status": "completed"},
        "findings_truncated": False,
        "findings": [{"fingerprint": "possibly-old", "rule_id": "R1", "severity": "HIGH", "path": "a.py", "line": 1}],
        "telemetry": {"trace": []},
    }
    diff = _compare_run_snapshots(before, after)
    assert diff["findings"]["new"] == []
    assert len(diff["findings"]["not_observed_before"]) == 1


def test_truncated_target_run_does_not_confirm_disappearance():
    from app.main import _compare_run_snapshots

    before = {
        "run": {"status": "completed"},
        "findings_truncated": False,
        "findings": [{"fingerprint": "old", "rule_id": "R1", "severity": "HIGH", "path": "a.py", "line": 1}],
        "telemetry": {"trace": []},
    }
    after = {"run": {"status": "completed"}, "findings_truncated": True, "findings": [], "telemetry": {"trace": []}}
    diff = _compare_run_snapshots(before, after)
    assert diff["findings"]["disappeared"] == []
    assert len(diff["findings"]["not_observed"]) == 1
    assert diff["findings"]["absence_confirmed"] is False
