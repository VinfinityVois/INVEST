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
