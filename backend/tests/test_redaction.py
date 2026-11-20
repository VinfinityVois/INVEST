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
        "message": "token=ghp_abcdefghijklmnopqrstuvwxyz012345",
        "nested": [{"password": "hunter2", "text": "safe"}],
    })

    assert value["api_key"] == "[REDACTED]"
    assert "super-secret-value" not in json.dumps(value)
    assert "ghp_abcdefghijklmnopqrstuvwxyz012345" not in json.dumps(value)
    assert value["nested"][0]["password"] == "[REDACTED]"
    assert value["nested"][0]["text"] == "safe"
