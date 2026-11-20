from app.security.redaction import redact_text

def test_redacts_assignments_and_known_token_shapes():
    source = "api_key=super-secret-value AKIA1234567890ABCDEF"
    result = redact_text(source)
    assert "super-secret-value" not in result
    assert "AKIA1234567890ABCDEF" not in result
    assert "[REDACTED]" in result
