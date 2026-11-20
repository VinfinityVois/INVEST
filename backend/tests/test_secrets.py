from app.scanners.secrets import scan_text

def test_detects_aws_key_and_masks_value():
    findings = scan_text("aws = AKIA1234567890ABCDEF", "settings.py")
    assert findings
    assert findings[0]["rule_id"] == "aws_access_key"
    assert "AKIA1234567890ABCDEF" not in str(findings[0])

def test_ignores_placeholder_password():
    assert scan_text('password = "changeme"', "config.py") == []

def test_detects_generic_secret_assignment():
    findings = scan_text('api_key = "super-secret-value-123"', "config.py")
    assert any(item["rule_id"] == "generic_assignment" for item in findings)
