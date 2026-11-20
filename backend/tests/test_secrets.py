from app.scanners.secrets import scan_text

def test_detects_provider_key_and_masks_value():
    findings = scan_text("aws = AKIA1234567890ABCDEF", "settings.py")
    assert findings[0]["rule_id"] == "aws_access_key"
    assert "AKIA1234567890ABCDEF" not in str(findings[0])
    assert findings[0]["fingerprint"]

def test_ignores_placeholder_password():
    assert scan_text('password = "changeme"', "config.py") == []

def test_detects_generic_secret_assignment():
    findings = scan_text('api_key = "super-secret-value-123"', "config.py")
    assert any(item["rule_id"] == "generic_assignment" for item in findings)

def test_training_named_kotlin_password_and_api_key():
    password = scan_text('    private val legacyImportPassword = "cg26_parts_H9r4Vm2Kb6Qp"', "PartsImportSettings.kt")
    api_key = scan_text('    private val pricingApiKey = "cg26_quote_qA7mN4kV9rT2sJ6c"', "QuoteRequest.kt")
    assert any(x["class"] == "password" and x["line"] == 1 for x in password)
    assert any(x["class"] == "api-key" and x["line"] == 1 for x in api_key)
    assert "cg26_parts_H9r4Vm2Kb6Qp" not in str(password)

def test_training_bearer_configuration_and_environment_control():
    config = 'authorization: "Bearer cg26_pickup_Gq7mP8vJdW3sY6zN"\ntoken: ' + "$" + '{INVENTORY_TOKEN}'
    findings = scan_text(config, "application.yml")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "bearer_configuration"
    assert findings[0]["line"] == 1

def test_training_environment_fallback():
    text = 'val access = System.getenv("DEPOT_STATUS_TOKEN") ?: "cg26_depot_mK7xR4bP9wD2qT"'
    findings = scan_text(text, "DepotStatusClient.kt")
    assert any(x["rule_id"] == "secret_fallback" and x["line"] == 1 for x in findings)

def test_training_reconstructed_authorization_token():
    text = '''val series = "cg26_warranty_"
val grant = "D7v4sB2wJ8kP6mQ9"
val access = series + grant
return HttpHeaders().apply { setBearerAuth(access) }'''
    findings = scan_text(text, "WarrantyHeaders.kt")
    item = next(x for x in findings if x["rule_id"] == "reconstructed_auth_token")
    assert item["line"] == 1 and item["endLine"] == 4
    assert "cg26_warranty_D7v4sB2wJ8kP6mQ9" not in str(item)

def test_safe_configuration_reference_is_not_a_secret():
    assert scan_text("token: " + "$" + "{INVENTORY_TOKEN}", "application.yml") == []



def test_detects_high_entropy_secret_named_literal_and_masks_value():
    value = "k7Qp9xVm2Rz8Nw4Hs6Ty3Bc"
    findings = scan_text(f'JWT_SECRET = "{value}"', "AuthConfig.py")
    item = next(x for x in findings if x["rule_id"] == "high_entropy_secret")
    assert item["severity"] == "MEDIUM"
    assert item["confidence"] == 0.76
    assert value not in str(item)
    assert item["masked_value"] != value


def test_entropy_rule_ignores_low_entropy_secret_named_literal():
    assert scan_text('JWT_SECRET = "aaaaaaaaaaaaaaaaaaaaaaaa"', "AuthConfig.py") == []


def test_entropy_rule_does_not_scan_unrelated_random_literals():
    assert scan_text('SERVICE_NAME = "k7Qp9xVm2Rz8Nw4Hs6Ty3Bc"', "AuthConfig.py") == []


def test_entropy_rule_does_not_duplicate_existing_secret_assignment_finding():
    findings = scan_text('private val apiKey = "k7Qp9xVm2Rz8Nw4Hs6Ty3Bc"', "AuthConfig.kt")
    assert any(item["rule_id"] == "named_secret_literal" for item in findings)
    assert not any(item["rule_id"] == "high_entropy_secret" for item in findings)



def test_entropy_rule_bounds_very_long_literals():
    value = "k7Qp9xVm2Rz8Nw4Hs6Ty3Bc" * 200
    findings = scan_text(f'JWT_SECRET = "{value}"', "AuthConfig.py")
    assert not any(item["rule_id"] == "high_entropy_secret" for item in findings)
