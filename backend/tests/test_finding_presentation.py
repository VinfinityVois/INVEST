from pathlib import Path

from app.scanners.presentation import enrich_finding


def test_finding_includes_source_context_and_actionable_explanation(tmp_path: Path):
    source = tmp_path / "SecurityConfig.kt"
    source.write_text(
        "fun configure() {\n"
        "  requestMatchers(\"/admin/export\").permitAll()\n"
        "}\n",
        encoding="utf-8",
    )
    finding = enrich_finding({
        "rule_id": "kotlin.spring.public-sensitive-route",
        "category": "SAST",
        "path": "SecurityConfig.kt",
        "line": 2,
        "severity": "HIGH",
        "message": "Sensitive route is public",
    }, tmp_path)

    assert finding["why_it_matters"]
    assert "permitAll" in finding["recommendation"]
    assert any(item["is_finding"] and "permitAll" in item["text"] for item in finding["code_context"])


def test_secret_values_are_redacted_from_source_context(tmp_path: Path):
    source = tmp_path / "application.properties"
    source.write_text('password = "super-secret-value-123"\n', encoding="utf-8")
    finding = enrich_finding({
        "rule_id": "generic_assignment",
        "category": "SECRET",
        "path": "application.properties",
        "line": 1,
        "severity": "MEDIUM",
        "message": "Potential secret",
    }, tmp_path)

    snippet = "\n".join(item["text"] for item in finding["code_context"])
    assert "super-secret-value-123" not in snippet
    assert "[REDACTED:" in snippet


def test_private_key_source_context_is_fully_hidden(tmp_path: Path):
    source = tmp_path / "private.pem"
    source.write_text(
        "-----BEGIN PRIVATE KEY-----\\n"
        "VERY-SENSITIVE-PRIVATE-KEY-MATERIAL\\n"
        "-----END PRIVATE KEY-----\\n",
        encoding="utf-8",
    )
    finding = enrich_finding({
        "rule_id": "private_key",
        "category": "SECRET",
        "path": "private.pem",
        "line": 1,
        "severity": "CRITICAL",
        "message": "Private key detected",
    }, tmp_path)
    snippet = "\\n".join(item["text"] for item in finding["code_context"])
    assert "VERY-SENSITIVE-PRIVATE-KEY-MATERIAL" not in snippet
    assert finding["code_context_redacted"] is True
