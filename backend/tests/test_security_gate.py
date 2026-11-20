import pytest

from app.policies.security_gate import evaluate_security_gate


def test_empty_findings_pass():
    result = evaluate_security_gate([])
    assert result["decision"] == "PASS"
    assert result["blocked"] is False


def test_critical_and_high_findings_block_by_default():
    result = evaluate_security_gate([
        {"fingerprint": "a", "severity": "CRITICAL", "rule_id": "SECRET"},
        {"fingerprint": "b", "severity": "HIGH", "rule_id": "SQLI"},
    ])
    assert result["decision"] == "BLOCK"
    assert result["blocked"] is True
    assert result["counts"]["CRITICAL"] == 1
    assert result["counts"]["HIGH"] == 1


def test_medium_findings_warn_without_blocking():
    result = evaluate_security_gate([{"severity": "MEDIUM"}])
    assert result["decision"] == "WARN"
    assert result["blocked"] is False


def test_policy_can_override_thresholds():
    result = evaluate_security_gate(
        [{"severity": "HIGH"}],
        {"block_on": ["MEDIUM"], "warn_on": ["LOW", "INFO", "HIGH"]},
    )
    assert result["decision"] == "WARN"


def test_unknown_severity_is_counted_as_info():
    result = evaluate_security_gate([{"severity": "unrated"}])
    assert result["decision"] == "WARN"
    assert result["counts"]["INFO"] == 1


def test_invalid_policy_is_rejected():
    with pytest.raises(ValueError):
        evaluate_security_gate([], {"block_on": ["URGENT"]})
