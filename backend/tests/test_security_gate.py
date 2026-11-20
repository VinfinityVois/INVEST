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


def test_accepted_risk_and_false_positive_are_suppressed():
    findings = [
        {"fingerprint": "risk-1", "severity": "CRITICAL"},
        {"fingerprint": "fp-1", "severity": "HIGH"},
    ]
    states = {
        "risk-1": {"state": "accepted_risk"},
        "fp-1": {"state": "false_positive"},
    }
    result = evaluate_security_gate(findings, finding_states=states)
    assert result["decision"] == "PASS"
    assert result["counts"]["CRITICAL"] == 0
    assert len(result["suppressed_findings"]) == 2


def test_expired_accepted_risk_no_longer_suppresses_finding():
    result = evaluate_security_gate(
        [{"fingerprint": "risk-1", "severity": "HIGH"}],
        finding_states={"risk-1": {
            "state": "accepted_risk",
            "expires_at": "2020-01-01T00:00:00+00:00",
        }},
    )
    assert result["decision"] == "BLOCK"
    assert result["counts"]["HIGH"] == 1


def test_fixed_state_does_not_hide_a_finding_that_is_still_detected():
    result = evaluate_security_gate(
        [{"fingerprint": "fixed-1", "severity": "CRITICAL"}],
        finding_states={"fixed-1": {"state": "fixed"}},
    )
    assert result["decision"] == "BLOCK"
