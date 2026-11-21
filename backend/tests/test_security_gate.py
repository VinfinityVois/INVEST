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


def test_builtin_policy_packs_expose_expected_gate_thresholds():
    from app.rules_loader import rule_packs

    bank = rule_packs.resolve(["bank-strict"], analyzer="policy")[0]
    startup = rule_packs.resolve(["startup-lenient"], analyzer="policy")[0]
    secrets = rule_packs.resolve(["secrets-zero"], analyzer="policy")[0]

    assert bank["block_on"] == ["CRITICAL", "HIGH"]
    assert startup["block_on"] == ["CRITICAL"]
    assert secrets["block_on"] == ["CRITICAL", "HIGH", "MEDIUM"]
    assert bank["fail_on_unfixed"] is True


def test_fail_on_unfixed_policy_ignores_findings_marked_fixed():
    from app.policies.security_gate import evaluate_security_gate

    finding = {"fingerprint": "fp-fixed", "rule_id": "test.rule", "severity": "HIGH"}
    result = evaluate_security_gate(
        [finding],
        {"block_on": ["HIGH"], "warn_on": [], "fail_on_unfixed": True},
        {"fp-fixed": {"state": "fixed"}},
    )
    assert result["decision"] == "PASS"
    assert result["counts"]["HIGH"] == 0


def test_named_policy_profiles_drive_gate_thresholds():
    from app.rules_loader import rule_packs
    from app.policies.security_gate import evaluate_security_gate

    findings = [
        {"fingerprint": "high", "severity": "HIGH", "rule_id": "demo.high"},
        {"fingerprint": "critical", "severity": "CRITICAL", "rule_id": "demo.critical"},
    ]
    bank = rule_packs.resolve(["bank-strict"], analyzer="policy")[0]
    startup = rule_packs.resolve(["startup-lenient"], analyzer="policy")[0]
    assert evaluate_security_gate(findings, bank)["decision"] == "BLOCK"
    assert evaluate_security_gate(findings, startup)["decision"] == "BLOCK"
    assert startup["warn_on"] == ["HIGH", "MEDIUM", "LOW", "INFO"]
