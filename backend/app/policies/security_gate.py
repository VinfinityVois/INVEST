from collections import Counter
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
DECISIONS = ("PASS", "WARN", "BLOCK")


def evaluate_security_gate(
    findings: list[dict[str, Any]],
    config: dict[str, Any] | None = None,
    finding_states: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate normalized findings against an explicit, deterministic policy.

    Defaults block CRITICAL/HIGH findings and warn on MEDIUM/LOW/INFO.
    Unknown severities are treated as INFO so malformed data cannot silently
    increase severity or crash a workflow.
    """
    policy = config or {}
    block_on = policy.get("block_on", ["CRITICAL", "HIGH"])
    warn_on = policy.get("warn_on", ["MEDIUM", "LOW", "INFO"])
    if not isinstance(block_on, list) or not all(isinstance(x, str) for x in block_on):
        raise ValueError("block_on must be a list of severity names")
    if not isinstance(warn_on, list) or not all(isinstance(x, str) for x in warn_on):
        raise ValueError("warn_on must be a list of severity names")
    block_set = {item.upper() for item in block_on}
    warn_set = {item.upper() for item in warn_on}
    invalid = (block_set | warn_set) - set(SEVERITIES)
    if invalid:
        raise ValueError("Unsupported severity: " + ", ".join(sorted(invalid)))

    counts = Counter()
    blocked = []
    warnings = []
    suppressed = []
    states = finding_states or {}
    now = datetime.now(timezone.utc)
    for finding in findings:
        severity = str(finding.get("severity", "INFO")).upper()
        if severity not in SEVERITIES:
            severity = "INFO"
        fingerprint = str(finding.get("fingerprint") or "")
        state_record = states.get(fingerprint, {})
        lifecycle_state = state_record.get("state")
        expires_at = state_record.get("expires_at")
        is_active_exception = lifecycle_state in {"accepted_risk", "false_positive"}
        if is_active_exception and expires_at:
            try:
                expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                is_active_exception = expiry > now
            except ValueError:
                is_active_exception = False
        item = {
            "fingerprint": finding.get("fingerprint"),
            "lifecycle_state": lifecycle_state,
            "rule_id": finding.get("rule_id", "unknown"),
            "severity": severity,
            "path": finding.get("path", ""),
            "line": finding.get("line"),
            "message": finding.get("message", ""),
        }
        if is_active_exception:
            suppressed.append({**item, "suppression": lifecycle_state})
            continue
        counts[severity] += 1
        if severity in block_set:
            blocked.append(item)
        elif severity in warn_set:
            warnings.append(item)

    decision = "BLOCK" if blocked else ("WARN" if warnings else "PASS")
    return {
        "decision": decision,
        "blocked": bool(blocked),
        "counts": {severity: counts.get(severity, 0) for severity in SEVERITIES},
        "blocking_findings": blocked,
        "warnings": warnings,
        "suppressed_findings": suppressed,
        "policy": {"block_on": sorted(block_set), "warn_on": sorted(warn_set)},
    }
