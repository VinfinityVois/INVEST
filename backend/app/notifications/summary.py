"""Bounded plain-text summary for notification channels."""
from __future__ import annotations

from typing import Any


DEFAULT_MESSAGE_TEMPLATE = (
    "[{status}] {workflow}\n"
    "Findings: {total} | CRITICAL {critical} | HIGH {high} | "
    "MEDIUM {medium} | LOW {low} | INFO {info}\n"
    "Run: {run_id}"
)

DEFAULT_SUBJECT_TEMPLATE = "[{status}] {workflow}: {total} findings"


def _as_findings(report: dict | None, findings: list | None) -> list[dict]:
    if isinstance(findings, list):
        items = findings
    elif isinstance(report, dict) and isinstance(report.get("findings"), list):
        items = report["findings"]
    else:
        items = []
    return [item for item in items if isinstance(item, dict)]


def build_summary_context(
    *,
    report: dict | None = None,
    findings: list | None = None,
    workflow_name: str = "",
    run_id: str = "",
) -> dict[str, Any]:
    report = report if isinstance(report, dict) else {}
    items = _as_findings(report, findings)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for item in items:
        severity = str(item.get("severity", "INFO")).upper()
        if severity not in counts:
            severity = "INFO"
        counts[severity] += 1
    status = str(report.get("status") or "completed")[:40]
    return {
        "status": status,
        "workflow": str(workflow_name or report.get("workflow") or "workflow")[:160],
        "run_id": str(run_id or report.get("run_id") or "-")[:80],
        "total": len(items),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "info": counts["INFO"],
        "severity": counts,
    }


def render_template(template: str | None, context: dict[str, Any], default: str) -> str:
    raw = (template or "").strip() or default
    safe = {key: context.get(key, "") for key in (
        "status", "workflow", "run_id", "total", "critical", "high", "medium", "low", "info"
    )}
    try:
        return raw.format(**safe)[:3500]
    except (KeyError, ValueError):
        return default.format(**safe)[:3500]


def build_plain_message(
    *,
    report: dict | None = None,
    findings: list | None = None,
    workflow_name: str = "",
    run_id: str = "",
    template: str | None = None,
) -> tuple[str, dict[str, Any]]:
    context = build_summary_context(
        report=report,
        findings=findings,
        workflow_name=workflow_name,
        run_id=run_id,
    )
    text = render_template(template, context, DEFAULT_MESSAGE_TEMPLATE)
    return text, context
