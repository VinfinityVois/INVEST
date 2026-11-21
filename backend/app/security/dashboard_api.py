"""Workspace-scoped dashboard metrics."""

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import func, select

from app.db import SessionLocal
from app.models import Finding, Project, Workflow, WorkflowRun
from app.security.tenancy import require_active_workspace

router = APIRouter(tags=["dashboard"])


@router.get("/api/dashboard/summary")
def dashboard_summary(
    request: Request,
    project_id: UUID | None = None,
    days: int = Query(default=30, ge=7, le=90),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|info)$"),
    scanner: str | None = Query(default=None, max_length=80),
):
    with SessionLocal() as db:
        workspace, _ = require_active_workspace(db, request)
        project_query = select(Project).where(Project.workspace_id == workspace.id)
        if project_id is not None:
            project_query = project_query.where(Project.id == project_id)
        projects = db.scalars(project_query.order_by(Project.name)).all()
        if project_id is not None and not projects:
            raise HTTPException(status_code=404, detail="Project not found.")

        workflow_query = select(Workflow).where(Workflow.workspace_id == workspace.id)
        if project_id is not None:
            workflow_query = workflow_query.where(Workflow.project_id == project_id)
        workflows = db.scalars(workflow_query).all()
        workflow_ids = [row.id for row in workflows]

        since = datetime.now(timezone.utc) - timedelta(days=days)
        run_query = (
            select(WorkflowRun)
            .where(
                WorkflowRun.workflow_id.in_(workflow_ids) if workflow_ids else False,
                WorkflowRun.queued_at >= since,
            )
            .order_by(WorkflowRun.queued_at.desc())
        )
        runs = db.scalars(run_query).all()
        run_ids = [row.id for row in runs]

        finding_query = (
            select(Finding)
            .where(Finding.run_id.in_(run_ids) if run_ids else False)
        )
        if severity:
            finding_query = finding_query.where(func.lower(Finding.severity) == severity)
        findings = db.scalars(finding_query).all()
        if scanner:
            findings = [
                finding for finding in findings
                if str((finding.payload or {}).get("scanner") or (finding.payload or {}).get("scanner_type") or "").lower() == scanner.lower()
            ]

        severity_counts = Counter(str(item.severity).lower() for item in findings)
        scanner_counts = Counter(
            str((item.payload or {}).get("scanner") or (item.payload or {}).get("scanner_type") or "unknown")
            for item in findings
        )
        run_findings = Counter(item.run_id for item in findings)
        trend = defaultdict(lambda: {"scans": 0, "findings": 0})
        for run in runs:
            day = run.queued_at.date().isoformat()
            trend[day]["scans"] += 1
            trend[day]["findings"] += run_findings.get(run.id, 0)

        recent_runs = [{
            "id": str(run.id),
            "workflow_id": str(run.workflow_id),
            "workflow_name": next((item.name for item in workflows if item.id == run.workflow_id), "Workflow"),
            "status": run.status,
            "queued_at": run.queued_at,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "findings": run_findings.get(run.id, 0),
        } for run in runs[:10]]

        return {
            "workspace_id": str(workspace.id),
            "filters": {
                "project_id": str(project_id) if project_id else None,
                "days": days,
                "severity": severity,
                "scanner": scanner,
            },
            "metrics": {
                "projects": len(projects) if project_id else db.scalar(
                    select(func.count(Project.id)).where(Project.workspace_id == workspace.id)
                ) or 0,
                "workflows": len(workflows),
                "scans": len(runs),
                "findings": len(findings),
                "severity": {
                    "critical": severity_counts.get("critical", 0),
                    "high": severity_counts.get("high", 0),
                    "medium": severity_counts.get("medium", 0),
                    "low": severity_counts.get("low", 0),
                    "info": severity_counts.get("info", 0),
                },
                "scanners": dict(scanner_counts),
            },
            "trend": [
                {"date": key, "scans": value["scans"], "findings": value["findings"]}
                for key, value in sorted(trend.items())
            ],
            "recent_runs": recent_runs,
            "projects": [{"id": str(item.id), "name": item.name} for item in projects],
        }
