"""Workspace-scoped dashboard metrics."""

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
        run_query = select(WorkflowRun).where(
            WorkflowRun.workflow_id.in_(workflow_ids) if workflow_ids else False,
            WorkflowRun.queued_at >= since,
        ).order_by(WorkflowRun.queued_at.desc())
        runs = db.scalars(run_query).all()
        run_ids = [row.id for row in runs]
        finding_conditions = [Finding.run_id.in_(run_ids)] if run_ids else [False]
        if severity:
            finding_conditions.append(func.lower(Finding.severity) == severity)
        scanner_expr = func.coalesce(
            Finding.payload["scanner"].as_string(),
            Finding.payload["scanner_type"].as_string(),
            "unknown",
        )
        if scanner:
            finding_conditions.append(func.lower(scanner_expr) == scanner.lower())

        severity_rows = db.execute(
            select(func.lower(Finding.severity), func.count(Finding.id))
            .where(*finding_conditions)
            .group_by(func.lower(Finding.severity))
        ).all()
        severity_counts = {str(name): int(count) for name, count in severity_rows}
        total_findings = sum(severity_counts.values())

        scanner_rows = db.execute(
            select(scanner_expr, func.count(Finding.id))
            .where(*finding_conditions)
            .group_by(scanner_expr)
        ).all()
        scanner_counts = {str(name or "unknown"): int(count) for name, count in scanner_rows}

        run_finding_rows = db.execute(
            select(Finding.run_id, func.count(Finding.id))
            .where(*finding_conditions)
            .group_by(Finding.run_id)
        ).all()
        run_findings = {run_id: int(count) for run_id, count in run_finding_rows}

        scan_trend_rows = db.execute(
            select(func.date(WorkflowRun.queued_at), func.count(WorkflowRun.id))
            .where(
                WorkflowRun.id.in_(run_ids) if run_ids else False,
            )
            .group_by(func.date(WorkflowRun.queued_at))
        ).all()
        finding_trend_rows = db.execute(
            select(func.date(WorkflowRun.queued_at), func.count(Finding.id))
            .select_from(Finding)
            .join(WorkflowRun, WorkflowRun.id == Finding.run_id)
            .where(*finding_conditions)
            .group_by(func.date(WorkflowRun.queued_at))
        ).all()
        trend = {}
        for day, count in scan_trend_rows:
            trend[str(day)] = {"scans": int(count), "findings": 0}
        for day, count in finding_trend_rows:
            trend.setdefault(str(day), {"scans": 0, "findings": 0})["findings"] = int(count)

        workflow_names = {row.id: row.name for row in workflows}
        recent_runs = [{
            "id": str(run.id),
            "workflow_id": str(run.workflow_id),
            "workflow_name": workflow_names.get(run.workflow_id, "Workflow"),
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
                "projects": len(projects) if project_id else (
                    db.scalar(select(func.count(Project.id)).where(Project.workspace_id == workspace.id)) or 0
                ),
                "workflows": len(workflows),
                "scans": len(runs),
                "findings": total_findings,
                "severity": {
                    "critical": severity_counts.get("critical", 0),
                    "high": severity_counts.get("high", 0),
                    "medium": severity_counts.get("medium", 0),
                    "low": severity_counts.get("low", 0),
                    "info": severity_counts.get("info", 0),
                },
                "scanners": scanner_counts,
            },
            "trend": [
                {"date": day, "scans": value["scans"], "findings": value["findings"]}
                for day, value in sorted(trend.items())
            ],
            "recent_runs": recent_runs,
            "projects": [{"id": str(item.id), "name": item.name} for item in projects],
        }
