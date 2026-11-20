import json
import time
from datetime import datetime, timezone
from uuid import UUID

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError

from app.config import settings
from app.sources.archive import ArchiveValidationError, extract_project_archive
from app.db import SessionLocal
from app.models import Finding, Workflow, WorkflowRun, WorkflowVersion
from app.workflows.registry import registry
from app.workflows.schemas import WorkflowGraph
from app.workflows.validator import validate_graph
from app.workflows.engine import execute_graph, WorkflowExecutionError

app = FastAPI(title="AI Security Workflow API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "api"}


@app.get("/health/db")
def database_health():
    try:
        with SessionLocal() as session:
            session.execute(text("SELECT 1"))
        return {"status": "ok", "service": "postgres"}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@app.post("/api/sources/upload", status_code=201)
def upload_source(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=415, detail="Загрузите ZIP-архив проекта.")
    try:
        result = extract_project_archive(file.file, settings.workspace_root)
        return {
            **result,
            "source": "workspace-upload",
            "message": "Архив безопасно распакован. Команды проекта не запускались.",
        }
    except ArchiveValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Не удалось сохранить архив в рабочую директорию.") from exc


@app.get("/api/node-types")
def node_types():
    return [manifest.model_dump() for manifest in registry.all()]


@app.post("/api/workflows/validate")
def validate_workflow(graph: WorkflowGraph):
    return validate_graph(graph, registry).model_dump()


@app.get("/api/workflows")
def list_workflows():
    with SessionLocal() as session:
        rows = session.scalars(select(Workflow).order_by(Workflow.updated_at.desc())).all()
        return [
            {"id": str(item.id), "name": item.name, "description": item.description, "updated_at": item.updated_at}
            for item in rows
        ]


@app.post("/api/workflows", status_code=201)
def create_workflow(graph: WorkflowGraph):
    validation = validate_graph(graph, registry)
    if not validation.valid:
        raise HTTPException(status_code=422, detail=validation.model_dump())
    with SessionLocal() as session:
        workflow = Workflow(name=graph.name)
        session.add(workflow)
        session.flush()
        session.add(WorkflowVersion(workflow_id=workflow.id, version=1, graph=graph.model_dump(mode="json")))
        session.commit()
        return {"id": str(workflow.id), "name": workflow.name, "version": 1}


@app.get("/api/workflows/{workflow_id}")
def get_workflow(workflow_id: UUID):
    with SessionLocal() as session:
        workflow = session.get(Workflow, workflow_id)
        if workflow is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        version = session.scalar(
            select(WorkflowVersion)
            .where(WorkflowVersion.workflow_id == workflow_id)
            .order_by(WorkflowVersion.version.desc())
            .limit(1)
        )
        return {
            "id": str(workflow.id),
            "name": workflow.name,
            "version": version.version if version else 0,
            "graph": version.graph if version else None,
        }


@app.put("/api/workflows/{workflow_id}")
def update_workflow(workflow_id: UUID, graph: WorkflowGraph):
    validation = validate_graph(graph, registry)
    if not validation.valid:
        raise HTTPException(status_code=422, detail=validation.model_dump())
    with SessionLocal() as session:
        workflow = session.get(Workflow, workflow_id)
        if workflow is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        latest = session.scalar(
            select(WorkflowVersion)
            .where(WorkflowVersion.workflow_id == workflow_id)
            .order_by(WorkflowVersion.version.desc())
            .limit(1)
        )
        version = (latest.version if latest else 0) + 1
        workflow.name = graph.name
        session.add(WorkflowVersion(workflow_id=workflow_id, version=version, graph=graph.model_dump(mode="json")))
        session.commit()
        return {"id": str(workflow.id), "name": workflow.name, "version": version}


@app.post("/api/workflows/{workflow_id}/runs", status_code=202)
def execute_saved_workflow(workflow_id: UUID):
    """Persist a run request; the dedicated worker performs the scan asynchronously."""
    with SessionLocal() as session:
        workflow = session.get(Workflow, workflow_id)
        if workflow is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        version = session.scalar(
            select(WorkflowVersion)
            .where(WorkflowVersion.workflow_id == workflow_id)
            .order_by(WorkflowVersion.version.desc())
            .limit(1)
        )
        if version is None:
            raise HTTPException(status_code=409, detail="Workflow has no saved version")

        graph = WorkflowGraph.model_validate(version.graph)
        validation = validate_graph(graph, registry)
        if not validation.valid:
            raise HTTPException(status_code=422, detail=validation.model_dump())

        run = WorkflowRun(
            workflow_id=workflow_id,
            status="queued",
            source="ui",
            graph_snapshot=version.graph,
        )
        session.add(run)
        session.commit()
        return {
            "run_id": str(run.id),
            "workflow_id": str(workflow_id),
            "workflow_version": version.version,
            "status": "queued",
            "findings_count": 0,
        }


@app.get("/api/workflows/{workflow_id}/runs")
def list_workflow_runs(workflow_id: UUID):
    with SessionLocal() as session:
        if session.get(Workflow, workflow_id) is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        rows = session.scalars(
            select(WorkflowRun).where(WorkflowRun.workflow_id == workflow_id).order_by(WorkflowRun.queued_at.desc())
        ).all()
        return [
            {
                "id": str(run.id),
                "status": run.status,
                "source": run.source,
                "queued_at": run.queued_at,
                "started_at": run.started_at,
                "finished_at": run.finished_at,
            }
            for run in rows
        ]


def _run_telemetry(session, run: WorkflowRun):
    findings = session.scalars(select(Finding).where(Finding.run_id == run.id)).all()
    severity = {}
    for finding in findings:
        key = (finding.severity or "UNKNOWN").upper()
        severity[key] = severity.get(key, 0) + 1

    result = run.result if isinstance(run.result, dict) else {}
    trace = result.get("trace", []) if isinstance(result, dict) else []
    progress = result if run.status == "running" and "completed_nodes" in result else None
    if progress:
        severity = progress.get("severity", severity)
    total_findings = progress.get("total_findings", len(findings)) if progress else len(findings)
    now = datetime.now(timezone.utc)
    duration_ms = None
    if run.started_at:
        ended = run.finished_at or now
        duration_ms = max(0, round((ended - run.started_at).total_seconds() * 1000))

    scanner_types = {"scan.secrets", "scan.sca", "scan.sast"}
    scanners = [
        {
            "node_id": item.get("node_id"),
            "type": item.get("type"),
            "status": item.get("status"),
            "findings": item.get("findings", 0),
            "duration_ms": item.get("duration_ms"),
        }
        for item in trace
        if item.get("type") in scanner_types
    ]
    return {
        "run_id": str(run.id),
        "workflow_id": str(run.workflow_id) if run.workflow_id else None,
        "status": run.status,
        "source": run.source,
        "queued_at": run.queued_at,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "duration_ms": duration_ms,
        "total_findings": total_findings,
        "severity": severity,
        "scanners": scanners,
        "completed_nodes": progress.get("completed_nodes", len(trace)) if progress else len(trace),
        "total_nodes": progress.get("total_nodes", len(run.graph_snapshot.get("nodes", []))) if progress else len(run.graph_snapshot.get("nodes", [])),
        "current_node": progress.get("current_node") if progress else None,\n        "error": run.error,
    }


@app.get("/api/workflows/{workflow_id}/telemetry/latest")
def latest_workflow_telemetry(workflow_id: UUID):
    with SessionLocal() as session:
        if session.get(Workflow, workflow_id) is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        run = session.scalar(
            select(WorkflowRun)
            .where(WorkflowRun.workflow_id == workflow_id)
            .order_by(WorkflowRun.queued_at.desc())
            .limit(1)
        )
        if run is None:
            return {"status": "never_run", "total_findings": 0, "severity": {}, "scanners": []}
        return _run_telemetry(session, run)


@app.get("/api/runs/{run_id}/telemetry")
def get_run_telemetry(run_id: UUID):
    with SessionLocal() as session:
        run = session.get(WorkflowRun, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        return _run_telemetry(session, run)


@app.get("/api/runs/{run_id}/events")
def stream_run_events(run_id: UUID):
    def event_stream():
        deadline = time.monotonic() + 1800
        while time.monotonic() < deadline:
            with SessionLocal() as session:
                run = session.get(WorkflowRun, run_id)
                if run is None:
                    payload = {"status": "not_found", "run_id": str(run_id)}
                    yield "event: error\ndata: " + json.dumps(payload) + "\n\n"
                    return
                payload = _run_telemetry(session, run)
            yield "data: " + json.dumps(payload, default=str) + "\n\n"
            if payload["status"] in {"completed", "partial", "failed"}:
                return
            time.sleep(1)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/runs/{run_id}")
def get_run(run_id: UUID):
    with SessionLocal() as session:
        run = session.get(WorkflowRun, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        return {
            "id": str(run.id),
            "workflow_id": str(run.workflow_id) if run.workflow_id else None,
            "status": run.status,
            "source": run.source,
            "result": run.result,
            "error": run.error,
            "queued_at": run.queued_at,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
        }


@app.get("/api/runs/{run_id}/findings")
def list_run_findings(run_id: UUID):
    with SessionLocal() as session:
        if session.get(WorkflowRun, run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        rows = session.scalars(
            select(Finding).where(Finding.run_id == run_id).order_by(Finding.severity, Finding.path, Finding.line)
        ).all()
        return [
            {
                "id": str(item.id),
                "fingerprint": item.fingerprint,
                "rule_id": item.rule_id,
                "severity": item.severity,
                "path": item.path,
                "line": item.line,
                **item.payload,
            }
            for item in rows
        ]


@app.post("/api/workflows/run")
def run_workflow(graph: WorkflowGraph):
    try:
        return execute_graph(graph, registry)
    except WorkflowExecutionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
