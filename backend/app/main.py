import json
import time
import shutil
import re
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field, field_validator
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError

from app.config import settings
from app.sources.archive import ArchiveValidationError, extract_project_archive
from app.sources.run_files import RunSourceFileError, resolve_run_source_file
from app.scanners.presentation import _redact
from app.db import SessionLocal
from app.models import AuditLog, Finding, FindingState, Project, Workflow, WorkflowRun, WorkflowVersion
from app.workflows.registry import registry
from app.workflows.schemas import WorkflowGraph
from app.workflows.validator import validate_graph
from app.workflows.engine import execute_graph, WorkflowExecutionError

class ProjectRename(BaseModel):
    name: str = Field(min_length=1, max_length=200)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Название проекта не может быть пустым.")
        return value


class FindingStateUpdate(BaseModel):
    state: Literal["open", "accepted_risk", "fixed", "false_positive"]
    reason: str = Field(min_length=3, max_length=2000)
    expires_at: datetime | None = None

    @field_validator("reason")
    @classmethod
    def reason_must_contain_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Укажите причину изменения статуса.")
        return value.strip()


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



def _project_root(project: Project) -> Path:
    workspace = Path(settings.workspace_root).resolve()
    relative = PurePosixPath(project.workspace_path)
    if (
        relative.is_absolute()
        or len(relative.parts) != 2
        or relative.parts[0] != "projects"
        or not relative.parts[1].startswith("project-")
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise HTTPException(status_code=500, detail="Invalid project workspace reference")
    root = workspace.joinpath(*relative.parts)
    if root.is_symlink():
        raise HTTPException(status_code=404, detail="Project files are unavailable")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise HTTPException(status_code=404, detail="Project files are unavailable") from exc
    if not resolved.is_relative_to(workspace) or not resolved.is_dir():
        raise HTTPException(status_code=404, detail="Project files are unavailable")
    return resolved


def _project_has_active_run(session, project: Project) -> bool:
    runs = session.scalars(select(WorkflowRun).where(WorkflowRun.status.in_(["queued", "running"]))).all()
    for run in runs:
        graph = run.graph_snapshot if isinstance(run.graph_snapshot, dict) else {}
        for node in graph.get("nodes", []):
            if not isinstance(node, dict) or node.get("type") != "source.upload":
                continue
            config = node.get("config", {})
            if isinstance(config, dict) and config.get("path") == project.workspace_path:
                return True
    return False


def _project_payload(project: Project) -> dict:
    return {
        "id": str(project.id),
        "name": project.name,
        "workspace_path": project.workspace_path,
        "original_filename": project.original_filename,
        "file_count": project.file_count,
        "expanded_bytes": project.expanded_bytes,
        "created_at": project.created_at,
        "updated_at": project.updated_at,
    }


def _safe_project_name(filename: str | None) -> str:
    stem = Path(filename or "Новый проект").stem
    cleaned = re.sub(r"[^\w .()-]+", " ", stem, flags=re.UNICODE).strip(" .-_")
    return (cleaned or "Новый проект")[:200]


@app.get("/api/projects")
def list_projects():
    with SessionLocal() as session:
        rows = session.scalars(select(Project).order_by(Project.updated_at.desc(), Project.name)).all()
        return [_project_payload(item) for item in rows]


@app.post("/api/projects", status_code=201)
def create_project(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=415, detail="Загрузите ZIP-архив проекта.")
    project_id = uuid4()
    workspace_path = f"projects/project-{project_id}"
    staging_path = f"projects/.staging-{project_id}"
    try:
        result = extract_project_archive(file.file, settings.workspace_root, staging_path)
        root = Path(settings.workspace_root).resolve()
        destination = root / workspace_path
        result_path = root / staging_path
        result_path.rename(destination)
        with SessionLocal() as session:
            project = Project(
                id=project_id,
                name=_safe_project_name(file.filename),
                workspace_path=workspace_path,
                original_filename=Path(file.filename).name[:255],
                file_count=result["files"],
                expanded_bytes=result["expanded_bytes"],
            )
            session.add(project)
            session.add(AuditLog(action="project.created", entity="project", entity_id=str(project_id), details={
                "file_count": result["files"], "expanded_bytes": result["expanded_bytes"]
            }))
            session.commit()
            session.refresh(project)
            return _project_payload(project)
    except ArchiveValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        shutil.rmtree(Path(settings.workspace_root) / staging_path, ignore_errors=True)
        raise HTTPException(status_code=500, detail="Не удалось сохранить проект в рабочую папку.") from exc
    finally:
        file.file.close()


@app.put("/api/projects/{project_id}/archive")
def update_project_archive(project_id: UUID, file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=415, detail="Загрузите ZIP-архив проекта.")
    with SessionLocal() as session:
        project = session.get(Project, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        if _project_has_active_run(session, project):
            raise HTTPException(status_code=409, detail="Нельзя обновить проект, пока выполняется workflow с этим источником.")
        workspace_path = project.workspace_path
        staging_path = f"projects/.staging-{project_id}-{uuid4().hex}"
        root = Path(settings.workspace_root).resolve()
        destination = _project_root(project)
        staging = root.joinpath(*PurePosixPath(staging_path).parts)
        backup = root / "projects" / f".previous-{project_id}-{uuid4().hex}"
        try:
            result = extract_project_archive(file.file, root, staging_path)
            destination.rename(backup)
            try:
                staging.rename(destination)
            except Exception:
                backup.rename(destination)
                raise
            shutil.rmtree(backup, ignore_errors=True)
            project.file_count = result["files"]
            project.expanded_bytes = result["expanded_bytes"]
            project.original_filename = Path(file.filename).name[:255]
            session.add(AuditLog(action="project.updated", entity="project", entity_id=str(project_id), details={
                "file_count": result["files"], "expanded_bytes": result["expanded_bytes"]
            }))
            session.commit()
            session.refresh(project)
            return _project_payload(project)
        except ArchiveValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except OSError as exc:
            shutil.rmtree(staging, ignore_errors=True)
            raise HTTPException(status_code=500, detail="Не удалось обновить файлы проекта.") from exc
        finally:
            file.file.close()


@app.patch("/api/projects/{project_id}")
def rename_project(project_id: UUID, payload: ProjectRename):
    with SessionLocal() as session:
        project = session.get(Project, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        previous = project.name
        project.name = payload.name
        session.add(AuditLog(action="project.renamed", entity="project", entity_id=str(project_id), details={
            "previous_name": previous, "name": payload.name
        }))
        session.commit()
        session.refresh(project)
        return _project_payload(project)


@app.delete("/api/projects/{project_id}", status_code=204)
def delete_project(project_id: UUID):
    with SessionLocal() as session:
        project = session.get(Project, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        if _project_has_active_run(session, project):
            raise HTTPException(status_code=409, detail="Нельзя удалить проект, пока выполняется workflow с этим источником.")
        root = _project_root(project)
        shutil.rmtree(root)
        session.add(AuditLog(action="project.deleted", entity="project", entity_id=str(project_id), details={
            "name": project.name, "workspace_path": project.workspace_path
        }))
        session.delete(project)
        session.commit()
    return None


@app.get("/api/projects/{project_id}/files")
def list_project_files(project_id: UUID):
    with SessionLocal() as session:
        project = session.get(Project, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        root = _project_root(project)
        files = []
        for current, directories, filenames in __import__("os").walk(root, followlinks=False):
            directories[:] = [name for name in directories if name != ".git" and not (Path(current) / name).is_symlink()]
            for filename in filenames:
                item = Path(current) / filename
                if item.is_symlink():
                    continue
                try:
                    relative = item.relative_to(root).as_posix()
                    files.append({"path": relative, "size": item.stat().st_size})
                except OSError:
                    continue
                if len(files) >= 10000:
                    break
            if len(files) >= 10000:
                break
        return {"project": _project_payload(project), "files": sorted(files, key=lambda item: item["path"].lower()), "truncated": len(files) >= 10000}


@app.get("/api/projects/{project_id}/file")
def preview_project_file(
    project_id: UUID,
    path: str = Query(min_length=1, max_length=1000),
    start_line: int = Query(default=1, ge=1),
):
    relative = PurePosixPath(path)
    if relative.is_absolute() or "\\" in path or "\x00" in path or any(part in {"", ".", ".."} for part in relative.parts):
        raise HTTPException(status_code=400, detail="Invalid project file path")
    with SessionLocal() as session:
        project = session.get(Project, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        root = _project_root(project)
        candidate = root.joinpath(*relative.parts)
        current = candidate
        while current != root:
            if current.is_symlink():
                raise HTTPException(status_code=404, detail="Project file is unavailable")
            current = current.parent
        try:
            resolved = candidate.resolve(strict=True)
            if not resolved.is_relative_to(root) or not resolved.is_file() or resolved.stat().st_size > 1_000_000:
                raise OSError("File is unavailable or too large")
            content = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=404, detail="Файл недоступен для текстового просмотра (лимит 1 MiB).") from exc
        lines = content.splitlines()
        first = min(start_line, max(1, len(lines)))
        last = min(len(lines), first + 299)
        return {
            "path": relative.as_posix(),
            "start_line": first,
            "end_line": last,
            "total_lines": len(lines),
            "lines": [{"line": number, "text": _redact(lines[number - 1])[:1000]} for number in range(first, last + 1)],
        }


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
        "trace": trace,
        "completed_nodes": progress.get("completed_nodes", len(trace)) if progress else len(trace),
        "total_nodes": progress.get("total_nodes", len(run.graph_snapshot.get("nodes", []))) if progress else len(run.graph_snapshot.get("nodes", [])),
        "current_node": progress.get("current_node") if progress else None,
        "scanner_progress": progress.get("scanner_progress") if progress else None,
        "node_results": (
            progress.get("node_results", {}) if progress else {
                node_id: {
                    "status": output.get("status"),
                    **({"message": output["message"]} if output.get("message") else {}),
                    **({"findings": output["summary"]["total"]} if isinstance(output.get("summary"), dict) else {}),
                    **({"explained_count": output.get("explained_count", len(output.get("explanations", [])))} if node_id in {item.get("node_id") for item in trace if item.get("type") == "ai.explain"} else {}),
                    **({"total_findings": len(output.get("findings", []))} if node_id in {item.get("node_id") for item in trace if item.get("type") == "ai.explain"} else {}),
                    **({"explanations": [
                        {
                            "root_cause": str(item.get("root_cause", ""))[:240],
                            "impact": str(item.get("impact", ""))[:180],
                            "recommendation": str(item.get("recommendation", ""))[:240],
                        } for item in output.get("explanations", [])[:3]
                    ]} if node_id in {item.get("node_id") for item in trace if item.get("type") == "ai.explain"} else {}),
                } for node_id, output in (result.get("outputs", {}) if isinstance(result, dict) else {}).items()
            }
        ),
        "security_gate": result.get("security_gate"),
        "error": run.error,
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


@app.get("/api/runs/{run_id}/findings/{fingerprint}/source")
def get_finding_source(
    run_id: UUID,
    fingerprint: str,
    start_line: int | None = Query(default=None, ge=1),
    end_line: int | None = Query(default=None, ge=1),
):
    """Return a bounded, redacted source window for a finding belonging to this run."""
    if not fingerprint or len(fingerprint) > 64:
        raise HTTPException(status_code=422, detail="Invalid finding fingerprint")
    if start_line is not None and end_line is not None and end_line < start_line:
        raise HTTPException(status_code=422, detail="end_line must be >= start_line")
    if start_line is not None and end_line is not None and end_line - start_line + 1 > 300:
        raise HTTPException(status_code=422, detail="Source window is limited to 300 lines")

    with SessionLocal() as session:
        run = session.get(WorkflowRun, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        finding = session.scalar(
            select(Finding).where(Finding.run_id == run_id, Finding.fingerprint == fingerprint).limit(1)
        )
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found in this run")
        payload = finding.payload if isinstance(finding.payload, dict) else {}
        try:
            source_file = resolve_run_source_file(
                settings.workspace_root, run.graph_snapshot, run.result or {}, finding.path
            )
            if source_file.stat().st_size > 1_000_000:
                raise RunSourceFileError("Source file exceeds the 1 MiB preview limit")
            content = source_file.read_text(encoding="utf-8")
        except (RunSourceFileError, OSError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=404, detail="Source file is unavailable for this run") from exc

        lines = content.splitlines()
        total_lines = len(lines)
        center = finding.line or 1
        first = start_line if start_line is not None else max(1, center - 40)
        last = end_line if end_line is not None else min(total_lines, first + 99)
        if first > max(total_lines, 1):
            raise HTTPException(status_code=416, detail="Requested source window is outside the file")
        last = min(last, first + 299, total_lines)
        redact_entire_file = str(payload.get("category", "")).upper() == "SECRET"
        window = [
            {
                "line": number,
                "text": "[REDACTED: secret-bearing source file]" if redact_entire_file else _redact(lines[number - 1])[:1000],
                "is_finding": number == finding.line,
            }
            for number in range(first, last + 1)
        ]
        return {
            "path": finding.path,
            "finding_line": finding.line,
            "start_line": first,
            "end_line": last,
            "total_lines": total_lines,
            "redacted": redact_entire_file,
            "lines": window,
        }


@app.post("/api/workflows/run")
def run_workflow(graph: WorkflowGraph):
    try:
        return execute_graph(graph, registry)
    except WorkflowExecutionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc



@app.get("/api/workflows/{workflow_id}/finding-states")
def list_finding_states(workflow_id: UUID):
    with SessionLocal() as session:
        if session.get(Workflow, workflow_id) is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        rows = session.scalars(
            select(FindingState)
            .where(FindingState.workflow_id == workflow_id)
            .order_by(FindingState.fingerprint)
        ).all()
        return [
            {
                "fingerprint": row.fingerprint,
                "state": row.state,
                "reason": row.reason,
                "expires_at": row.expires_at,
            }
            for row in rows
        ]


@app.put("/api/workflows/{workflow_id}/findings/{fingerprint}/state")
def update_finding_state(workflow_id: UUID, fingerprint: str, payload: FindingStateUpdate):
    if not fingerprint or len(fingerprint) > 64:
        raise HTTPException(status_code=422, detail="Invalid finding fingerprint")
    if payload.state != "accepted_risk" and payload.expires_at is not None:
        raise HTTPException(status_code=422, detail="Срок действия допускается только для accepted_risk.")

    with SessionLocal() as session:
        if session.get(Workflow, workflow_id) is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        finding = session.scalar(
            select(Finding)
            .join(WorkflowRun, Finding.run_id == WorkflowRun.id)
            .where(WorkflowRun.workflow_id == workflow_id, Finding.fingerprint == fingerprint)
            .limit(1)
        )
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found in this workflow")

        state_row = session.scalar(
            select(FindingState).where(
                FindingState.workflow_id == workflow_id,
                FindingState.fingerprint == fingerprint,
            )
        )
        previous_state = state_row.state if state_row else None
        if state_row is None:
            state_row = FindingState(
                workflow_id=workflow_id,
                fingerprint=fingerprint,
                state=payload.state,
                reason=payload.reason,
                expires_at=payload.expires_at,
            )
            session.add(state_row)
        else:
            state_row.state = payload.state
            state_row.reason = payload.reason
            state_row.expires_at = payload.expires_at

        session.add(AuditLog(
            action="finding.state.changed",
            entity="finding_state",
            entity_id=f"{workflow_id}:{fingerprint}",
            details={
                "workflow_id": str(workflow_id),
                "fingerprint": fingerprint,
                "previous_state": previous_state,
                "new_state": payload.state,
                "reason": payload.reason,
                "expires_at": payload.expires_at.isoformat() if payload.expires_at else None,
            },
        ))
        session.commit()
        return {
            "fingerprint": fingerprint,
            "previous_state": previous_state,
            "state": state_row.state,
            "reason": state_row.reason,
            "expires_at": state_row.expires_at,
        }


@app.get("/api/workflows/{workflow_id}/findings/{fingerprint}/history")
def finding_state_history(workflow_id: UUID, fingerprint: str):
    with SessionLocal() as session:
        if session.get(Workflow, workflow_id) is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        entity_id = f"{workflow_id}:{fingerprint}"
        rows = session.scalars(
            select(AuditLog)
            .where(AuditLog.entity == "finding_state", AuditLog.entity_id == entity_id)
            .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        ).all()
        return [
            {
                "action": row.action,
                "details": row.details,
                "created_at": row.created_at,
            }
            for row in rows
        ]
