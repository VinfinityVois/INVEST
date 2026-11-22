import json
import io
import time
import shutil
import re
import os
import hashlib
import html
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Literal
from uuid import UUID, uuid4

from fastapi import FastAPI, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from starlette.background import BackgroundTask
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from croniter import croniter

from app.config import settings
from app.ai.explanations import provider_configuration
from app.ai.fixes import AIFixError, generate_fix_proposal
from app.ai.workflow_generation import WorkflowGenerationError, generate_workflow_graph
from app.sources.archive import ArchiveValidationError, extract_project_archive
from app.sources.run_files import RunSourceFileError, resolve_run_source_file
from app.sources.project_root import detect_project_root
from app.scanners.presentation import _redact
from app.security.redaction import redact_text
from app.db import SessionLocal
from app.models import AuditLog, Finding, FindingState, Project, Workflow, WorkflowRun, WorkflowVersion, WorkflowSchedule, WorkflowTemplate
from app.workflows.registry import registry
from app.rules_loader import rule_packs
from app.workflows.schemas import WorkflowGraph
from app.workflows.validator import validate_graph
from app.workflows.engine import CACHE_TTL_SECONDS, execute_graph, WorkflowExecutionError
from app.workflows.templates import sanitize_graph, clone_graph
from app.workflows.presets import PresetError, list_presets, load_preset

class ProjectRename(BaseModel):
    name: str = Field(min_length=1, max_length=200)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Название проекта не может быть пустым.")
        return value


class WorkflowGenerateRequest(BaseModel):
    prompt: str = Field(min_length=10, max_length=2000)

    @field_validator("prompt")
    @classmethod
    def prompt_must_contain_text(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 10:
            raise ValueError("Опишите желаемый workflow (от 10 символов).")
        return value


class WorkflowScheduleUpdate(BaseModel):
    enabled: bool = True


class SelectedRunRequest(BaseModel):
    node_ids: list[str] = Field(min_length=1, max_length=100)
    force_full_scan: bool = False
    force_node_ids: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("node_ids")
    @classmethod
    def validate_node_ids(cls, value: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(item.strip() for item in value if isinstance(item, str) and item.strip()))
        if not normalized or any(len(item) > 120 for item in normalized):
            raise ValueError("Укажите от 1 до 100 корректных идентификаторов блоков.")
        return normalized




def _lock_workflow_for_version_write(session, workflow_id: UUID):
    """Serialize workflow version allocation across concurrent writers."""
    return session.scalar(
        select(Workflow).where(Workflow.id == workflow_id).with_for_update()
    )


def _lock_run_for_update(session, run_id: UUID):
    """Serialize run state transitions with worker claims and completion."""
    return session.scalar(
        select(WorkflowRun).where(WorkflowRun.id == run_id).with_for_update()
    )


def _lock_schedule_for_update(session, workflow_id: UUID, schedule_id: UUID):
    """Serialize schedule mutations with the due-schedule dispatcher."""
    return session.scalar(
        select(WorkflowSchedule).where(
            WorkflowSchedule.id == schedule_id,
            WorkflowSchedule.workflow_id == workflow_id,
        ).with_for_update()
    )


class FindingStateUpdate(BaseModel):
    state: Literal["open", "in_progress", "resolved", "accepted_risk", "false_positive", "fixed"]
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
    allow_origins=settings.allowed_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


from app.security.api import router as auth_router, SESSION_COOKIE
from app.security.users_api import router as users_router
from app.security.workspaces_api import router as workspaces_router
from app.security.tokens_api import router as tokens_router, require_workspace_api_token
from app.security.dashboard_api import router as dashboard_router
from app.security.findings_api import router as findings_router
from app.security.tenancy import require_active_workspace
from app.security.sessions import get_session_context
from app.security.file_versions import sha256_text, version_matches, project_file_lock
from app.security.project_file_history import save_project_file_version, load_project_file_version
from filelock import Timeout as FileLockTimeout

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(workspaces_router)
app.include_router(tokens_router)
app.include_router(dashboard_router)
app.include_router(findings_router)


def _project_in_active_workspace(session, request: Request, project_id: UUID, *, write: bool = False):
    roles = {"admin", "editor"} if write else None
    workspace, _ = require_active_workspace(session, request, allowed_roles=roles)
    project = session.scalar(
        select(Project).where(
            Project.id == project_id,
            Project.workspace_id == workspace.id,
        )
    )
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def _workflow_in_active_workspace(session, request: Request, workflow_id: UUID, *, write: bool = False, allowed_roles=None):
    roles = allowed_roles if allowed_roles is not None else ({"admin", "editor"} if write else None)
    workspace, _ = require_active_workspace(session, request, allowed_roles=roles)
    workflow = session.scalar(
        select(Workflow).where(
            Workflow.id == workflow_id,
            Workflow.workspace_id == workspace.id,
        )
    )
    if workflow is None:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return workflow


def _run_in_active_workspace(session, request: Request, run_id: UUID, *, write: bool = False):
    roles = {"admin", "editor"} if write else None
    workspace, _ = require_active_workspace(session, request, allowed_roles=roles)
    run = session.scalar(
        select(WorkflowRun)
        .join(Workflow, Workflow.id == WorkflowRun.workflow_id)
        .where(
            WorkflowRun.id == run_id,
            Workflow.workspace_id == workspace.id,
        )
    )
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


def _validate_graph_workspace_sources(session, workspace_id: UUID, graph: WorkflowGraph) -> UUID | None:
    project_ids = set()
    for node in graph.nodes:
        if node.type != "source.upload":
            continue
        source_path = node.config.get("path")
        if not isinstance(source_path, str) or not source_path.strip():
            continue
        project_id = session.scalar(
            select(Project.id).where(
                Project.workspace_id == workspace_id,
                Project.workspace_path == source_path,
            )
        )
        if project_id is None:
            raise HTTPException(
                status_code=404,
                detail="Workflow source project is not available in the active workspace.",
            )
        project_ids.add(project_id)
    return next(iter(project_ids)) if len(project_ids) == 1 else None


@app.middleware("http")
async def authentication_middleware(request: Request, call_next):
    path = request.url.path
    method = request.method.upper()

    if not path.startswith("/api/") or method == "OPTIONS":
        return await call_next(request)

    # CI and template publishing use their own dedicated tokens.
    if path.startswith("/api/ci/") or path == "/api/templates/publish":
        return await call_next(request)

    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        if origin not in settings.allowed_origin_list:
            return JSONResponse(
                status_code=403,
                content={"detail": "Invalid or missing Origin"},
            )

    if path == "/api/auth/login":
        return await call_next(request)
    if path == "/api/auth/logout" and method == "POST":
        return await call_next(request)

    token = request.cookies.get(SESSION_COOKIE)
    try:
        with SessionLocal() as db:
            session_context = get_session_context(db, token)
            if session_context is None:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Authentication required"},
                )
            user, user_session = session_context
            request.state.user = user
            request.state.user_session_id = user_session.id
            request.state.current_workspace_id = user_session.current_workspace_id
            db.commit()
    except SQLAlchemyError:
        return JSONResponse(
            status_code=503,
            content={"detail": "Authentication service unavailable"},
        )

    return await call_next(request)

@app.get("/api/ai/status")
def ai_provider_status():
    """Expose provider readiness without ever returning the API key."""
    return provider_configuration()


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
def upload_source(request: Request, file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=415, detail="Загрузите ZIP-архив проекта.")
    project_id = uuid4()
    workspace_path = f"projects/project-{project_id}"
    try:
        with SessionLocal() as session:
            workspace, _ = require_active_workspace(session, request, allowed_roles={"admin", "editor"})
        result = extract_project_archive(file.file, settings.workspace_root, workspace_path)
        with SessionLocal() as session:
            workspace, _ = require_active_workspace(session, request, allowed_roles={"admin", "editor"})
            project = Project(
                id=project_id,
                workspace_id=workspace.id,
                name=_safe_project_name(file.filename),
                workspace_path=workspace_path,
                original_filename=Path(file.filename).name[:255],
                file_count=result["files"],
                expanded_bytes=result["expanded_bytes"],
            )
            session.add(project)
            session.add(AuditLog(
                action="project.created",
                entity="project",
                entity_id=str(project_id),
                details={"file_count": result["files"], "expanded_bytes": result["expanded_bytes"], "source": "source-upload"},
            ))
            session.commit()
            return {
                **result,
                "project_id": str(project.id),
                "source": "workspace-upload",
                "message": "Архив добавлен в активную рабочую область. Команды проекта не исполнялись.",
            }
    except ArchiveValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        shutil.rmtree(Path(settings.workspace_root) / workspace_path, ignore_errors=True)
        raise HTTPException(status_code=500, detail="Не удалось сохранить архив в рабочую директорию.") from exc
    finally:
        file.file.close()



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
    runs = session.scalars(select(WorkflowRun).where(WorkflowRun.status.in_(["queued", "running", "cancelling"]))).all()
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




def _project_path_is_sensitive(relative: PurePosixPath) -> bool:
    blocked = ("secret", "credential", "password", "token", "private", ".env")
    return any(token in part.lower() for part in relative.parts for token in blocked)


def _project_content_is_safe(content: str) -> bool:
    assignment = re.compile(r"(?i)\b(?:password|passwd|api[_-]?(?:key|token)|access[_-]?token|client[_-]?secret|secret|authorization|token)\b\s*[:=]\s*[\"']?[^,\s\"'#]{8,}")
    if "-----BEGIN " in content and "PRIVATE KEY-----" in content:
        return False
    return all(_redact(line) == line and not assignment.search(line) for line in content.splitlines())


PROJECT_EXPORT_TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".scss",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".md", ".txt", ".xml",
    ".gradle", ".kts", ".properties", ".sql", ".sh", ".ps1",
}


def _project_export_file_is_safe(relative: PurePosixPath, size: int, content: str | None = None) -> bool:
    if _project_path_is_sensitive(relative) or size < 0 or size > 512 * 1024 * 1024:
        return False
    if relative.suffix.lower() in PROJECT_EXPORT_TEXT_SUFFIXES:
        # Large text files are omitted rather than exported without a complete secret scan.
        if size > 1_000_000 or content is None:
            return False
        return _project_content_is_safe(content)
    return True


def _project_file_snapshot(root: Path) -> dict[str, dict[str, int | str]]:
    """Build a bounded, content-addressed manifest for safe project files."""
    manifest: dict[str, dict[str, int | str]] = {}
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories
            if name != ".git" and not (Path(current) / name).is_symlink()
        )
        for filename in sorted(filenames):
            item = Path(current) / filename
            if item.is_symlink():
                continue
            try:
                relative = item.relative_to(root).as_posix()
                stat = item.stat()
                if not item.is_file():
                    continue
                digest = hashlib.sha256()
                with item.open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(chunk)
                manifest[relative] = {"size": stat.st_size, "sha256": digest.hexdigest()}
            except OSError:
                continue
    return manifest


def _project_snapshot_diff(before: dict, after: dict) -> dict:
    old_paths, new_paths = set(before), set(after)
    added = sorted(new_paths - old_paths)
    removed = sorted(old_paths - new_paths)
    changed = sorted(
        path for path in old_paths & new_paths
        if before[path] != after[path]
    )
    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_count": len(changed),
        "compared_files": len(old_paths | new_paths),
        "added_files": added[:50],
        "removed_files": removed[:50],
        "changed_files": changed[:50],
        "sample_truncated": any(len(items) > 50 for items in (added, removed, changed)),
    }


@app.get("/api/projects")
def list_projects(request: Request):
    with SessionLocal() as session:
        workspace, _ = require_active_workspace(session, request)
        rows = session.scalars(select(Project).where(Project.workspace_id == workspace.id).order_by(Project.updated_at.desc(), Project.name)).all()
        return [_project_payload(item) for item in rows]


@app.post("/api/projects", status_code=201)
def create_project(request: Request, file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=415, detail="Загрузите ZIP-архив проекта.")
    project_id = uuid4()
    workspace_path = f"projects/project-{project_id}"
    staging_path = f"projects/.staging-{project_id}"
    try:
        with SessionLocal() as session:
            workspace, _ = require_active_workspace(session, request, allowed_roles={"admin", "editor"})
        result = extract_project_archive(file.file, settings.workspace_root, staging_path)
        root = Path(settings.workspace_root).resolve()
        destination = root / workspace_path
        result_path = root / staging_path
        result_path.rename(destination)
        with SessionLocal() as session:
            workspace, _ = require_active_workspace(session, request, allowed_roles={"admin", "editor"})
            project = Project(
                id=project_id,
                workspace_id=workspace.id,
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
def update_project_archive(project_id: UUID, request: Request, file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=415, detail="Загрузите ZIP-архив проекта.")
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id, write=True)
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
            before_snapshot = _project_file_snapshot(destination)
            result = extract_project_archive(file.file, root, staging_path)
            after_snapshot = _project_file_snapshot(staging)
            changes = _project_snapshot_diff(before_snapshot, after_snapshot)
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
                "file_count": result["files"], "expanded_bytes": result["expanded_bytes"],
                "changes": changes,
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
def rename_project(project_id: UUID, payload: ProjectRename, request: Request):
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id, write=True)
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
def delete_project(project_id: UUID, request: Request):
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id, write=True)
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



@app.get("/api/projects/{project_id}/history")
def project_history(project_id: UUID, request: Request):
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        rows = session.scalars(
            select(AuditLog)
            .where(AuditLog.entity == "project", AuditLog.entity_id == str(project_id))
            .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
            .limit(30)
        ).all()
        return [
            {
                "action": row.action,
                "created_at": row.created_at,
                "details": row.details or {},
            }
            for row in rows
        ]


@app.get("/api/projects/{project_id}/files")
def list_project_files(project_id: UUID, request: Request):
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id)
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



class ProjectFileUpdate(BaseModel):
    content: str = Field(max_length=1_000_000)
    expected_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    ai_fix_run_id: UUID | None = None
    ai_fix_fingerprint: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

class ProjectFileRollback(BaseModel):
    target_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


@app.get("/api/projects/{project_id}/file")
def preview_project_file(
    project_id: UUID,
    request: Request,
    path: str = Query(min_length=1, max_length=1000),
    start_line: int = Query(default=1, ge=1),
):
    relative = PurePosixPath(path)
    if relative.is_absolute() or "\\" in path or "\x00" in path or any(part in {"", ".", ".."} for part in relative.parts):
        raise HTTPException(status_code=400, detail="Invalid project file path")
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id)
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
        safe_name = not _project_path_is_sensitive(relative)
        editable_suffixes = {".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".scss", ".json", ".yaml", ".yml", ".toml", ".ini", ".md", ".txt", ".xml", ".gradle", ".kts", ".properties", ".sql", ".sh", ".ps1"}
        editable = safe_name and relative.suffix.lower() in editable_suffixes and _project_content_is_safe(content)
        first = min(start_line, max(1, len(lines)))
        last = min(len(lines), first + 299)
        return {
            "path": relative.as_posix(),
            "start_line": first,
            "end_line": last,
            "total_lines": len(lines),
            "sha256": sha256_text(content),
            "editable": editable,
            "content": content if editable else None,
            "lines": [{"line": number, "text": _redact(lines[number - 1])[:1000]} for number in range(first, last + 1)],
        }


@app.get("/api/projects/{project_id}/download")
def download_project_archive(project_id: UUID, request: Request):
    """Export a project without VCS metadata, symlinks, or likely credentials."""
    max_archive_bytes = 1024 * 1024 * 1024
    temporary_path = None
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        root = _project_root(project)
        try:
            fd, temporary_path = tempfile.mkstemp(prefix="invest-project-", suffix=".zip")
            os.close(fd)
            included = 0
            skipped_sensitive = 0
            with zipfile.ZipFile(temporary_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
                for current, directories, filenames in os.walk(root, followlinks=False):
                    current_path = Path(current)
                    directories[:] = sorted(
                        name for name in directories
                        if name != ".git"
                        and not (current_path / name).is_symlink()
                        and not _project_path_is_sensitive(PurePosixPath((current_path / name).relative_to(root).as_posix()))
                    )
                    for filename in sorted(filenames):
                        source = current_path / filename
                        if source.is_symlink():
                            continue
                        relative = PurePosixPath(source.relative_to(root).as_posix())
                        try:
                            if not source.is_file():
                                continue
                            size = source.stat().st_size
                            content = None
                            if relative.suffix.lower() in PROJECT_EXPORT_TEXT_SUFFIXES and size <= 1_000_000:
                                try:
                                    content = source.read_text(encoding="utf-8")
                                except (UnicodeDecodeError, OSError):
                                    content = None
                            if not _project_export_file_is_safe(relative, size, content):
                                skipped_sensitive += 1
                                continue
                            archive.write(source, arcname=relative.as_posix())
                            included += 1
                            if os.path.getsize(temporary_path) > max_archive_bytes:
                                raise HTTPException(status_code=413, detail="Экспорт ограничен размером ZIP до 1 GiB.")
                        except OSError:
                            continue
            if included == 0:
                raise HTTPException(status_code=404, detail="В проекте нет файлов, доступных для экспорта.")
            session.add(AuditLog(
                action="project.exported",
                entity="project",
                entity_id=str(project_id),
                details={"included_files": included, "skipped_sensitive_files": skipped_sensitive},
            ))
            session.commit()
            safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", project.name).strip("-._") or "project"
            return FileResponse(
                temporary_path,
                media_type="application/zip",
                filename=f"{safe_name}.zip",
                background=BackgroundTask(os.unlink, temporary_path),
                headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
            )
        except HTTPException:
            if temporary_path and os.path.exists(temporary_path):
                os.unlink(temporary_path)
            raise
        except (OSError, zipfile.BadZipFile) as exc:
            if temporary_path and os.path.exists(temporary_path):
                os.unlink(temporary_path)
            raise HTTPException(status_code=500, detail="Не удалось сформировать ZIP-экспорт проекта.") from exc


@app.get("/api/projects/{project_id}/file/download")
def download_project_file(project_id: UUID, request: Request, path: str = Query(min_length=1, max_length=1000)):
    relative = PurePosixPath(path)
    if relative.is_absolute() or "\\" in path or "\x00" in path or any(part in {"", ".", ".."} for part in relative.parts):
        raise HTTPException(status_code=400, detail="Invalid project file path")
    if _project_path_is_sensitive(relative):
        raise HTTPException(status_code=404, detail="Project file is unavailable")
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id)
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
            if not resolved.is_relative_to(root) or not resolved.is_file():
                raise OSError("File is unavailable")
            size = resolved.stat().st_size
            if size > 100 * 1024 * 1024:
                raise HTTPException(status_code=413, detail="Скачивание одного файла ограничено 100 MiB.")
            content = None
            if relative.suffix.lower() in PROJECT_EXPORT_TEXT_SUFFIXES:
                if size > 1_000_000:
                    raise HTTPException(status_code=413, detail="Текстовые файлы больше 1 MiB нельзя скачать без полной проверки на секреты.")
                content = resolved.read_text(encoding="utf-8")
            if not _project_export_file_is_safe(relative, size, content):
                raise HTTPException(status_code=403, detail="Файл исключён из скачивания проверкой безопасности.")
        except HTTPException:
            raise
        except (OSError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=404, detail="Файл недоступен для скачивания.") from exc
        session.add(AuditLog(action="project.file_downloaded", entity="project", entity_id=str(project_id), details={
            "path": relative.as_posix(), "bytes": size,
        }))
        session.commit()
        return FileResponse(
            resolved,
            media_type="application/octet-stream",
            filename=resolved.name,
            content_disposition_type="attachment",
            headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
        )


@app.api_route("/api/projects/{project_id}/preview", methods=["GET", "HEAD"])
def preview_project_asset(
    project_id: UUID,
    request: Request,
    path: str = Query(min_length=1, max_length=1000),
):
    relative = PurePosixPath(path)
    if relative.is_absolute() or "\\" in path or "\x00" in path or any(part in {"", ".", ".."} for part in relative.parts):
        raise HTTPException(status_code=400, detail="Invalid project file path")
    allowed_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
        ".gif": "image/gif",
        ".pdf": "application/pdf",
    }
    media_type = allowed_types.get(relative.suffix.lower())
    if media_type is None:
        raise HTTPException(status_code=415, detail="Формат не поддерживает безопасный предпросмотр.")
    if _project_path_is_sensitive(relative):
        raise HTTPException(status_code=404, detail="Project file is unavailable")
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id)
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
            if not resolved.is_relative_to(root) or not resolved.is_file():
                raise OSError("File is unavailable")
            size = resolved.stat().st_size
            if size > 20 * 1024 * 1024:
                raise HTTPException(status_code=413, detail="Предпросмотр ограничен файлами до 20 MiB.")
        except HTTPException:
            raise
        except OSError as exc:
            raise HTTPException(status_code=404, detail="Файл недоступен для предпросмотра.") from exc
        return FileResponse(
            path=resolved,
            media_type=media_type,
            filename=resolved.name,
            content_disposition_type="inline",
            headers={
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'self'",
            },
        )


@app.put("/api/projects/{project_id}/file")
def update_project_file(project_id: UUID, request: Request, payload: ProjectFileUpdate, path: str = Query(min_length=1, max_length=1000)):
    relative = PurePosixPath(path)
    if relative.is_absolute() or "\\" in path or "\x00" in path or any(part in {"", ".", ".."} for part in relative.parts):
        raise HTTPException(status_code=400, detail="Invalid project file path")
    if relative.suffix.lower() not in {".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".scss", ".json", ".yaml", ".yml", ".toml", ".ini", ".md", ".txt", ".xml", ".gradle", ".kts", ".properties", ".sql", ".sh", ".ps1"}:
        raise HTTPException(status_code=415, detail="Этот тип файла нельзя редактировать в браузере.")
    if _project_path_is_sensitive(relative):
        raise HTTPException(status_code=403, detail="Файлы с потенциальными секретами доступны только для чтения.")
    if len(payload.content.encode("utf-8")) > 1_000_000:
        raise HTTPException(status_code=413, detail="Размер файла после UTF-8 кодирования превышает 1 MiB.")
    if not _project_content_is_safe(payload.content):
        raise HTTPException(status_code=400, detail="Сохранение отменено: содержимое похоже на секрет или учётные данные.")
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id, write=True)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        if _project_has_active_run(session, project):
            raise HTTPException(status_code=409, detail="Проект используется активным workflow; редактирование временно заблокировано.")
        ai_fix_metadata = None
        if payload.ai_fix_run_id is not None or payload.ai_fix_fingerprint is not None:
            if payload.ai_fix_run_id is None or payload.ai_fix_fingerprint is None:
                raise HTTPException(status_code=422, detail="AI Fix audit metadata must include both run ID and finding fingerprint.")
            ai_run = _run_in_active_workspace(session, request, payload.ai_fix_run_id)
            ai_finding = session.scalar(
                select(Finding).where(
                    Finding.run_id == payload.ai_fix_run_id,
                    Finding.fingerprint == payload.ai_fix_fingerprint,
                ).limit(1)
            )
            if ai_run is None or ai_finding is None:
                raise HTTPException(status_code=404, detail="AI Fix source finding is unavailable.")
            ai_payload = ai_finding.payload if isinstance(ai_finding.payload, dict) else {}
            if str(ai_payload.get("category", "")).upper() not in {"SAST", "SCA"}:
                raise HTTPException(status_code=403, detail="AI Fix audit metadata is not valid for this finding.")
            ai_result = ai_run.result if isinstance(ai_run.result, dict) else {}
            ai_outputs = ai_result.get("outputs", {}) if isinstance(ai_result.get("outputs"), dict) else {}
            ai_graph = ai_run.graph_snapshot if isinstance(ai_run.graph_snapshot, dict) else {}
            matching_source = None
            for node in ai_graph.get("nodes", []):
                if not isinstance(node, dict) or node.get("type") != "source.upload":
                    continue
                output = ai_outputs.get(node.get("id"), {})
                if isinstance(output, dict) and output.get("status") == "ready" and output.get("path") == project.workspace_path:
                    matching_source = output
                    break
            if matching_source is None:
                raise HTTPException(status_code=403, detail="AI Fix finding does not belong to this project.")
            canonical = PurePosixPath(_canonical_finding_path(ai_run, ai_finding.path))
            prefix = matching_source.get("project_subdirectory")
            expected_relative = (PurePosixPath(prefix) / canonical) if isinstance(prefix, str) and prefix else canonical
            if expected_relative.as_posix() != relative.as_posix():
                raise HTTPException(status_code=403, detail="AI Fix finding path does not match the edited file.")
            ai_fix_metadata = {
                "run_id": str(payload.ai_fix_run_id),
                "fingerprint": payload.ai_fix_fingerprint,
            }

        root = _project_root(project)
        try:
            # The OS-backed lock serializes writers across API/worker processes sharing this workspace.
            with project_file_lock(settings.workspace_root, project_id, relative):
                candidate = root.joinpath(*relative.parts)
                current = candidate
                while current != root:
                    if current.is_symlink():
                        raise HTTPException(status_code=404, detail="Project file is unavailable")
                    current = current.parent
                resolved = candidate.resolve(strict=True)
                if not resolved.is_relative_to(root) or not resolved.is_file() or resolved.stat().st_size > 1_000_000:
                    raise OSError("File is unavailable or too large")
                original = resolved.read_text(encoding="utf-8")
                if not _project_content_is_safe(original):
                    raise HTTPException(status_code=403, detail="Файл содержит потенциальные секреты и доступен только для чтения.")
                current_sha256 = sha256_text(original)
                if not version_matches(original, payload.expected_sha256):
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "code": "PROJECT_FILE_VERSION_CONFLICT",
                            "message": "Файл изменился после открытия. Обнови его перед сохранением, чтобы не затереть чужие изменения.",
                            "current_sha256": current_sha256,
                        },
                    )
                save_project_file_version(settings.workspace_root, project_id, relative, original)
                temp_name = None
                try:
                    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", dir=resolved.parent, prefix=".invest-edit-", delete=False) as temporary:
                        temp_name = temporary.name
                        temporary.write(payload.content)
                        temporary.flush()
                        os.fsync(temporary.fileno())
                    os.replace(temp_name, resolved)
                finally:
                    if temp_name and os.path.exists(temp_name):
                        os.unlink(temp_name)
                session.add(AuditLog(action="project.file_updated", entity="project", entity_id=str(project_id), details={
                    "path": relative.as_posix(),
                    "bytes": len(payload.content.encode("utf-8")),
                    "previous_sha256": current_sha256,
                    "new_sha256": sha256_text(payload.content),
                    "change_source": "ai_fix" if ai_fix_metadata else "manual",
                    **({
                        "ai_fix_run_id": ai_fix_metadata["run_id"],
                        "ai_fix_fingerprint": ai_fix_metadata["fingerprint"],
                    } if ai_fix_metadata else {}),
                }))
                session.commit()
        except FileLockTimeout as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "PROJECT_FILE_UPDATE_IN_PROGRESS",
                    "message": "Этот файл уже сохраняется в другом запросе. Повтори попытку через несколько секунд.",
                },
            ) from exc
        except HTTPException:
            raise
        except (OSError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=400, detail="Не удалось сохранить файл. Проверь размер и кодировку UTF-8.") from exc
    return {"saved": True, "path": relative.as_posix(), "bytes": len(payload.content.encode("utf-8"))}


@app.get("/api/projects/{project_id}/file-versions")
def list_project_file_versions(project_id: UUID, request: Request, path: str = Query(min_length=1, max_length=1000)):
    relative = PurePosixPath(path)
    if relative.is_absolute() or "\\" in path or "\x00" in path or any(part in {"", ".", ".."} for part in relative.parts):
        raise HTTPException(status_code=400, detail="Invalid project file path")
    if _project_path_is_sensitive(relative):
        raise HTTPException(status_code=403, detail="История файлов с потенциальными секретами недоступна.")
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id)
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
            raise HTTPException(status_code=404, detail="Файл недоступен для просмотра истории.") from exc
        if not _project_content_is_safe(content):
            raise HTTPException(status_code=403, detail="История файла с потенциальными секретами недоступна.")
        current_sha = sha256_text(content)
        rows = session.scalars(
            select(AuditLog)
            .where(
                AuditLog.entity == "project",
                AuditLog.entity_id == str(project_id),
                AuditLog.action.in_(["project.file_updated", "project.file_rolled_back"]),
            )
            .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
            .limit(200)
        ).all()
        versions = [{"sha256": current_sha, "current": True, "available": True, "created_at": None, "source": "current"}]
        seen = {current_sha}
        for row in rows:
            details = row.details if isinstance(row.details, dict) else {}
            digest = details.get("previous_sha256")
            if details.get("path") != relative.as_posix() or not isinstance(digest, str) or len(digest) != 64 or digest in seen:
                continue
            seen.add(digest)
            try:
                load_project_file_version(settings.workspace_root, project_id, relative, digest)
                available = True
            except (OSError, UnicodeDecodeError, ValueError):
                available = False
            versions.append({
                "sha256": digest,
                "current": False,
                "available": available,
                "created_at": row.created_at,
                "source": "rollback" if row.action == "project.file_rolled_back" else "edit",
            })
        return {"path": relative.as_posix(), "current_sha256": current_sha, "versions": versions}


@app.post("/api/projects/{project_id}/file-rollback")
def rollback_project_file(
    project_id: UUID,
    request: Request,
    payload: ProjectFileRollback,
    path: str = Query(min_length=1, max_length=1000),
):
    relative = PurePosixPath(path)
    if relative.is_absolute() or "\\" in path or "\x00" in path or any(part in {"", ".", ".."} for part in relative.parts):
        raise HTTPException(status_code=400, detail="Invalid project file path")
    if relative.suffix.lower() not in {".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".scss", ".json", ".yaml", ".yml", ".toml", ".ini", ".md", ".txt", ".xml", ".gradle", ".kts", ".properties", ".sql", ".sh", ".ps1"}:
        raise HTTPException(status_code=415, detail="Этот тип файла нельзя восстановить через браузер.")
    if _project_path_is_sensitive(relative):
        raise HTTPException(status_code=403, detail="Файлы с потенциальными секретами нельзя восстанавливать через браузер.")
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id, write=True)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        if _project_has_active_run(session, project):
            raise HTTPException(status_code=409, detail="Проект используется активным workflow; восстановление временно заблокировано.")
        root = _project_root(project)
        try:
            with project_file_lock(settings.workspace_root, project_id, relative):
                candidate = root.joinpath(*relative.parts)
                current = candidate
                while current != root:
                    if current.is_symlink():
                        raise HTTPException(status_code=404, detail="Project file is unavailable")
                    current = current.parent
                resolved = candidate.resolve(strict=True)
                if not resolved.is_relative_to(root) or not resolved.is_file() or resolved.stat().st_size > 1_000_000:
                    raise OSError("File is unavailable or too large")
                current_content = resolved.read_text(encoding="utf-8")
                if not _project_content_is_safe(current_content):
                    raise HTTPException(status_code=403, detail="Текущий файл содержит потенциальные секреты; восстановление запрещено.")
                current_sha = sha256_text(current_content)
                if not version_matches(current_content, payload.expected_sha256):
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "code": "PROJECT_FILE_VERSION_CONFLICT",
                            "message": "Файл изменился после просмотра истории. Обнови историю перед восстановлением.",
                            "current_sha256": current_sha,
                        },
                    )
                if payload.target_sha256 == current_sha:
                    raise HTTPException(status_code=400, detail="Выбранная версия уже является текущей.")
                try:
                    target_content = load_project_file_version(settings.workspace_root, project_id, relative, payload.target_sha256)
                except FileNotFoundError as exc:
                    raise HTTPException(status_code=404, detail="Сохранённая версия не найдена. Восстановление невозможно.") from exc
                if not _project_content_is_safe(target_content):
                    raise HTTPException(status_code=403, detail="Сохранённая версия содержит потенциальные секреты.")
                save_project_file_version(settings.workspace_root, project_id, relative, current_content)
                temp_name = None
                try:
                    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", dir=resolved.parent, prefix=".invest-rollback-", delete=False) as temporary:
                        temp_name = temporary.name
                        temporary.write(target_content)
                        temporary.flush()
                        os.fsync(temporary.fileno())
                    os.replace(temp_name, resolved)
                    temp_name = None
                finally:
                    if temp_name and os.path.exists(temp_name):
                        os.unlink(temp_name)
                target_sha = sha256_text(target_content)
                session.add(AuditLog(
                    action="project.file_rolled_back",
                    entity="project",
                    entity_id=str(project_id),
                    details={
                        "path": relative.as_posix(),
                        "previous_sha256": current_sha,
                        "new_sha256": target_sha,
                        "rollback_target_sha256": payload.target_sha256,
                    },
                ))
                session.commit()
        except FileLockTimeout as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "PROJECT_FILE_UPDATE_IN_PROGRESS",
                    "message": "Этот файл уже изменяется другим запросом. Повтори попытку через несколько секунд.",
                },
            ) from exc
        except HTTPException:
            raise
        except (OSError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=400, detail="Не удалось восстановить сохранённую версию файла.") from exc
    return {"restored": True, "path": relative.as_posix(), "sha256": target_sha}


@app.get("/api/projects/{project_id}/search")
def search_project_contents(project_id: UUID, request: Request, q: str = Query(min_length=2, max_length=100)):
    needle = q.casefold()
    text_suffixes = {".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".scss", ".json", ".yaml", ".yml", ".toml", ".ini", ".md", ".txt", ".xml", ".gradle", ".kts", ".properties", ".sql", ".sh", ".ps1"}
    results = []
    scanned = 0
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        root = _project_root(project)
        for current, directories, filenames in os.walk(root, followlinks=False):
            directories[:] = [name for name in directories if name != ".git" and not (Path(current) / name).is_symlink()]
            for filename in filenames:
                if scanned >= 3000 or len(results) >= 100:
                    break
                item = Path(current) / filename
                if item.is_symlink() or item.suffix.lower() not in text_suffixes or _project_path_is_sensitive(PurePosixPath(item.relative_to(root).as_posix())):
                    continue
                try:
                    if item.stat().st_size > 512_000:
                        continue
                    content = item.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                scanned += 1
                for number, line in enumerate(content.splitlines(), 1):
                    if needle in line.casefold() and _redact(line) == line:
                        results.append({"path": item.relative_to(root).as_posix(), "line": number, "text": line.strip()[:240]})
                        if len(results) >= 100:
                            break
            if scanned >= 3000 or len(results) >= 100:
                break
    return {"results": results, "scanned_files": scanned, "truncated": len(results) >= 100 or scanned >= 3000}


@app.get("/api/rule-packs")
def list_rule_packs(analyzer: str | None = Query(default=None, pattern="^(secrets|sca|sast|policy)$")):
    """List repository-owned, validated rule packs for configuration forms."""
    return rule_packs.list(analyzer=analyzer)


@app.get("/api/node-types")
def node_types():
    return [manifest.model_dump() for manifest in registry.all()]


@app.post("/api/workflows/generate")
def generate_workflow_draft(payload: WorkflowGenerateRequest, request: Request):
    with SessionLocal() as session:
        require_active_workspace(session, request, allowed_roles={"admin", "editor"})
    try:
        return generate_workflow_graph(payload.prompt)
    except WorkflowGenerationError as exc:
        message = str(exc)
        status = 503 if "Настройте LLM_" in message or "endpoint" in message.lower() else 422
        raise HTTPException(status_code=status, detail=message) from exc


@app.post("/api/workflows/validate")
def validate_workflow(graph: WorkflowGraph):
    return validate_graph(graph, registry).model_dump()


@app.get("/api/workflows")
def list_workflows(request: Request):
    with SessionLocal() as session:
        workspace, _ = require_active_workspace(session, request)
        rows = session.scalars(select(Workflow).where(Workflow.workspace_id == workspace.id).order_by(Workflow.updated_at.desc())).all()
        return [
            {"id": str(item.id), "name": item.name, "description": item.description, "updated_at": item.updated_at}
            for item in rows
        ]


@app.post("/api/workflows", status_code=201)
def create_workflow(graph: WorkflowGraph, request: Request):
    validation = validate_graph(graph, registry)
    if not validation.valid:
        raise HTTPException(status_code=422, detail=validation.model_dump())
    with SessionLocal() as session:
        workspace, _ = require_active_workspace(session, request, allowed_roles={"admin", "editor"})
        linked_project_id = _validate_graph_workspace_sources(session, workspace.id, graph)
        workflow = Workflow(name=graph.name, workspace_id=workspace.id, project_id=linked_project_id)
        session.add(workflow)
        session.flush()
        session.add(WorkflowVersion(workflow_id=workflow.id, version=1, graph=graph.model_dump(mode="json")))
        session.commit()
        return {"id": str(workflow.id), "name": workflow.name, "version": 1}


@app.get("/api/workflows/{workflow_id}")
def get_workflow(workflow_id: UUID, request: Request):
    with SessionLocal() as session:
        workflow = _workflow_in_active_workspace(session, request, workflow_id)
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
def update_workflow(workflow_id: UUID, graph: WorkflowGraph, request: Request):
    validation = validate_graph(graph, registry)
    if not validation.valid:
        raise HTTPException(status_code=422, detail=validation.model_dump())
    with SessionLocal() as session:
        active_workflow = _workflow_in_active_workspace(session, request, workflow_id, write=True)
        active_workflow.project_id = _validate_graph_workspace_sources(session, active_workflow.workspace_id, graph)
        _workflow_lock = _lock_workflow_for_version_write(session, workflow_id)
        workflow = _workflow_lock
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
        graph_data = graph.model_dump(mode="json")
        session.add(WorkflowVersion(workflow_id=workflow_id, version=version, graph=graph_data))
        active_schedule = session.scalar(
            select(WorkflowSchedule).where(WorkflowSchedule.workflow_id == workflow_id)
        )
        if active_schedule is not None and active_schedule.enabled:
            schedule_nodes = [node for node in graph.nodes if node.type == "trigger.schedule"]
            if len(schedule_nodes) != 1:
                active_schedule.enabled = False
                active_schedule.next_run_at = None
            else:
                schedule_config = schedule_nodes[0].config
                expression = str(schedule_config.get("cron", "")).strip()
                timezone_name = str(schedule_config.get("timezone", "UTC")).strip() or "UTC"
                try:
                    zone = ZoneInfo(timezone_name)
                    valid_cron = len(expression.split()) == 5 and croniter.is_valid(expression)
                except (ValueError, KeyError):
                    valid_cron = False
                    zone = None
                if not valid_cron:
                    active_schedule.enabled = False
                    active_schedule.next_run_at = None
                elif expression != active_schedule.cron_expression or timezone_name != active_schedule.timezone:
                    now = datetime.now(timezone.utc)
                    active_schedule.cron_expression = expression
                    active_schedule.timezone = timezone_name
                    active_schedule.next_run_at = croniter(expression, now.astimezone(zone)).get_next(datetime).astimezone(timezone.utc)
        session.commit()
        return {"id": str(workflow.id), "name": workflow.name, "version": version}


@app.get("/api/workflows/{workflow_id}/schedule")
def get_workflow_schedule(workflow_id: UUID, request: Request):
    with SessionLocal() as session:
        workflow = _workflow_in_active_workspace(session, request, workflow_id)
        if workflow is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        schedule = session.scalar(
            select(WorkflowSchedule).where(WorkflowSchedule.workflow_id == workflow_id)
        )
        if schedule is None:
            return {"enabled": False, "configured": False}
        return {
            "enabled": schedule.enabled,
            "configured": True,
            "cron": schedule.cron_expression,
            "timezone": schedule.timezone,
            "next_run_at": schedule.next_run_at,
            "last_run_at": schedule.last_run_at,
        }


@app.put("/api/workflows/{workflow_id}/schedule")
def update_workflow_schedule(workflow_id: UUID, payload: WorkflowScheduleUpdate, request: Request):
    with SessionLocal() as session:
        _workflow_in_active_workspace(session, request, workflow_id, write=True)
        workflow = _lock_workflow_for_version_write(session, workflow_id)
        if workflow is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        schedule = session.scalar(
            select(WorkflowSchedule).where(WorkflowSchedule.workflow_id == workflow_id)
        )
        if schedule is not None:
            schedule = _lock_schedule_for_update(session, workflow_id, schedule.id)
        if not payload.enabled:
            if schedule is not None:
                schedule.enabled = False
                schedule.next_run_at = None
                session.commit()
            return {"enabled": False, "configured": schedule is not None}

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
        triggers = [node for node in graph.nodes if node.type == "trigger.schedule"]
        if len(triggers) != 1:
            raise HTTPException(status_code=422, detail="Добавьте ровно одну Schedule trigger ноду.")
        config = triggers[0].config
        expression = str(config.get("cron", "")).strip()
        timezone_name = str(config.get("timezone", "UTC")).strip() or "UTC"
        if len(expression.split()) != 5 or not croniter.is_valid(expression):
            raise HTTPException(status_code=422, detail="Укажите корректное cron-выражение из пяти полей.")
        try:
            zone = ZoneInfo(timezone_name)
        except (ValueError, KeyError) as exc:
            raise HTTPException(status_code=422, detail="Укажите существующий IANA timezone.") from exc
        now = datetime.now(timezone.utc)
        next_run = croniter(expression, now.astimezone(zone)).get_next(datetime).astimezone(timezone.utc)
        if schedule is None:
            schedule = WorkflowSchedule(
                workflow_id=workflow_id,
                cron_expression=expression,
                timezone=timezone_name,
                enabled=True,
                next_run_at=next_run,
            )
            session.add(schedule)
        else:
            schedule.cron_expression = expression
            schedule.timezone = timezone_name
            schedule.enabled = True
            schedule.next_run_at = next_run
        session.add(AuditLog(
            action="workflow.schedule.updated",
            entity="workflow",
            entity_id=str(workflow_id),
            details={"enabled": True, "cron": expression, "timezone": timezone_name},
        ))
        session.commit()
        return {
            "enabled": True,
            "configured": True,
            "cron": expression,
            "timezone": timezone_name,
            "next_run_at": next_run,
        }


@app.post("/api/workflows/{workflow_id}/runs", status_code=202)
def execute_saved_workflow(workflow_id: UUID, request: Request, force_full_scan: bool = Query(default=False)):
    """Persist a run request; the dedicated worker performs the scan asynchronously."""
    with SessionLocal() as session:
        workflow = _workflow_in_active_workspace(session, request, workflow_id, write=True)
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
        _validate_graph_workspace_sources(session, workflow.workspace_id, graph)

        graph_snapshot = dict(version.graph)
        graph_snapshot["__execution_scope"] = {"requested_node_ids": [], "force_full_scan": force_full_scan}
        run = WorkflowRun(
            workflow_id=workflow_id,
            status="queued",
            source="ui",
            graph_snapshot=graph_snapshot,
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


@app.post("/api/ci/workflows/{workflow_id}/runs", status_code=202)
def execute_ci_workflow(workflow_id: UUID, x_ci_token: str = Header(default="", alias="X-CI-Token")):
    """Queue a saved workflow for CI; requires a dedicated secret and an explicit Security Gate."""
    with SessionLocal() as session:
        workflow = session.get(Workflow, workflow_id)
        if workflow is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        require_workspace_api_token(session, x_ci_token, workflow.workspace_id, "workflow:run")
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
        _validate_graph_workspace_sources(session, workflow.workspace_id, graph)
        gate_nodes = [node for node in graph.nodes if node.type == "ci.gate"]
        if len(gate_nodes) != 1:
            raise HTTPException(status_code=422, detail="CI workflow must contain exactly one Security Gate node")
        gate_node = gate_nodes[0]
        nodes_by_id = {node.id: node for node in graph.nodes}
        gate_merge_ids = {
            edge.source for edge in graph.edges
            if edge.target == gate_node.id
            and edge.source in nodes_by_id
            and nodes_by_id[edge.source].type == "findings.merge"
        }
        if not gate_merge_ids:
            raise HTTPException(status_code=422, detail="Security Gate must receive findings from a Merge findings node")
        has_scanner_input = any(
            edge.target in gate_merge_ids
            and edge.source in nodes_by_id
            and nodes_by_id[edge.source].type in {"scan.secrets", "scan.sca", "scan.sast"}
            for edge in graph.edges
        )
        if not has_scanner_input:
            raise HTTPException(status_code=422, detail="The findings merge connected to Security Gate must receive at least one scanner output")
        snapshot = graph.model_dump(mode="json")
        snapshot["__execution_scope"] = {"requested_node_ids": [], "force_full_scan": False}
        run = WorkflowRun(
            workflow_id=workflow_id,
            status="queued",
            source="ci",
            graph_snapshot=snapshot,
        )
        session.add(run)
        session.commit()
        return {
            "run_id": str(run.id),
            "workflow_id": str(workflow_id),
            "workflow_version": version.version,
            "status": "queued",
        }


@app.get("/api/ci/runs/{run_id}")
def get_ci_run(run_id: UUID, x_ci_token: str = Header(default="", alias="X-CI-Token")):
    """Return a minimal CI polling contract without exposing findings or source excerpts."""
    with SessionLocal() as session:
        run = session.scalar(
            select(WorkflowRun)
            .join(Workflow, Workflow.id == WorkflowRun.workflow_id)
            .where(WorkflowRun.id == run_id)
        )
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        workflow = session.get(Workflow, run.workflow_id)
        if workflow is None:
            raise HTTPException(status_code=404, detail="Run not found")
        require_workspace_api_token(session, x_ci_token, workflow.workspace_id, "run:read")
        result = run.result if isinstance(run.result, dict) else {}
        gate = result.get("security_gate") if isinstance(result, dict) else None
        return {
            "id": str(run.id),
            "workflow_id": str(run.workflow_id) if run.workflow_id else None,
            "status": run.status,
            "security_gate": gate,
            "error": run.error,
            "finished_at": run.finished_at,
        }


@app.post("/api/workflows/{workflow_id}/runs/selected", status_code=202)
def execute_selected_workflow(workflow_id: UUID, request: Request, payload: SelectedRunRequest):
    with SessionLocal() as session:
        workflow = _workflow_in_active_workspace(session, request, workflow_id)
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
        _validate_graph_workspace_sources(session, workflow.workspace_id, graph)
        known_ids = {node.id for node in graph.nodes}
        unknown = sorted(set(payload.node_ids) - known_ids)
        if unknown:
            raise HTTPException(status_code=422, detail={"message": "Выбраны отсутствующие блоки.", "unknown_node_ids": unknown})
        snapshot = graph.model_dump(mode="json")
        known_force_ids = set(payload.force_node_ids)
        if not known_force_ids.issubset(known_ids):
            raise HTTPException(status_code=422, detail={"message": "Для сброса кэша выбраны неизвестные блоки.", "unknown_node_ids": sorted(known_force_ids - known_ids)})
        snapshot["__execution_scope"] = {"requested_node_ids": payload.node_ids, "force_full_scan": payload.force_full_scan, "force_node_ids": payload.force_node_ids}
        run = WorkflowRun(
            workflow_id=workflow_id,
            status="queued",
            source="selected",
            graph_snapshot=snapshot,
        )
        session.add(run)
        session.commit()
        return {
            "run_id": str(run.id),
            "workflow_id": str(workflow_id),
            "workflow_version": version.version,
            "requested_node_ids": payload.node_ids,
            "status": "queued",
        }


@app.get("/api/workflows/{workflow_id}/versions")
def list_workflow_versions(workflow_id: UUID, request: Request):
    with SessionLocal() as session:
        workflow = _workflow_in_active_workspace(session, request, workflow_id)
        if workflow is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        versions = session.scalars(
            select(WorkflowVersion)
            .where(WorkflowVersion.workflow_id == workflow_id)
            .order_by(WorkflowVersion.version.desc())
        ).all()
        return [
            {
                "version": item.version,
                "created_at": item.created_at,
                "name": item.graph.get("name", workflow.name) if isinstance(item.graph, dict) else workflow.name,
                "node_count": len(item.graph.get("nodes", [])) if isinstance(item.graph, dict) else 0,
                "edge_count": len(item.graph.get("edges", [])) if isinstance(item.graph, dict) else 0,
            }
            for item in versions
        ]


@app.get("/api/workflows/{workflow_id}/versions/compare")
def compare_workflow_versions(
    workflow_id: UUID,
    request: Request,
    from_version: int = Query(ge=1),
    to_version: int = Query(ge=1),
):
    if from_version == to_version:
        raise HTTPException(status_code=422, detail="Выберите две разные версии.")
    with SessionLocal() as session:
        if _workflow_in_active_workspace(session, request, workflow_id) is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        rows = session.scalars(select(WorkflowVersion).where(
            WorkflowVersion.workflow_id == workflow_id,
            WorkflowVersion.version.in_([from_version, to_version]),
        )).all()
        by_version = {item.version: item for item in rows}
        if from_version not in by_version or to_version not in by_version:
            raise HTTPException(status_code=404, detail="Workflow version not found")
        return {"from_version": from_version, "to_version": to_version,
                **_compare_workflow_graphs(by_version[from_version].graph, by_version[to_version].graph)}


@app.post("/api/workflows/{workflow_id}/versions/{version}/restore", status_code=201)
def restore_workflow_version(workflow_id: UUID, version: int, request: Request):
    with SessionLocal() as session:
        _workflow_in_active_workspace(session, request, workflow_id, write=True)
        workflow = _lock_workflow_for_version_write(session, workflow_id)
        if workflow is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        source_version = session.scalar(
            select(WorkflowVersion).where(
                WorkflowVersion.workflow_id == workflow_id,
                WorkflowVersion.version == version,
            )
        )
        if source_version is None:
            raise HTTPException(status_code=404, detail="Workflow version not found")
        graph = WorkflowGraph.model_validate(source_version.graph)
        validation = validate_graph(graph, registry)
        if not validation.valid:
            raise HTTPException(status_code=422, detail=validation.model_dump())
        workflow.project_id = _validate_graph_workspace_sources(session, workflow.workspace_id, graph)
        latest = session.scalar(
            select(WorkflowVersion)
            .where(WorkflowVersion.workflow_id == workflow_id)
            .order_by(WorkflowVersion.version.desc())
            .limit(1)
        )
        next_version = (latest.version if latest else 0) + 1
        workflow.name = graph.name
        session.add(WorkflowVersion(
            workflow_id=workflow_id,
            version=next_version,
            graph=graph.model_dump(mode="json"),
        ))
        session.commit()
        return {"id": str(workflow.id), "restored_from": version, "version": next_version, "name": workflow.name}


@app.post("/api/runs/{run_id}/cancel")
def cancel_workflow_run(run_id: UUID, request: Request):
    with SessionLocal() as session:
        run = _run_in_active_workspace(session, request, run_id, write=True)
        run = _lock_run_for_update(session, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        if run.status in {"completed", "partial", "failed", "cancelled"}:
            raise HTTPException(status_code=409, detail=f"Run is already {run.status}")
        if run.status == "queued":
            run.status = "cancelled"
            run.finished_at = datetime.now(timezone.utc)
            run.error = "Cancelled before worker claimed the run"
        elif run.status == "running":
            run.status = "cancelling"
        elif run.status != "cancelling":
            raise HTTPException(status_code=409, detail=f"Run cannot be cancelled from status {run.status}")
        session.commit()
        return {"run_id": str(run.id), "status": run.status}


@app.post("/api/runs/{run_id}/retry", status_code=202)
def retry_workflow_run(run_id: UUID, request: Request):
    with SessionLocal() as session:
        _run_in_active_workspace(session, request, run_id, write=True)
        previous = _lock_run_for_update(session, run_id)
        if previous is None:
            raise HTTPException(status_code=404, detail="Run not found")
        if previous.status not in {"completed", "partial", "failed", "cancelled"}:
            raise HTTPException(status_code=409, detail="Only finished runs can be retried")
        graph = WorkflowGraph.model_validate(previous.graph_snapshot)
        validation = validate_graph(graph, registry)
        if not validation.valid:
            raise HTTPException(status_code=422, detail=validation.model_dump())
        retry = WorkflowRun(
            workflow_id=previous.workflow_id,
            status="queued",
            source="retry",
            graph_snapshot=previous.graph_snapshot,
        )
        session.add(retry)
        session.commit()
        return {"run_id": str(retry.id), "retry_of": str(previous.id), "status": "queued"}


@app.get("/api/workflows/{workflow_id}/runs")
def list_workflow_runs(workflow_id: UUID, request: Request):
    with SessionLocal() as session:
        if _workflow_in_active_workspace(session, request, workflow_id) is None:
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

@app.get("/api/workflows/{workflow_id}/security-trend")
def workflow_security_trend(
    workflow_id: UUID,
    request: Request,
    limit: int = Query(default=20, ge=2, le=100),
):
    """Return a bounded chronological security trend for the workflow."""
    with SessionLocal() as session:
        if _workflow_in_active_workspace(session, request, workflow_id) is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        rows = session.scalars(
            select(WorkflowRun)
            .where(WorkflowRun.workflow_id == workflow_id)
            .where(WorkflowRun.status.in_(["completed", "partial", "failed", "cancelled"]))
            .order_by(WorkflowRun.queued_at.desc())
            .limit(limit)
        ).all()
        points = []
        for run in reversed(rows):
            telemetry = _run_telemetry(session, run)
            points.append({
                "run_id": str(run.id),
                "status": run.status,
                "queued_at": run.queued_at,
                "finished_at": run.finished_at,
                "duration_ms": telemetry.get("duration_ms"),
                "total_findings": telemetry.get("total_findings", 0),
                "severity": telemetry.get("severity", {}),
                "security_gate": telemetry.get("security_gate"),
            })
        return {
            "workflow_id": str(workflow_id),
            "limit": limit,
            "points": points,
            "summary": {
                "runs": len(points),
                "latest_findings": points[-1]["total_findings"] if points else 0,
                "previous_findings": points[-2]["total_findings"] if len(points) > 1 else None,
                "delta": (
                    points[-1]["total_findings"] - points[-2]["total_findings"]
                    if len(points) > 1 else None
                ),
            },
        }



def _compare_scanner_runs(before_result: dict, after_result: dict) -> dict:
    """Compare cache use and scanner-specific findings across two runs."""
    scanner_types = {"scan.secrets", "scan.sca", "scan.sast"}
    before_trace = {str(item.get("node_id")): item for item in before_result.get("trace", []) if isinstance(item, dict) and item.get("type") in scanner_types and item.get("node_id")}
    after_trace = {str(item.get("node_id")): item for item in after_result.get("trace", []) if isinstance(item, dict) and item.get("type") in scanner_types and item.get("node_id")}
    before_outputs = before_result.get("outputs", {}) if isinstance(before_result.get("outputs"), dict) else {}
    after_outputs = after_result.get("outputs", {}) if isinstance(after_result.get("outputs"), dict) else {}
    before_meta = before_result.get("cache_metadata", {}) if isinstance(before_result.get("cache_metadata"), dict) else {}
    after_meta = after_result.get("cache_metadata", {}) if isinstance(after_result.get("cache_metadata"), dict) else {}
    scanners = []
    for node_id in sorted(set(before_trace) | set(after_trace)):
        old_trace, new_trace = before_trace.get(node_id), after_trace.get(node_id)
        old_output, new_output = before_outputs.get(node_id, {}), after_outputs.get(node_id, {})
        old_findings = {str(item.get("fingerprint")): item for item in old_output.get("findings", []) if isinstance(item, dict) and item.get("fingerprint")} if isinstance(old_output, dict) else {}
        new_findings = {str(item.get("fingerprint")): item for item in new_output.get("findings", []) if isinstance(item, dict) and item.get("fingerprint")} if isinstance(new_output, dict) else {}
        old_ids, new_ids = set(old_findings), set(new_findings)
        old_metadata, new_metadata = before_meta.get(node_id), after_meta.get(node_id)
        source_changed = None
        if isinstance(old_metadata, dict) and isinstance(new_metadata, dict) and old_metadata.get("source_hash") and new_metadata.get("source_hash"):
            source_changed = old_metadata["source_hash"] != new_metadata["source_hash"]
        scanners.append({
            "node_id": node_id, "type": (new_trace or old_trace).get("type"),
            "before_present": old_trace is not None, "after_present": new_trace is not None,
            "before_cached": old_trace.get("cached") is True if old_trace else None,
            "after_cached": new_trace.get("cached") is True if new_trace else None,
            "before_cache_age_seconds": old_trace.get("cache_age_seconds") if old_trace else None,
            "after_cache_age_seconds": new_trace.get("cache_age_seconds") if new_trace else None,
            "source_changed": source_changed,
            "before_findings": len(old_ids), "after_findings": len(new_ids),
            "added_findings": len(new_ids - old_ids), "removed_findings": len(old_ids - new_ids),
        })
    before_hits = sum(1 for item in before_trace.values() if item.get("cached") is True)
    after_hits = sum(1 for item in after_trace.values() if item.get("cached") is True)
    return {"cache_comparison": {"before_hits": before_hits, "after_hits": after_hits, "delta_hits": after_hits - before_hits, "before_scanners": len(before_trace), "after_scanners": len(after_trace)}, "scanner_comparison": scanners}

def _compare_run_snapshots(before: dict, after: dict) -> dict:
    """Compare two completed scan snapshots without treating partial absence as a fix."""
    old_findings = {
        str(item.get("fingerprint")): item
        for item in before.get("findings", [])
        if isinstance(item, dict) and item.get("fingerprint")
    }
    new_findings = {
        str(item.get("fingerprint")): item
        for item in after.get("findings", [])
        if isinstance(item, dict) and item.get("fingerprint")
    }
    old_ids, new_ids = set(old_findings), set(new_findings)
    complete_before = before.get("run", {}).get("status") == "completed" and not before.get("findings_truncated", False)
    complete_after = after.get("run", {}).get("status") == "completed" and not after.get("findings_truncated", False)

    def finding_summary(item: dict) -> dict:
        return {
            "fingerprint": item.get("fingerprint"),
            "rule_id": item.get("rule_id"),
            "severity": item.get("severity"),
            "path": item.get("path"),
            "line": item.get("line"),
        }

    candidate_added = [finding_summary(new_findings[key]) for key in sorted(new_ids - old_ids)]
    added = candidate_added if complete_before else []
    not_observed_before = [] if complete_before else candidate_added
    persisted = []
    for key in sorted(old_ids & new_ids):
        old, new = old_findings[key], new_findings[key]
        persisted.append({
            **finding_summary(new),
            "severity_changed": old.get("severity") != new.get("severity"),
            "previous_severity": old.get("severity"),
        })
    missing = [finding_summary(old_findings[key]) for key in sorted(old_ids - new_ids)]
    disappeared = missing if complete_after else []
    not_observed = [] if complete_after else missing

    old_trace = {
        str(item.get("node_id")): item
        for item in before.get("telemetry", {}).get("trace", [])
        if isinstance(item, dict) and item.get("node_id")
    }
    new_trace = {
        str(item.get("node_id")): item
        for item in after.get("telemetry", {}).get("trace", [])
        if isinstance(item, dict) and item.get("node_id")
    }
    node_changes = []
    for node_id in sorted(set(old_trace) | set(new_trace)):
        old, new = old_trace.get(node_id), new_trace.get(node_id)
        if old is None or new is None:
            node_changes.append({
                "node_id": node_id,
                "change": "added_to_trace" if old is None else "missing_from_trace",
                "before_status": old.get("status") if old else None,
                "after_status": new.get("status") if new else None,
            })
            continue
        fields = ("status", "duration_ms", "findings", "diagnostic_level", "reason_code")
        changes = {
            field: {"before": old.get(field), "after": new.get(field)}
            for field in fields if old.get(field) != new.get(field)
        }
        if changes:
            node_changes.append({"node_id": node_id, "change": "changed", "fields": changes})

    return {
        "findings": {
            "new": added,
            "not_observed_before": not_observed_before,
            "persisting": persisted,
            "disappeared": disappeared,
            "not_observed": not_observed,
            "absence_confirmed": complete_after,
            "summary": {
                "new": len(added),
                "not_observed_before": len(not_observed_before),
                "persisting": len(persisted),
                "disappeared": len(disappeared),
                "not_observed": len(not_observed),
            },
        },
        "nodes": node_changes,
        "summary": {
            "new_findings": len(added),
            "not_observed_before_findings": len(not_observed_before),
            "persisting_findings": len(persisted),
            "disappeared_findings": len(disappeared),
            "not_observed_findings": len(not_observed),
            "changed_nodes": len(node_changes),
        },
    }



def _compare_source_manifests(before_result: dict, after_result: dict) -> dict:
    """Compare immutable per-run file manifests; missing/incomplete data stays unknown."""
    old_sources = before_result.get("source_manifests", {}) if isinstance(before_result.get("source_manifests"), dict) else {}
    new_sources = after_result.get("source_manifests", {}) if isinstance(after_result.get("source_manifests"), dict) else {}
    source_ids = sorted(set(old_sources) | set(new_sources))
    per_source = []
    added_all, removed_all, modified_all = set(), set(), set()
    comparable = 0
    incomplete = False
    for node_id in source_ids:
        old = old_sources.get(node_id)
        new = new_sources.get(node_id)
        if not isinstance(old, dict) or not isinstance(new, dict):
            per_source.append({"node_id": node_id, "status": "source_added" if old is None else "source_removed",
                               "added_count": 0, "removed_count": 0, "modified_count": 0,
                               "added_files": [], "removed_files": [], "modified_files": []})
            incomplete = True
            continue
        if old.get("complete") is not True or new.get("complete") is not True:
            per_source.append({"node_id": node_id, "status": "manifest_incomplete",
                               "reason": new.get("reason") or old.get("reason"),
                               "added_count": None, "removed_count": None, "modified_count": None,
                               "added_files": [], "removed_files": [], "modified_files": []})
            incomplete = True
            continue
        old_files = old.get("files") if isinstance(old.get("files"), dict) else {}
        new_files = new.get("files") if isinstance(new.get("files"), dict) else {}
        old_paths, new_paths = set(old_files), set(new_files)
        added = new_paths - old_paths
        removed = old_paths - new_paths
        modified = {path for path in old_paths & new_paths if old_files[path] != new_files[path]}
        added_all.update(added)
        removed_all.update(removed)
        modified_all.update(modified)
        comparable += 1
        per_source.append({
            "node_id": node_id, "status": "compared",
            "added_count": len(added), "removed_count": len(removed), "modified_count": len(modified),
            "compared_files": len(old_paths | new_paths),
            "added_files": sorted(added)[:50], "removed_files": sorted(removed)[:50],
            "modified_files": sorted(modified)[:50],
            "sample_truncated": any(len(items) > 50 for items in (added, removed, modified)),
        })
    available = comparable > 0
    status = "unavailable" if not source_ids or not available else ("partial" if incomplete else "complete")
    return {
        "status": status, "comparable_sources": comparable,
        "added_count": len(added_all) if available else None,
        "removed_count": len(removed_all) if available else None,
        "modified_count": len(modified_all) if available else None,
        "added_files": sorted(added_all)[:100] if available else [],
        "removed_files": sorted(removed_all)[:100] if available else [],
        "modified_files": sorted(modified_all)[:100] if available else [],
        "sample_truncated": any(len(items) > 100 for items in (added_all, removed_all, modified_all)),
        "sources": per_source,
        "correlation_note": "Совпадение пути находки с изменённым файлом показывает корреляцию, а не доказывает причинную связь.",
    }


def _annotate_finding_source_relation(findings: list, source_comparison: dict) -> list:
    if not isinstance(findings, list):
        return []
    if source_comparison.get("status") not in {"complete", "partial"}:
        return [{**item, "source_relation": "unknown"} for item in findings if isinstance(item, dict)]
    added = set(source_comparison.get("added_files", []))
    removed = set(source_comparison.get("removed_files", []))
    modified = set(source_comparison.get("modified_files", []))
    fully_compared = source_comparison.get("status") == "complete"
    output = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        relation = "unknown"
        if isinstance(path, str) and path:
            if path in added:
                relation = "added_file"
            elif path in modified:
                relation = "modified_file"
            elif path in removed:
                relation = "removed_file"
            elif fully_compared:
                relation = "unchanged_file"
        output.append({**item, "source_relation": relation})
    return output



@app.get("/api/workflows/{workflow_id}/runs/compare")
def compare_workflow_runs(
    workflow_id: UUID,
    request: Request,
    from_run: UUID = Query(...),
    to_run: UUID = Query(...),
):
    if from_run == to_run:
        raise HTTPException(status_code=422, detail="Выберите два разных запуска.")
    terminal = {"completed", "partial", "failed", "cancelled"}
    with SessionLocal() as session:
        if _workflow_in_active_workspace(session, request, workflow_id) is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        before = session.get(WorkflowRun, from_run)
        after = session.get(WorkflowRun, to_run)
        if before is None or after is None:
            raise HTTPException(status_code=404, detail="Run not found")
        if before.workflow_id != workflow_id or after.workflow_id != workflow_id:
            raise HTTPException(status_code=404, detail="Run not found in this workflow")
        if before.status not in terminal or after.status not in terminal:
            raise HTTPException(status_code=409, detail="Сравнивать можно только завершённые запуски.")
        before_report = _build_run_report(session, before)
        after_report = _build_run_report(session, after)
        diff = _compare_run_snapshots(before_report, after_report)
        before_result = before.result if isinstance(before.result, dict) else {}
        after_result = after.result if isinstance(after.result, dict) else {}
        scanner_diff = _compare_scanner_runs(before_result, after_result)
        source_comparison = _compare_source_manifests(before_result, after_result)
        for kind in ("new", "not_observed_before", "persisting", "disappeared", "not_observed"):
            diff["findings"][kind] = _annotate_finding_source_relation(diff["findings"][kind], source_comparison)
        return {
            "workflow_id": str(workflow_id),
            **scanner_diff,
            "source_comparison": source_comparison,
            "from_run": before_report["run"],
            "to_run": after_report["run"],
            **diff,
            "limitations": {
                "before_findings_truncated": before_report["findings_truncated"],
                "after_findings_truncated": after_report["findings_truncated"],
                "absence_confirmed": diff["findings"]["absence_confirmed"],
                "note": None if diff["findings"]["absence_confirmed"] else
                    "Полнота сравнения ограничена: запуск назначения неполный или один из отчётов усечён. Отсутствие находок не считается подтверждённым исправлением.",
            },
        }


def _cache_telemetry_summary(trace: list) -> dict:
    scanner_steps = [
        item for item in trace
        if isinstance(item, dict) and item.get("type") in {"scan.secrets", "scan.sca", "scan.sast"}
    ]
    hits = sum(1 for item in scanner_steps if item.get("cached") is True)
    total = len(scanner_steps)
    return {
        "scanner_blocks": total,
        "cache_hits": hits,
        "fresh_scans": total - hits,
        "hit_rate": round(hits / total, 4) if total else 0.0,
        "ttl_seconds": CACHE_TTL_SECONDS,
    }


def _run_telemetry(session, run: WorkflowRun):
    findings = session.scalars(select(Finding).where(Finding.run_id == run.id)).all()
    severity = {}
    for finding in findings:
        key = (finding.severity or "UNKNOWN").upper()
        severity[key] = severity.get(key, 0) + 1

    result = run.result if isinstance(run.result, dict) else {}
    trace = result.get("trace", []) if isinstance(result, dict) else []
    progress = result if run.status in {"running", "cancelling"} and "completed_nodes" in result else None
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
        "cache": _cache_telemetry_summary(trace),
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
                    **({
                        "explained_count": output.get("explained_count", len(output.get("explanations", []))),
                        "analyzed_count": output.get("analyzed_count", 0),
                        "skipped_count": output.get("skipped_count", 0),
                        "unexplained_count": output.get("unexplained_count", 0),
                        "coverage": output.get("coverage", 0),
                        "provider": output.get("provider"),
                        "model": output.get("model"),
                    } if node_id in {item.get("node_id") for item in trace if item.get("type") == "ai.explain"} else {}),
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
def latest_workflow_telemetry(workflow_id: UUID, request: Request):
    with SessionLocal() as session:
        if _workflow_in_active_workspace(session, request, workflow_id) is None:
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


def _safe_report_value(value, key: str = ""):
    """Bound and redact report content before it leaves the API."""
    if re.search(r"(?i)(api[_-]?key|access[_-]?token|authorization|password|passwd|client[_-]?secret|private[_-]?key|ciphertext|nonce)", key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(child_key)[:120]: _safe_report_value(child_value, str(child_key))
            for child_key, child_value in list(value.items())[:500]
        }
    if isinstance(value, (list, tuple)):
        return [_safe_report_value(item) for item in value[:5000]]
    if isinstance(value, str):
        return redact_text(_redact(value[:5000]))
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:500]


def _compare_workflow_graphs(before: dict, after: dict) -> dict:
    def indexed(graph: dict, key: str) -> dict:
        rows = graph.get(key, []) if isinstance(graph, dict) else []
        return {str(item.get("id")): item for item in rows if isinstance(item, dict) and item.get("id") is not None}

    old_nodes, new_nodes = indexed(before, "nodes"), indexed(after, "nodes")
    old_edges, new_edges = indexed(before, "edges"), indexed(after, "edges")
    added_nodes = sorted(set(new_nodes) - set(old_nodes))
    removed_nodes = sorted(set(old_nodes) - set(new_nodes))
    changed_nodes = []
    for node_id in sorted(set(old_nodes) & set(new_nodes)):
        old, new = old_nodes[node_id], new_nodes[node_id]
        changes = []
        for field in ("type", "config", "position"):
            if old.get(field, {}) != new.get(field, {}):
                changes.append({"field": field, "before": _safe_report_value(old.get(field, {}), field),
                                "after": _safe_report_value(new.get(field, {}), field)})
        if changes:
            changed_nodes.append({"id": node_id, "label": _safe_report_value(new.get("config", {}).get("label", new.get("type", node_id))),
                                  "changes": changes})
    added_edges = sorted(set(new_edges) - set(old_edges))
    removed_edges = sorted(set(old_edges) - set(new_edges))
    return {
        "name_changed": before.get("name") != after.get("name"),
        "name_before": _safe_report_value(before.get("name", "")),
        "name_after": _safe_report_value(after.get("name", "")),
        "nodes": {
            "added": [{"id": key, "type": _safe_report_value(new_nodes[key].get("type", ""))} for key in added_nodes],
            "removed": [{"id": key, "type": _safe_report_value(old_nodes[key].get("type", ""))} for key in removed_nodes],
            "changed": changed_nodes,
        },
        "edges": {
            "added": [{"id": key, "source": new_edges[key].get("source"), "target": new_edges[key].get("target")} for key in added_edges],
            "removed": [{"id": key, "source": old_edges[key].get("source"), "target": old_edges[key].get("target")} for key in removed_edges],
        },
        "summary": {"added_nodes": len(added_nodes), "removed_nodes": len(removed_nodes), "changed_nodes": len(changed_nodes),
                    "added_edges": len(added_edges), "removed_edges": len(removed_edges)},
    }


def _canonical_finding_path(run: WorkflowRun, path: str) -> str:
    """Normalize legacy archive-wrapper prefixes in API and exported reports."""
    if not isinstance(path, str) or not path:
        return path
    result = run.result if isinstance(run.result, dict) else {}
    outputs = result.get("outputs", {}) if isinstance(result.get("outputs"), dict) else {}
    graph_snapshot = getattr(run, "graph_snapshot", None)
    nodes = graph_snapshot.get("nodes", []) if isinstance(graph_snapshot, dict) else []
    for node in nodes:
        if not isinstance(node, dict) or node.get("type") not in {"source.upload", "source.git"}:
            continue
        output = outputs.get(node.get("id"), {})
        if not isinstance(output, dict) or output.get("status") != "ready":
            continue
        prefix = output.get("project_subdirectory")
        if not prefix and node.get("type") == "source.upload":
            source_path = output.get("path")
            if isinstance(source_path, str):
                relative = PurePosixPath(source_path)
                if not relative.is_absolute() and all(part not in {"", ".", ".."} for part in relative.parts):
                    try:
                        workspace = Path(settings.workspace_root).resolve()
                        artifact = workspace.joinpath(*relative.parts).resolve(strict=True)
                        if artifact.is_relative_to(workspace) and artifact.is_dir():
                            detected = detect_project_root(artifact)
                            if detected != artifact:
                                prefix = detected.relative_to(artifact).as_posix()
                    except (OSError, ValueError):
                        prefix = None
        if isinstance(prefix, str) and prefix and prefix != "." and path.startswith(prefix + "/"):
            return path[len(prefix) + 1:]
        break
    return path

def _summarize_report_findings(findings: list[dict]) -> dict:
    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    explained = 0
    for finding in findings:
        severity = str(finding.get("severity") or "UNKNOWN").upper()
        category = str(finding.get("category") or finding.get("analyzer") or "UNCATEGORIZED").upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1
        if isinstance(finding.get("ai_explanation"), dict):
            explained += 1
    return {
        "total_findings": len(findings),
        "by_severity": dict(sorted(severity_counts.items())),
        "by_category": dict(sorted(category_counts.items())),
        "ai_explained": explained,
        "without_ai_explanation": len(findings) - explained,
    }


def _build_run_report(session, run: WorkflowRun) -> dict:
    telemetry = _safe_report_value(_run_telemetry(session, run))
    rows = session.scalars(
        select(Finding).where(Finding.run_id == run.id).order_by(Finding.severity, Finding.path, Finding.line)
    ).all()
    findings = [
        _safe_report_value({
            **(item.payload if isinstance(item.payload, dict) else {}),
            "fingerprint": item.fingerprint,
            "rule_id": item.rule_id,
            "severity": item.severity,
            "path": _canonical_finding_path(run, item.path),
            "line": item.line,
        })
        for item in rows
    ]
    return {
        "report_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run": {
            "id": str(run.id),
            "workflow_id": str(run.workflow_id) if run.workflow_id else None,
            "status": run.status,
            "source": run.source,
            "queued_at": run.queued_at.isoformat() if run.queued_at else None,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            "error": _safe_report_value(run.error) if run.error else None,
        },
        "telemetry": telemetry,
        "summary": _summarize_report_findings(findings),
        "findings": findings,
        "findings_truncated": False,
    }


@app.post("/api/projects/{project_id}/reports/{run_id}", status_code=201)
def save_run_report_to_project(project_id: UUID, run_id: UUID, request: Request):
    with SessionLocal() as session:
        project = _project_in_active_workspace(session, request, project_id, write=True)
        run = _run_in_active_workspace(session, request, run_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        root = _project_root(project)
        reports_dir = root / "reports"
        if reports_dir.is_symlink():
            raise HTTPException(status_code=400, detail="Report directory is unavailable")
        reports_dir.mkdir(mode=0o750, exist_ok=True)
        if reports_dir.resolve(strict=True).parent != root:
            raise HTTPException(status_code=400, detail="Invalid report directory")
        report = _build_run_report(session, run)
        payload = json.dumps(report, ensure_ascii=False, indent=2, default=str)
        if len(payload.encode("utf-8")) > 10 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Report exceeds the 10 MiB project storage limit")
        filename = f"run-{run_id}.json"
        destination = reports_dir / filename
        if destination.is_symlink() or destination.exists():
            raise HTTPException(status_code=409, detail="A report for this run already exists in the project")
        try:
            with destination.open("x", encoding="utf-8") as stream:
                stream.write(payload)
        except FileExistsError as exc:
            raise HTTPException(status_code=409, detail="A report for this run already exists in the project") from exc
        session.add(AuditLog(
            action="report_saved",
            entity="project",
            entity_id=str(project_id),
            details={"run_id": str(run_id), "path": f"reports/{filename}", "bytes": len(payload.encode("utf-8"))},
        ))
        session.commit()
        return {"project_id": str(project_id), "run_id": str(run_id), "path": f"reports/{filename}", "bytes": len(payload.encode("utf-8"))}


@app.get("/api/runs/{run_id}/report.json")
def export_run_report_json(run_id: UUID, request: Request):
    with SessionLocal() as session:
        run = _run_in_active_workspace(session, request, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        report = _build_run_report(session, run)
        return JSONResponse(
            content=report,
            headers={"Content-Disposition": f'attachment; filename="invest-run-{run_id}-report.json"'},
        )


@app.get("/api/runs/{run_id}/report.zip")
def export_run_report_zip(run_id: UUID, request: Request):
    with SessionLocal() as session:
        run = _run_in_active_workspace(session, request, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        report = _build_run_report(session, run)

    findings = report.get("findings") or []
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "report.json",
            json.dumps(report, ensure_ascii=False, indent=2, default=str),
        )
        archive.writestr(
            "summary.json",
            json.dumps(
                {"run": report.get("run"), "summary": report.get("summary"), "telemetry": report.get("telemetry")},
                ensure_ascii=False,
                indent=2,
                default=str,
            ),
        )
        archive.writestr(
            "findings/all.json",
            json.dumps({"findings": findings}, ensure_ascii=False, indent=2, default=str),
        )

        severities = sorted({str(item.get("severity") or "UNKNOWN").upper() for item in findings})
        for severity in severities:
            selected = [item for item in findings if str(item.get("severity") or "UNKNOWN").upper() == severity]
            archive.writestr(
                f"findings/by-severity/{severity}.json",
                json.dumps({"severity": severity, "count": len(selected), "findings": selected}, ensure_ascii=False, indent=2, default=str),
            )

        categories: dict[str, list[dict]] = {}
        for item in findings:
            category = str(item.get("category") or item.get("analyzer") or "UNCATEGORIZED").upper()
            safe_category = re.sub(r"[^A-Z0-9_.-]+", "_", category)[:80] or "UNCATEGORIZED"
            categories.setdefault(safe_category, []).append(item)
        for category, selected in sorted(categories.items()):
            archive.writestr(
                f"findings/by-category/{category}.json",
                json.dumps({"category": category, "count": len(selected), "findings": selected}, ensure_ascii=False, indent=2, default=str),
            )

        archive.writestr(
            "README.txt",
            "INVEST security report archive\n\n"
            "report.json — полный отчёт запуска: метаданные, telemetry, все сохранённые находки и AI-объяснения.\n"
            "summary.json — сводка по уровням серьёзности, категориям и покрытию AI.\n"
            "findings/all.json — все находки одним массивом.\n"
            "findings/by-severity/ — те же находки, сгруппированные по severity.\n"
            "findings/by-category/ — те же находки, сгруппированные по категории анализатора.\n\n"
            "AI-объяснения включены, если они были сохранены для находки. Их отсутствие не удаляет саму находку. "
            "Секреты и чувствительные значения проходят серверную очистку перед экспортом. "
            "Отчёт содержит только данные, сохранённые для данного запуска.\n",
        )

    archive_buffer.seek(0)
    filename = f"invest-run-{run_id}-report.zip"
    return StreamingResponse(
        archive_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/runs/{run_id}/report.html", response_class=HTMLResponse)
def export_run_report_html(run_id: UUID, request: Request):
    with SessionLocal() as session:
        run = _run_in_active_workspace(session, request, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        report = _build_run_report(session, run)

    # Keep JSON safe inside an application/json script element and render all
    # dynamic report content through textContent in the browser.
    encoded = json.dumps(report, ensure_ascii=False, separators=(",", ":"), default=str)
    encoded = (encoded.replace("&", "\\u0026").replace("<", "\\u003c")
               .replace(">", "\\u003e").replace("\u2028", "\\u2028")
               .replace("\u2029", "\\u2029"))
    run_data = report.get("run") or {}
    title = html.escape(f"INVEST · Отчёт запуска {run_data.get('id', run_id)}")
    document = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light"><title>__TITLE__</title>
<style>
:root{color-scheme:dark;--bg:#0b1118;--panel:#111c27;--panel2:#162331;--line:#263747;--text:#e6edf3;--muted:#91a3b4;--green:#45c58a;--red:#ff6b76;--orange:#ffad66;--yellow:#e9ca69;--blue:#75b9ef;--purple:#c09af2;--mono:"JetBrains Mono",Consolas,monospace}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 12% -10%,rgba(42,118,91,.16),transparent 34%),var(--bg);color:var(--text);font:14px/1.55 Inter,system-ui,-apple-system,sans-serif}
button,input,select{font:inherit}button{cursor:pointer}a{color:inherit;text-decoration:none}.shell{max-width:1440px;margin:auto;padding:34px 38px 70px}
.topline{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:24px}.brand{display:flex;align-items:center;gap:10px;color:#a9b9c7;font:700 11px var(--mono);letter-spacing:.16em}.brand-mark{display:grid;place-items:center;width:30px;height:30px;border:1px solid rgba(69,197,138,.45);border-radius:9px;color:var(--green);font-size:16px}.actions{display:flex;gap:8px;flex-wrap:wrap}.btn{border:1px solid var(--line);border-radius:8px;padding:9px 12px;background:var(--panel);color:var(--text);font-size:12px}.btn:hover{border-color:#4d806b;background:var(--panel2)}.btn.primary{background:#173b30;border-color:#28684f;color:#b8f1d5}
.hero{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;margin-bottom:24px}.eyebrow{color:var(--green);font:700 10px var(--mono);letter-spacing:.15em;text-transform:uppercase}.hero h1{margin:7px 0 5px;font-size:clamp(25px,3vw,38px);letter-spacing:-.04em;line-height:1.15}.sub{color:var(--muted);font-size:12px}.status{display:inline-flex;align-items:center;gap:7px;padding:7px 11px;border:1px solid var(--line);border-radius:99px;background:var(--panel);font:700 10px var(--mono);letter-spacing:.06em}.dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 12px currentColor}.status.partial .dot{background:var(--orange)}.status.failed .dot{background:var(--red)}
.meta{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0 0}.chip{padding:6px 9px;border:1px solid var(--line);border-radius:6px;background:rgba(17,28,39,.72);color:#b4c2ce;font:10px var(--mono)}
.metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin:22px 0}.metric{padding:15px 16px;border:1px solid var(--line);border-radius:11px;background:linear-gradient(145deg,var(--panel),rgba(17,28,39,.68));min-width:0}.metric span{display:block;color:var(--muted);font-size:10px}.metric b{display:block;margin-top:4px;font-size:26px;letter-spacing:-.04em}.metric small{color:var(--muted);font-size:10px}.metric.critical b{color:var(--red)}.metric.high b{color:var(--orange)}.metric.ai b{color:var(--purple)}
.tabs{display:flex;gap:5px;padding:5px;border:1px solid var(--line);border-radius:10px;background:#0e1720;width:max-content;max-width:100%;margin:26px 0 16px}.tab{border:0;border-radius:7px;padding:9px 15px;background:transparent;color:var(--muted);font-size:12px}.tab.active{background:#20382f;color:#c5f3dc;box-shadow:inset 0 0 0 1px rgba(69,197,138,.24)}
.section-head{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;margin:22px 0 13px}.section-head h2{margin:0;font-size:17px}.section-head p{margin:3px 0 0;color:var(--muted);font-size:11px}
.panel{border:1px solid var(--line);border-radius:12px;background:var(--panel);overflow:hidden}.summary-grid{display:grid;grid-template-columns:1.2fr .8fr;gap:12px}.summary-panel{padding:18px}.summary-panel h3{margin:0 0 12px;font-size:12px}.severity-list{display:grid;gap:10px}.sev-row{display:grid;grid-template-columns:82px 1fr 35px;gap:10px;align-items:center;color:var(--muted);font-size:11px}.bar{height:7px;border-radius:9px;background:#253442;overflow:hidden}.bar i{display:block;height:100%;border-radius:9px}.sev-row strong{text-align:right;color:var(--text);font:11px var(--mono)}.sev-critical{background:var(--red)}.sev-high{background:var(--orange)}.sev-medium{background:var(--yellow)}.sev-low{background:var(--blue)}.sev-info{background:#8295a7}
.ai-summary{display:flex;align-items:center;gap:15px}.ring{width:76px;height:76px;flex:none;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--purple) var(--coverage),#293344 0);position:relative}.ring:before{content:"";position:absolute;inset:7px;border-radius:50%;background:var(--panel)}.ring b{position:relative;font:700 16px var(--mono)}.ai-summary strong{display:block;font-size:20px}.ai-summary p{margin:3px 0;color:var(--muted);font-size:11px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0}.toolbar input,.toolbar select{min-width:150px;padding:9px 10px;border:1px solid var(--line);border-radius:7px;background:#0d1720;color:var(--text);font-size:11px}.toolbar input{flex:1}
.finding-list{display:grid;gap:10px}.finding{border:1px solid var(--line);border-radius:11px;background:var(--panel);overflow:hidden}.finding-head{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:12px;align-items:start;padding:14px 16px}.sev{padding:4px 7px;border-radius:5px;font:700 9px var(--mono);letter-spacing:.06em}.sev.CRITICAL{background:rgba(255,107,118,.14);color:var(--red)}.sev.HIGH{background:rgba(255,173,102,.14);color:var(--orange)}.sev.MEDIUM{background:rgba(233,202,105,.14);color:var(--yellow)}.sev.LOW{background:rgba(117,185,239,.14);color:var(--blue)}.sev.INFO{background:rgba(130,149,167,.14);color:#a8b8c7}
.finding h3{margin:0;font-size:13px}.finding .path{margin-top:4px;color:var(--muted);font:10px var(--mono);overflow-wrap:anywhere}.finding .message{margin-top:7px;color:#c4d0da;font-size:12px}.finding-toggle{border:1px solid var(--line);border-radius:7px;background:#172432;color:#aebdca;padding:7px 9px;font-size:10px}.finding-body{display:none;padding:0 16px 16px;border-top:1px solid var(--line)}.finding.open .finding-body{display:block}.finding.open .finding-head{border-bottom:1px solid var(--line)}
.detail-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px;margin-top:13px}.detail{padding:11px 12px;border:1px solid var(--line);border-radius:8px;background:#14212c;min-width:0}.detail.full{grid-column:1/-1}.detail label{display:block;margin-bottom:5px;color:#9aabc0;font:700 9px var(--mono);letter-spacing:.09em}.detail p{margin:0;color:#d3dde6;font-size:12px;line-height:1.6;overflow-wrap:anywhere}.ai-card{margin-top:12px;padding:14px;border:1px solid rgba(192,154,242,.28);border-left:3px solid var(--purple);border-radius:9px;background:linear-gradient(125deg,rgba(112,75,157,.13),rgba(17,28,39,.85))}.ai-head{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-bottom:12px}.ai-icon{display:grid;place-items:center;width:26px;height:26px;border-radius:8px;background:rgba(192,154,242,.14);color:var(--purple)}.ai-head strong{font-size:12px}.ai-head span{margin-left:auto;color:#d2b9f4;font:10px var(--mono)}.ai-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.ai-block{padding:10px;border:1px solid rgba(192,154,242,.15);border-radius:7px;background:rgba(8,14,22,.3)}.ai-block label{display:block;margin-bottom:5px;color:#c3a4e8;font:700 9px var(--mono);letter-spacing:.08em}.ai-block p{margin:0;color:#d5cce1;font-size:11px;line-height:1.55;overflow-wrap:anywhere}.evidence{margin-top:11px;border:1px solid var(--line);border-radius:8px;overflow:hidden}.evidence-title{padding:8px 10px;background:#172432;color:#aebdca;font:700 9px var(--mono);letter-spacing:.08em}.evidence-row{display:grid;grid-template-columns:42px minmax(0,1fr);gap:9px;padding:6px 10px;border-top:1px solid rgba(255,255,255,.04);font:11px var(--mono)}.evidence-row span{color:#71859a;text-align:right}.evidence-row code{color:#c8d7e4;white-space:pre-wrap;overflow-wrap:anywhere}.evidence-row.hit{background:rgba(255,173,102,.08)}.limits{display:block;margin-top:10px;color:#a99bb9;font-size:10px;line-height:1.5}.empty{padding:28px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:10px}
.json-tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:12px;border-bottom:1px solid var(--line)}.json-tools input{flex:1;min-width:180px;padding:8px 10px;border:1px solid var(--line);border-radius:7px;background:#0b141d;color:var(--text);font:11px var(--mono)}.json-meta{margin-left:auto;color:var(--muted);font:10px var(--mono)}.json-view{max-height:72vh;overflow:auto;padding:18px;background:#0a121a}.json-view pre{margin:0;color:#c6d4df;font:11px/1.7 var(--mono);white-space:pre;tab-size:2}.j-key{color:#83c8f5}.j-string{color:#a9d99b}.j-number{color:#e6c27a}.j-bool{color:#c49af1}.j-null{color:#8295a7}
.hidden{display:none!important}.foot{margin-top:22px;color:#718396;font-size:10px;text-align:center}
@media(max-width:900px){.shell{padding:24px 18px 50px}.metrics{grid-template-columns:repeat(3,minmax(0,1fr))}.summary-grid{grid-template-columns:1fr}.hero{flex-direction:column}.ai-grid{grid-template-columns:1fr}.detail-grid{grid-template-columns:1fr}.detail.full{grid-column:auto}}
@media(max-width:520px){.shell{padding:18px 12px 40px}.topline{align-items:flex-start;flex-direction:column}.metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}.metric{padding:11px}.metric b{font-size:22px}.tabs{width:100%}.tab{flex:1;padding:9px 7px}.finding-head{grid-template-columns:auto minmax(0,1fr)}.finding-toggle{grid-column:2;justify-self:start}.sev-row{grid-template-columns:68px 1fr 25px}.ai-summary{align-items:flex-start}.json-view{padding:12px}.json-view pre{font-size:10px}}
</style></head>
<body><main class="shell">
<div class="topline"><div class="brand"><span class="brand-mark">I</span> INVEST <span style="color:#53677a">/ SECURITY REPORT</span></div><div class="actions"><button class="btn" id="copy-json">Копировать JSON</button><button class="btn primary" id="download-json">Скачать JSON</button></div></div>
<header class="hero"><div><div class="eyebrow">Отчёт анализа безопасности</div><h1>Результаты запуска</h1><div class="sub">Сводка сканеров, подтверждённые находки и пояснения AI</div><div class="meta"><span class="chip" id="run-id">RUN __RUN_ID__</span><span class="chip" id="run-source"></span><span class="chip" id="run-date"></span></div></div><div class="status" id="run-status"><i class="dot"></i><span></span></div></header>
<section class="metrics" id="metrics"></section>
<nav class="tabs"><button class="tab active" data-tab="overview">Обзор</button><button class="tab" data-tab="findings">Находки</button><button class="tab" data-tab="json">JSON</button></nav>
<section id="tab-overview"><div class="summary-grid"><div class="panel summary-panel"><h3>Распределение по критичности</h3><div class="severity-list" id="severity-list"></div></div><div class="panel summary-panel"><h3>Покрытие AI-объяснениями</h3><div class="ai-summary" id="ai-summary"></div></div></div><div class="section-head"><div><h2>Сводка запуска</h2><p>Время выполнения и состояние обработки</p></div></div><div class="panel summary-panel" id="run-details"></div></section>
<section id="tab-findings" class="hidden"><div class="section-head"><div><h2>Находки безопасности</h2><p id="finding-count"></p></div></div><div class="toolbar"><input id="finding-search" placeholder="Поиск по правилу, файлу или описанию…"><select id="finding-severity"><option value="">Все уровни</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select><select id="finding-ai"><option value="">Все находки</option><option value="yes">С AI-объяснением</option><option value="no">Без AI-объяснения</option></select></div><div class="finding-list" id="finding-list"></div></section>
<section id="tab-json" class="hidden"><div class="section-head"><div><h2>Структурированный JSON</h2><p>Полный машинно-читаемый отчёт без потери полей</p></div></div><div class="panel"><div class="json-tools"><input id="json-search" placeholder="Найти ключ или значение в JSON…"><button class="btn" id="json-copy">Копировать</button><button class="btn" id="json-download">Скачать .json</button><span class="json-meta" id="json-meta"></span></div><div class="json-view"><pre id="json-content"></pre></div></div></section>
<div class="foot">INVEST · AI-пояснения помогают интерпретировать результаты, но не заменяют ручную проверку и доказательства сканера.</div>
</main><script id="report-data" type="application/json">__REPORT__</script>
<script>
(function(){
"use strict";
var report=JSON.parse(document.getElementById("report-data").textContent), run=report.run||{}, findings=Array.isArray(report.findings)?report.findings:[];
var $=function(id){return document.getElementById(id);};
var esc=function(v){return String(v==null?"":v).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});};
var sev=["CRITICAL","HIGH","MEDIUM","LOW","INFO"], counts={};sev.forEach(function(s){counts[s]=findings.filter(function(f){return String(f.severity||"INFO").toUpperCase()===s;}).length;});
var aiCount=findings.filter(function(f){return !!f.ai_explanation;}).length, coverage=findings.length?Math.round(aiCount/findings.length*100):0;
var status=String(run.status||"unknown").toLowerCase();$("run-status").classList.add(status);$("run-status").querySelector("span").textContent=({completed:"ЗАВЕРШЁН",partial:"ЧАСТИЧНО",failed:"ОШИБКА",cancelled:"ОТМЕНЁН",running:"В РАБОТЕ",queued:"В ОЧЕРЕДИ"})[status]||status.toUpperCase();
$("run-source").textContent=run.source||"Источник не указан";$("run-date").textContent=run.finished_at?new Date(run.finished_at).toLocaleString("ru-RU"):"Дата завершения неизвестна";
var metrics=[["Всего находок",findings.length,"в отчёте",""],["Critical",counts.CRITICAL,"критический уровень","critical"],["High",counts.HIGH,"высокий уровень","high"],["AI объяснения",aiCount,"из "+findings.length,"ai"],["Покрытие AI",coverage+"%","по находкам","ai"]];
$("metrics").innerHTML=metrics.map(function(m){return '<div class="metric '+m[3]+'"><span>'+m[0]+'</span><b>'+m[1]+'</b><small>'+m[2]+'</small></div>';}).join("");
$("severity-list").innerHTML=sev.map(function(s){var n=counts[s],w=findings.length?Math.round(n/findings.length*100):0;return '<div class="sev-row"><span>'+s+'</span><div class="bar"><i class="sev-'+s.toLowerCase()+'" style="width:'+w+'%"></i></div><strong>'+n+'</strong></div>';}).join("");
$("ai-summary").innerHTML='<div class="ring" style="--coverage:'+coverage+'%"><b>'+coverage+'%</b></div><div><strong>'+aiCount+' / '+findings.length+'</strong><p>находок получили AI-объяснение</p><p>'+ (findings.length-aiCount)+' без пояснения модели</p></div>';
var duration=run.started_at&&run.finished_at?Math.max(0,Math.round((new Date(run.finished_at)-new Date(run.started_at))/1000))+" сек.":"—";
$("run-details").innerHTML='<div class="meta"><span class="chip">Начало: '+esc(run.started_at?new Date(run.started_at).toLocaleString("ru-RU"):"—")+'</span><span class="chip">Завершение: '+esc(run.finished_at?new Date(run.finished_at).toLocaleString("ru-RU"):"—")+'</span><span class="chip">Длительность: '+duration+'</span><span class="chip">Версия отчёта: '+esc(report.report_version||"—")+'</span></div>'+(run.error?'<p style="color:var(--red);margin:12px 0 0">'+esc(run.error)+'</p>':"")+(report.findings_truncated?'<p style="color:var(--orange)">Выборка находок ограничена 5000 записями.</p>':"");
function aiMarkup(ai){
if(!ai)return "";
var ev=Array.isArray(ai.source_evidence)?ai.source_evidence:[];
return '<div class="ai-card"><div class="ai-head"><span class="ai-icon">✦</span><strong>AI · ОБЪЯСНЕНИЕ</strong><span>Уверенность '+Math.round(Number(ai.confidence||0)*100)+'%</span></div><div class="ai-grid"><div class="ai-block"><label>ПЕРВОПРИЧИНА</label><p>'+esc(ai.root_cause)+'</p></div><div class="ai-block"><label>ВОЗДЕЙСТВИЕ</label><p>'+esc(ai.impact)+'</p></div><div class="ai-block"><label>РЕКОМЕНДАЦИЯ</label><p>'+esc(ai.recommendation)+'</p></div></div>'+(ev.length?'<div class="evidence"><div class="evidence-title">ДОКАЗАТЕЛЬСТВО ИЗ СКАНЕРА · '+ev.length+' СТРОК</div>'+ev.map(function(e){return '<div class="evidence-row '+(e.is_finding?"hit":"")+'"><span>'+esc(e.line)+'</span><code>'+esc(e.text)+'</code></div>';}).join("")+'</div>':'<small class="limits">Сканер не предоставил фрагмент исходного кода. Текст модели не является самостоятельным доказательством.</small>')+(ai.evidence_limits?'<small class="limits">Ограничения анализа: '+esc(ai.evidence_limits)+'</small>':'')+'<small class="limits">Уверенность — оценка модели, а не вероятность эксплуатации или подтверждение уязвимости.</small></div>';
}
function findingMarkup(f,i){
var severity=String(f.severity||"INFO").toUpperCase(), ai=f.ai_explanation;
return '<article class="finding"><div class="finding-head"><span class="sev '+esc(severity)+'">'+esc(severity)+'</span><div><h3>'+esc(f.rule_id||"Security finding")+'</h3><div class="path">'+esc(f.path||"—")+(f.line?":"+esc(f.line):"")+'</div><div class="message">'+esc(f.message||"Потенциальная проблема; проверьте контекст.")+'</div></div><button class="finding-toggle">Подробнее ↓</button></div><div class="finding-body"><div class="detail-grid">'+(f.why_it_matters?'<div class="detail"><label>ПОЧЕМУ ЭТО ВАЖНО</label><p>'+esc(f.why_it_matters)+'</p></div>':'')+(f.recommendation?'<div class="detail"><label>РЕКОМЕНДАЦИЯ СКАНЕРА</label><p>'+esc(f.recommendation)+'</p></div>':'')+'<div class="detail"><label>ИДЕНТИФИКАТОРЫ</label><p>'+esc([].concat(f.cwe||[]).concat(f.cve?[f.cve]:[]).join(" · ")||"Не указаны")+'</p></div><div class="detail"><label>FINGERPRINT</label><p style="font-family:var(--mono);font-size:10px">'+esc(f.fingerprint||"—")+'</p></div></div>'+aiMarkup(ai)+'</div></article>';
}
function renderFindings(){
var q=$("finding-search").value.toLowerCase(), s=$("finding-severity").value, a=$("finding-ai").value;
var list=findings.filter(function(f){var hay=[f.rule_id,f.path,f.message,f.why_it_matters,f.recommendation].join(" ").toLowerCase();return (!q||hay.indexOf(q)>=0)&&(!s||String(f.severity||"").toUpperCase()===s)&&(!a||(a==="yes"?"yes":"no")===(f.ai_explanation?"yes":"no"));});
$("finding-count").textContent=list.length+" из "+findings.length+" · AI: "+list.filter(function(f){return !!f.ai_explanation;}).length;
$("finding-list").innerHTML=list.length?list.map(findingMarkup).join(""):'<div class="empty">По выбранным условиям находок нет.</div>';
Array.prototype.forEach.call(document.querySelectorAll(".finding-toggle"),function(btn){btn.addEventListener("click",function(){var card=btn.closest(".finding");card.classList.toggle("open");btn.textContent=card.classList.contains("open")?"Свернуть ↑":"Подробнее ↓";});});
}
["finding-search","finding-severity","finding-ai"].forEach(function(id){$(id).addEventListener("input",renderFindings);});renderFindings();
function jsonText(){return JSON.stringify(report,null,2);}
function download(){var blob=new Blob([jsonText()],{type:"application/json;charset=utf-8"}),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download="invest-run-"+String(run.id||"report").replace(/[^a-zA-Z0-9_-]/g,"")+".json";a.click();URL.revokeObjectURL(url);}
function copy(){var value=jsonText();if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(value).then(function(){$("copy-json").textContent="Скопировано ✓";setTimeout(function(){$("copy-json").textContent="Копировать JSON";},1500);});}else{var t=document.createElement("textarea");t.value=value;document.body.appendChild(t);t.select();document.execCommand("copy");t.remove();}}
$("download-json").addEventListener("click",download);$("json-download").addEventListener("click",download);$("copy-json").addEventListener("click",copy);$("json-copy").addEventListener("click",copy);
function highlight(value){var safe=esc(value);return safe.replace(/("(?:\\.|[^"\\])*"\s*:)|("(?:\\.|[^"\\])*")|\b(true|false)\b|\b(null)\b|(-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b)/g,function(m,key,str,bool,nul,num){if(key)return '<span class="j-key">'+key+'</span>';if(str)return '<span class="j-string">'+str+'</span>';if(bool)return '<span class="j-bool">'+bool+'</span>';if(nul)return '<span class="j-null">'+nul+'</span>';return '<span class="j-number">'+num+'</span>';});}
var raw=jsonText();$("json-meta").textContent=new Blob([raw]).size.toLocaleString("ru-RU")+" байт · "+findings.length+" находок";
function renderJson(){var q=$("json-search").value.toLowerCase(),text=raw;if(q){var lines=raw.split("\n"),matched=lines.map(function(line,i){return line.toLowerCase().indexOf(q)>=0?i:-1;}).filter(function(i){return i>=0;});text=matched.length?matched.map(function(i){return String(i+1).padStart(4," ")+"  "+lines[i];}).join("\n"):"Совпадений не найдено";}$("json-content").innerHTML=highlight(text);}
$("json-search").addEventListener("input",renderJson);renderJson();
function selectTab(name){["overview","findings","json"].forEach(function(tab){$("tab-"+tab).classList.toggle("hidden",tab!==name);document.querySelector('[data-tab="'+tab+'"]').classList.toggle("active",tab===name);});if(name==="json")renderJson();}
Array.prototype.forEach.call(document.querySelectorAll(".tab"),function(btn){btn.addEventListener("click",function(){selectTab(btn.dataset.tab);});});
if(new URLSearchParams(location.search).get("view")==="json")selectTab("json");
})();
</script></body></html>"""
    document = document.replace("__TITLE__", title).replace("__RUN_ID__", html.escape(str(run_data.get("id", run_id))))
    document = document.replace("__REPORT__", encoded)
    return HTMLResponse(document, headers={"Content-Disposition": f'inline; filename="invest-run-{run_id}.html"' })

@app.get("/api/runs/{run_id}/telemetry")
def get_run_telemetry(run_id: UUID, request: Request):
    with SessionLocal() as session:
        run = _run_in_active_workspace(session, request, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        return _run_telemetry(session, run)


@app.get("/api/runs/{run_id}/events")
def stream_run_events(run_id: UUID, request: Request):
    def event_stream():
        deadline = time.monotonic() + 1800
        while time.monotonic() < deadline:
            with SessionLocal() as session:
                try:
                    run = _run_in_active_workspace(session, request, run_id)
                except HTTPException:
                    payload = {"status": "not_found", "run_id": str(run_id)}
                    yield "event: error\ndata: " + json.dumps(payload) + "\n\n"
                    return
                payload = _run_telemetry(session, run)
            yield "data: " + json.dumps(payload, default=str) + "\n\n"
            if payload["status"] in {"completed", "partial", "failed", "cancelled"}:
                return
            time.sleep(1)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/runs/{run_id}")
def get_run(run_id: UUID, request: Request):
    with SessionLocal() as session:
        run = _run_in_active_workspace(session, request, run_id)
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
def list_run_findings(run_id: UUID, request: Request):
    with SessionLocal() as session:
        run = _run_in_active_workspace(session, request, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        rows = session.scalars(
            select(Finding).where(Finding.run_id == run_id).order_by(Finding.severity, Finding.path, Finding.line)
        ).all()
        run_result = run.result if isinstance(run.result, dict) else {}
        outputs = run_result.get("outputs", {}) if isinstance(run_result.get("outputs"), dict) else {}
        ai_output = outputs.get("ai-explain", {}) if isinstance(outputs.get("ai-explain"), dict) else {}
        explanations = ai_output.get("explanations", []) if isinstance(ai_output.get("explanations"), list) else []
        explanation_by_fingerprint = {
            str(item.get("fingerprint")): item
            for item in explanations
            if isinstance(item, dict) and item.get("fingerprint")
        }
        result = []
        for item in rows:
            payload = item.payload if isinstance(item.payload, dict) else {}
            explanation = explanation_by_fingerprint.get(item.fingerprint)
            result.append({
                "id": str(item.id),
                "fingerprint": item.fingerprint,
                **payload,
                "id": str(item.id),
                "fingerprint": item.fingerprint,
                "rule_id": item.rule_id,
                "severity": item.severity,
                "path": _canonical_finding_path(run, item.path),
                "line": item.line,
                **({"ai_explanation": explanation} if explanation else {}),
            })
        return result


@app.get("/api/runs/{run_id}/findings/{fingerprint}/source")
def get_finding_source(
    run_id: UUID,
    fingerprint: str,
    request: Request,
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
        run = _run_in_active_workspace(session, request, run_id)
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


@app.post("/api/runs/{run_id}/findings/{fingerprint}/fix-preview")
def preview_ai_finding_fix(run_id: UUID, fingerprint: str, request: Request):
    """Generate a bounded AI proposal for a safe project file; never apply it."""
    if not fingerprint or len(fingerprint) > 64:
        raise HTTPException(status_code=422, detail="Invalid finding fingerprint")

    with SessionLocal() as session:
        run = _run_in_active_workspace(session, request, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        finding = session.scalar(
            select(Finding).where(
                Finding.run_id == run_id,
                Finding.fingerprint == fingerprint,
            ).limit(1)
        )
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found in this run")
        finding_payload = finding.payload if isinstance(finding.payload, dict) else {}
        category = str(finding_payload.get("category", "")).upper()
        if category not in {"SAST", "SCA"}:
            raise HTTPException(
                status_code=403,
                detail="AI Fix доступен только для находок SAST и SCA. Секреты автоматически не исправляются.",
            )

        result = run.result if isinstance(run.result, dict) else {}
        outputs = result.get("outputs", {}) if isinstance(result.get("outputs"), dict) else {}
        graph = run.graph_snapshot if isinstance(run.graph_snapshot, dict) else {}
        ready_sources = []
        for node in graph.get("nodes", []):
            if not isinstance(node, dict) or node.get("type") != "source.upload":
                continue
            output = outputs.get(node.get("id"), {})
            if isinstance(output, dict) and output.get("status") == "ready":
                ready_sources.append(output)
        if len(ready_sources) != 1:
            raise HTTPException(
                status_code=409,
                detail="AI Fix доступен только для запуска с одним источником проекта из рабочей области.",
            )
        source_output = ready_sources[0]
        source_path = source_output.get("path")
        workflow = session.get(Workflow, run.workflow_id) if run.workflow_id else None
        if not isinstance(source_path, str) or workflow is None:
            raise HTTPException(status_code=409, detail="Не удалось связать запуск с проектом рабочей области.")
        project = session.scalar(
            select(Project).where(
                Project.workspace_id == workflow.workspace_id,
                Project.workspace_path == source_path,
            )
        )
        if project is None:
            raise HTTPException(
                status_code=409,
                detail="AI Fix доступен только для файлов проекта, сохранённого в рабочей области.",
            )

        canonical_path = _canonical_finding_path(run, finding.path)
        finding_relative = PurePosixPath(canonical_path)
        if (
            finding_relative.is_absolute()
            or not finding_relative.parts
            or any(part in {"", ".", ".."} for part in finding_relative.parts)
        ):
            raise HTTPException(status_code=400, detail="Invalid finding source path")
        subdirectory_value = source_output.get("project_subdirectory")
        if subdirectory_value:
            subdirectory = PurePosixPath(subdirectory_value)
            if (
                subdirectory.is_absolute()
                or not subdirectory.parts
                or any(part in {"", ".", ".."} for part in subdirectory.parts)
            ):
                raise HTTPException(status_code=400, detail="Invalid project subdirectory")
            project_relative = subdirectory / finding_relative
        else:
            project_relative = finding_relative

        editable_suffixes = {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".scss",
            ".json", ".yaml", ".yml", ".toml", ".ini", ".md", ".txt", ".xml",
            ".gradle", ".kts", ".properties", ".sql", ".sh", ".ps1",
        }
        if project_relative.suffix.lower() not in editable_suffixes or _project_path_is_sensitive(project_relative):
            raise HTTPException(status_code=403, detail="Этот файл нельзя передавать AI Fix или редактировать.")
        root = _project_root(project)
        candidate = root.joinpath(*project_relative.parts)
        current = candidate
        while current != root:
            if current.is_symlink():
                raise HTTPException(status_code=404, detail="Project file is unavailable")
            current = current.parent
        try:
            resolved = candidate.resolve(strict=True)
            run_source = resolve_run_source_file(
                settings.workspace_root, run.graph_snapshot, run.result or {}, finding.path
            ).resolve(strict=True)
            if (
                not resolved.is_relative_to(root)
                or not resolved.is_file()
                or resolved != run_source
                or resolved.stat().st_size > 32 * 1024
            ):
                raise OSError("File is unavailable, mismatched, or too large for AI Fix")
            source_content = resolved.read_text(encoding="utf-8")
        except (RunSourceFileError, OSError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=404, detail="Исходный файл недоступен для безопасного AI Fix.") from exc
        if not _project_content_is_safe(source_content):
            raise HTTPException(status_code=403, detail="Файл содержит потенциальные секреты и не может передаваться AI Fix.")
        proposal_context = {
            "project_id": str(project.id),
            "path": project_relative.as_posix(),
            "content": source_content,
            "sha256": sha256_text(source_content),
            "finding": {
                **finding_payload,
                "fingerprint": finding.fingerprint,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "path": canonical_path,
                "line": finding.line,
            },
        }

    try:
        proposal = generate_fix_proposal(
            proposal_context["finding"],
            proposal_context["content"],
            proposal_context["path"],
        )
    except AIFixError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    with SessionLocal() as session:
        session.add(AuditLog(
            action="project.ai_fix_proposed",
            entity="project",
            entity_id=proposal_context["project_id"],
            details={
                "run_id": str(run_id),
                "fingerprint": fingerprint,
                "path": proposal_context["path"],
                "original_sha256": proposal_context["sha256"],
                "proposed_sha256": sha256_text(proposal["proposed_content"]),
                "diff_sha256": hashlib.sha256(proposal["diff"].encode("utf-8")).hexdigest(),
                "model": proposal.get("model"),
            },
        ))
        session.commit()

    return {
        "project_id": proposal_context["project_id"],
        "run_id": str(run_id),
        "fingerprint": fingerprint,
        "path": proposal_context["path"],
        "original_sha256": proposal_context["sha256"],
        **proposal,
        "auto_applied": False,
        "apply_requires_confirmation": True,
    }


@app.post("/api/workflows/run")
def run_workflow(graph: WorkflowGraph, request: Request):
    try:
        with SessionLocal() as session:
            workspace, _ = require_active_workspace(session, request, allowed_roles={"admin", "editor"})
            _validate_graph_workspace_sources(session, workspace.id, graph)
        return execute_graph(graph, registry)
    except WorkflowExecutionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc



@app.get("/api/workflows/{workflow_id}/finding-states")
def list_finding_states(workflow_id: UUID, request: Request):
    with SessionLocal() as session:
        _workflow_in_active_workspace(session, request, workflow_id)
        workflow = _lock_workflow_for_version_write(session, workflow_id)
        if workflow is None:
            raise HTTPException(status_code=404, detail="Workflow not found")

        rows = session.scalars(
            select(FindingState)
            .where(FindingState.workflow_id == workflow_id)
            .order_by(FindingState.fingerprint)
        ).all()

        now = datetime.now(timezone.utc)
        changed = False
        for row in rows:
            if row.state != "accepted_risk" or row.expires_at is None:
                continue
            expiry = row.expires_at
            if expiry.tzinfo is None or expiry.utcoffset() is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry <= now:
                previous_state = row.state
                row.state = "open"
                row.reason = "Срок принятого риска истёк."
                row.expires_at = None
                session.add(AuditLog(
                    action="finding.state.expired",
                    entity="finding_state",
                    entity_id=f"{workflow_id}:{row.fingerprint}",
                    details={
                        "workflow_id": str(workflow_id),
                        "fingerprint": row.fingerprint,
                        "previous_state": previous_state,
                        "new_state": "open",
                    },
                ))
                changed = True

        if changed:
            session.commit()

        return [
            {
                "fingerprint": row.fingerprint,
                "state": row.state,
                "reason": row.reason,
                "expires_at": row.expires_at,
                "assigned_to_user_id": str(getattr(row, "assigned_to_user_id", None)) if getattr(row, "assigned_to_user_id", None) else None,
            }
            for row in rows
        ]


@app.put("/api/workflows/{workflow_id}/findings/{fingerprint}/state")
def update_finding_state(workflow_id: UUID, fingerprint: str, payload: FindingStateUpdate, request: Request):
    if not fingerprint or len(fingerprint) > 64:
        raise HTTPException(status_code=422, detail="Invalid finding fingerprint")
    normalized_state = "resolved" if payload.state == "fixed" else payload.state
    if normalized_state != "accepted_risk" and payload.expires_at is not None:
        raise HTTPException(status_code=422, detail="Срок действия допускается только для accepted_risk.")

    if normalized_state == "accepted_risk" and payload.expires_at is not None:
        expiry = payload.expires_at
        if expiry.tzinfo is None or expiry.utcoffset() is None:
            raise HTTPException(status_code=422, detail="Срок принятого риска должен содержать часовой пояс.")
        if expiry <= datetime.now(timezone.utc):
            raise HTTPException(status_code=422, detail="Срок принятого риска должен быть в будущем.")
    with SessionLocal() as session:
        _workflow_in_active_workspace(session, request, workflow_id, allowed_roles={"admin", "editor", "analyst"})
        workflow = _lock_workflow_for_version_write(session, workflow_id)
        if workflow is None:
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
            ).with_for_update()
        )
        previous_state = state_row.state if state_row else None
        if state_row is None:
            state_row = FindingState(
                workflow_id=workflow_id,
                fingerprint=fingerprint,
                state=normalized_state,
                reason=payload.reason,
                expires_at=payload.expires_at,
            )
            session.add(state_row)
        else:
            state_row.state = normalized_state
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
                "new_state": normalized_state,
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
            "assigned_to_user_id": str(state_row.assigned_to_user_id) if state_row.assigned_to_user_id else None,
            "expires_at": state_row.expires_at,
        }


@app.get("/api/workflows/{workflow_id}/findings/{fingerprint}/history")
def finding_state_history(workflow_id: UUID, fingerprint: str, request: Request, limit: int = Query(default=25, ge=1, le=100), offset: int = Query(default=0, ge=0)):
    with SessionLocal() as session:
        if _workflow_in_active_workspace(session, request, workflow_id) is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        entity_id = f"{workflow_id}:{fingerprint}"
        rows = session.scalars(
            select(AuditLog)
            .where(AuditLog.entity == "finding_state", AuditLog.entity_id == entity_id)
            .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return [
            {
                "action": row.action,
                "details": row.details,
                "created_at": row.created_at,
            }
            for row in rows
        ]


class TemplatePublishRequest(BaseModel):
    workflow_id: UUID
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=1000)
    category: str = Field(default="general", min_length=2, max_length=60)


class TemplateCloneRequest(BaseModel):
    name: str | None = Field(default=None, max_length=200)


class PresetCloneRequest(BaseModel):
    name: str | None = Field(default=None, max_length=200)


@app.get("/api/presets")
def list_builtin_presets():
    try:
        return list_presets()
    except PresetError as exc:
        raise HTTPException(status_code=500, detail="Built-in preset catalog is unavailable") from exc


@app.get("/api/presets/{preset_id}")
def get_builtin_preset(preset_id: str):
    try:
        preset = load_preset(preset_id)
    except PresetError as exc:
        status = 404 if str(exc).startswith("Unknown preset:") else 500
        detail = "Preset not found" if status == 404 else "Built-in preset catalog is unavailable"
        raise HTTPException(status_code=status, detail=detail) from exc
    return {key: value for key, value in preset.items() if key != "file"} | {"graph": sanitize_graph(preset["graph"])}


@app.post("/api/presets/{preset_id}/clone", status_code=201)
def clone_builtin_preset(preset_id: str, payload: PresetCloneRequest, request: Request):
    try:
        preset = load_preset(preset_id)
    except PresetError as exc:
        status = 404 if str(exc).startswith("Unknown preset:") else 500
        detail = "Preset not found" if status == 404 else "Built-in preset catalog is unavailable"
        raise HTTPException(status_code=status, detail=detail) from exc

    base_name = payload.name.strip() if payload.name else preset["name"]
    if not base_name:
        raise HTTPException(status_code=422, detail="Workflow name cannot be empty")
    graph_data = clone_graph(sanitize_graph(preset["graph"]), base_name[:200])
    graph = WorkflowGraph.model_validate(graph_data)
    validation = validate_graph(graph, registry)
    if not validation.valid:
        raise HTTPException(status_code=422, detail=validation.model_dump())

    with SessionLocal() as session:
        workspace, _ = require_active_workspace(session, request, allowed_roles={"admin", "editor"})
        linked_project_id = _validate_graph_workspace_sources(session, workspace.id, graph)
        workflow = Workflow(name=base_name[:200], workspace_id=workspace.id, project_id=linked_project_id, description=f"Created from built-in preset: {preset['id']}")
        session.add(workflow)
        session.flush()
        session.add(WorkflowVersion(workflow_id=workflow.id, version=1, graph=graph.model_dump(mode="json")))
        session.add(AuditLog(
            action="workflow_preset.cloned",
            entity="workflow",
            entity_id=str(workflow.id),
            details={"preset_id": preset["id"], "preset_version": preset["version"]},
        ))
        session.commit()
        return {
            "id": str(workflow.id),
            "name": workflow.name,
            "version": 1,
            "executed": False,
            "setup_required": preset["setup_required"],
        }


@app.get("/api/templates")
def list_workflow_templates(category: str | None = Query(default=None, max_length=60), q: str | None = Query(default=None, max_length=100)):
    with SessionLocal() as session:
        query = select(WorkflowTemplate).where(WorkflowTemplate.published.is_(True))
        if category:
            query = query.where(WorkflowTemplate.category == category)
        if q:
            query = query.where(WorkflowTemplate.name.ilike(f"%{q.strip()}%"))
        rows = session.scalars(query.order_by(WorkflowTemplate.category, WorkflowTemplate.name).limit(100)).all()
        return [{
            "id": str(row.id), "name": row.name, "description": row.description,
            "category": row.category, "node_count": len(row.graph.get("nodes", [])),
            "created_at": row.created_at,
        } for row in rows]


@app.get("/api/templates/{template_id}")
def get_workflow_template(template_id: UUID):
    with SessionLocal() as session:
        row = session.get(WorkflowTemplate, template_id)
        if row is None or not row.published:
            raise HTTPException(status_code=404, detail="Template not found")
        return {"id": str(row.id), "name": row.name, "description": row.description,
                "category": row.category, "graph": sanitize_graph(row.graph)}


@app.post("/api/templates/publish", status_code=201)
def publish_workflow_template(payload: TemplatePublishRequest, x_template_publish_token: str = Header(default="", alias="X-Template-Publish-Token")):
    with SessionLocal() as session:
        workflow = session.get(Workflow, payload.workflow_id)
        if workflow is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        require_workspace_api_token(session, x_template_publish_token, workflow.workspace_id, "template:publish")
        version = session.scalar(select(WorkflowVersion).where(
            WorkflowVersion.workflow_id == payload.workflow_id
        ).order_by(WorkflowVersion.version.desc()).limit(1))
        if version is None:
            raise HTTPException(status_code=409, detail="Workflow has no saved version")
        graph = WorkflowGraph.model_validate(version.graph)
        validation = validate_graph(graph, registry)
        if not validation.valid:
            raise HTTPException(status_code=422, detail=validation.model_dump())
        safe_graph = sanitize_graph(graph.model_dump(mode="json"))
        row = WorkflowTemplate(name=payload.name.strip(), description=payload.description.strip(),
                               category=payload.category.strip().lower(), graph=safe_graph, published=True)
        session.add(row)
        session.flush()
        session.add(AuditLog(action="workflow_template.published", entity="workflow_template",
                             entity_id=str(row.id), details={"source_workflow_id": str(workflow.id), "version": version.version}))
        session.commit()
        return {"id": str(row.id), "name": row.name, "published": True, "sanitized": True}


@app.post("/api/templates/{template_id}/clone", status_code=201)
def clone_workflow_template(template_id: UUID, payload: TemplateCloneRequest, request: Request):
    with SessionLocal() as session:
        template = session.get(WorkflowTemplate, template_id)
        if template is None or not template.published:
            raise HTTPException(status_code=404, detail="Template not found")
        base_name = payload.name.strip() if payload.name else f"{template.name} (copy)"
        if not base_name:
            raise HTTPException(status_code=422, detail="Workflow name cannot be empty")
        graph_data = clone_graph(sanitize_graph(template.graph), base_name[:200])
        graph = WorkflowGraph.model_validate(graph_data)
        validation = validate_graph(graph, registry)
        if not validation.valid:
            raise HTTPException(status_code=422, detail=validation.model_dump())
        workspace, _ = require_active_workspace(session, request, allowed_roles={"admin", "editor"})
        linked_project_id = _validate_graph_workspace_sources(session, workspace.id, graph)
        workflow = Workflow(name=base_name[:200], workspace_id=workspace.id, project_id=linked_project_id, description=f"Cloned from template: {template.name}")
        session.add(workflow)
        session.flush()
        session.add(WorkflowVersion(workflow_id=workflow.id, version=1, graph=graph.model_dump(mode="json")))
        session.add(AuditLog(action="workflow_template.cloned", entity="workflow", entity_id=str(workflow.id),
                             details={"template_id": str(template.id)}))
        session.commit()
        return {"id": str(workflow.id), "name": workflow.name, "version": 1, "executed": False}



