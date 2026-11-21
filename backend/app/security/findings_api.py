"""Workspace-scoped finding comments and assignment."""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from typing import Literal
from sqlalchemy import select

from app.db import SessionLocal
from app.models import AuditLog, Finding, FindingComment, FindingState, User, Workflow, WorkflowRun
from app.security.tenancy import require_active_workspace, workspace_role

router = APIRouter(tags=["finding-collaboration"])


class FindingCommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=5000)

    @field_validator("body")
    @classmethod
    def clean_body(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Comment cannot be empty.")
        return value


class FindingAssigneeUpdate(BaseModel):
    user_id: UUID | None = None


class FindingBulkUpdate(BaseModel):
    fingerprints: list[str] = Field(min_length=1, max_length=100)
    state: Literal["open", "in_progress", "resolved", "accepted_risk", "false_positive"]
    reason: str = Field(min_length=3, max_length=2000)

    @field_validator("fingerprints")
    @classmethod
    def unique_fingerprints(cls, values: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(value.strip() for value in values))
        if any(not value or len(value) > 64 for value in normalized):
            raise ValueError("Invalid finding fingerprint.")
        return normalized

    @field_validator("reason")
    @classmethod
    def clean_reason(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 3:
            raise ValueError("A reason is required.")
        return value


def _actor(request: Request) -> User:
    actor = getattr(request.state, "user", None)
    if actor is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return actor


def _workflow_and_finding(db, request: Request, workflow_id: UUID, fingerprint: str, *, roles=None):
    workspace, _ = require_active_workspace(db, request, allowed_roles=roles)
    workflow = db.scalar(
        select(Workflow).where(
            Workflow.id == workflow_id,
            Workflow.workspace_id == workspace.id,
        )
    )
    if workflow is None:
        raise HTTPException(status_code=404, detail="Workflow not found.")
    if not fingerprint or len(fingerprint) > 64:
        raise HTTPException(status_code=422, detail="Invalid finding fingerprint.")
    finding = db.scalar(
        select(Finding)
        .join(WorkflowRun, Finding.run_id == WorkflowRun.id)
        .where(
            WorkflowRun.workflow_id == workflow_id,
            Finding.fingerprint == fingerprint,
        )
        .limit(1)
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found in this workflow.")
    return workspace, workflow, finding


@router.get("/api/workflows/{workflow_id}/findings/{fingerprint}/comments")
def list_finding_comments(workflow_id: UUID, fingerprint: str, request: Request):
    with SessionLocal() as db:
        _workflow_and_finding(db, request, workflow_id, fingerprint)
        rows = db.execute(
            select(FindingComment, User.email)
            .join(User, User.id == FindingComment.author_user_id)
            .where(
                FindingComment.workflow_id == workflow_id,
                FindingComment.fingerprint == fingerprint,
            )
            .order_by(FindingComment.created_at.asc(), FindingComment.id.asc())
        ).all()
        return {"items": [{
            "id": str(comment.id),
            "author_user_id": str(comment.author_user_id),
            "author_email": email,
            "body": comment.body,
            "created_at": comment.created_at,
        } for comment, email in rows]}


@router.post("/api/workflows/{workflow_id}/findings/{fingerprint}/comments", status_code=201)
def add_finding_comment(workflow_id: UUID, fingerprint: str, payload: FindingCommentCreate, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        _workflow_and_finding(db, request, workflow_id, fingerprint, roles={"admin", "editor", "analyst"})
        comment = FindingComment(
            workflow_id=workflow_id,
            fingerprint=fingerprint,
            author_user_id=actor.id,
            body=payload.body,
        )
        db.add(comment)
        db.flush()
        db.add(AuditLog(
            action="finding.comment.created",
            entity="finding_comment",
            entity_id=str(comment.id),
            details={"actor_user_id": str(actor.id), "workflow_id": str(workflow_id), "fingerprint": fingerprint},
        ))
        db.commit()
        return {
            "id": str(comment.id),
            "author_user_id": str(actor.id),
            "author_email": actor.email,
            "body": comment.body,
            "created_at": comment.created_at,
        }


@router.delete("/api/workflows/{workflow_id}/findings/{fingerprint}/comments/{comment_id}")
def delete_finding_comment(workflow_id: UUID, fingerprint: str, comment_id: UUID, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        workspace, _, _ = _workflow_and_finding(db, request, workflow_id, fingerprint)
        comment = db.scalar(
            select(FindingComment).where(
                FindingComment.id == comment_id,
                FindingComment.workflow_id == workflow_id,
                FindingComment.fingerprint == fingerprint,
            )
        )
        if comment is None:
            raise HTTPException(status_code=404, detail="Comment not found.")
        role = workspace_role(db, actor.id, workspace.id)
        if comment.author_user_id != actor.id and role not in {"admin", "editor"}:
            raise HTTPException(status_code=403, detail="You can only delete your own comments.")
        db.add(AuditLog(
            action="finding.comment.deleted",
            entity="finding_comment",
            entity_id=str(comment.id),
            details={"actor_user_id": str(actor.id), "workflow_id": str(workflow_id), "fingerprint": fingerprint},
        ))
        db.delete(comment)
        db.commit()
        return {"status": "deleted"}


@router.patch("/api/workflows/{workflow_id}/findings/{fingerprint}/assignee")
def update_finding_assignee(workflow_id: UUID, fingerprint: str, payload: FindingAssigneeUpdate, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        workspace, _, _ = _workflow_and_finding(
            db, request, workflow_id, fingerprint, roles={"admin", "editor", "analyst"}
        )
        assignee = None
        if payload.user_id is not None:
            assignee = db.get(User, payload.user_id)
            if assignee is None or not assignee.is_active:
                raise HTTPException(status_code=404, detail="Active assignee not found.")
            if workspace_role(db, assignee.id, workspace.id) is None:
                raise HTTPException(status_code=422, detail="Assignee must have access to this Workspace.")
        state_row = db.scalar(
            select(FindingState).where(
                FindingState.workflow_id == workflow_id,
                FindingState.fingerprint == fingerprint,
            ).with_for_update()
        )
        if state_row is None:
            state_row = FindingState(
                workflow_id=workflow_id,
                fingerprint=fingerprint,
                state="open",
                reason="Finding assigned.",
            )
            db.add(state_row)
        previous_assignee = state_row.assigned_to_user_id
        state_row.assigned_to_user_id = payload.user_id
        db.add(AuditLog(
            action="finding.assignee.changed",
            entity="finding_state",
            entity_id=f"{workflow_id}:{fingerprint}",
            details={
                "actor_user_id": str(actor.id),
                "workflow_id": str(workflow_id),
                "fingerprint": fingerprint,
                "previous_assignee_user_id": str(previous_assignee) if previous_assignee else None,
                "assignee_user_id": str(payload.user_id) if payload.user_id else None,
            },
        ))
        db.commit()
        return {
            "workflow_id": str(workflow_id),
            "fingerprint": fingerprint,
            "assigned_to_user_id": str(payload.user_id) if payload.user_id else None,
            "assigned_to_email": assignee.email if assignee else None,
        }


@router.post("/api/workflows/{workflow_id}/findings/bulk")
def bulk_update_finding_states(workflow_id: UUID, payload: FindingBulkUpdate, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        _workspace, _workflow, _finding = _workflow_and_finding(
            db, request, workflow_id, payload.fingerprints[0], roles={"admin", "editor", "analyst"}
        )
        existing = set(db.scalars(
            select(Finding.fingerprint)
            .join(WorkflowRun, Finding.run_id == WorkflowRun.id)
            .where(
                WorkflowRun.workflow_id == workflow_id,
                Finding.fingerprint.in_(payload.fingerprints),
            )
            .distinct()
        ).all())
        missing = sorted(set(payload.fingerprints) - existing)
        if missing:
            raise HTTPException(status_code=404, detail={"message": "Some findings are not in this workflow.", "missing": missing})
        rows = db.scalars(
            select(FindingState).where(
                FindingState.workflow_id == workflow_id,
                FindingState.fingerprint.in_(payload.fingerprints),
            ).with_for_update()
        ).all()
        by_fingerprint = {row.fingerprint: row for row in rows}
        updated = []
        for fingerprint in payload.fingerprints:
            row = by_fingerprint.get(fingerprint)
            previous_state = row.state if row else None
            if row is None:
                row = FindingState(
                    workflow_id=workflow_id,
                    fingerprint=fingerprint,
                    state=payload.state,
                    reason=payload.reason,
                )
                db.add(row)
            else:
                row.state = payload.state
                row.reason = payload.reason
                row.expires_at = None
            db.add(AuditLog(
                action="finding.state.bulk_changed",
                entity="finding_state",
                entity_id=f"{workflow_id}:{fingerprint}",
                details={
                    "actor_user_id": str(actor.id),
                    "workflow_id": str(workflow_id),
                    "fingerprint": fingerprint,
                    "previous_state": previous_state,
                    "new_state": payload.state,
                    "reason": payload.reason,
                },
            ))
            updated.append(fingerprint)
        db.commit()
        return {"updated": len(updated), "fingerprints": updated, "state": payload.state}
