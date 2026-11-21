"""HTTP authentication endpoints."""

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.config import settings
from app.db import SessionLocal
from app.security.auth import authenticate_user
from app.security.sessions import (
    DEFAULT_SESSION_LIFETIME,
    create_session,
    revoke_session,
)

router = APIRouter(prefix="/api/auth", tags=["authentication"])

SESSION_COOKIE = "invest_session"


class LoginRequest(BaseModel):
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=int(DEFAULT_SESSION_LIFETIME.total_seconds()),
        httponly=True,
        secure=settings.app_env.lower() == "production",
        samesite="lax",
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=settings.app_env.lower() == "production",
        samesite="lax",
    )


@router.post("/login")
def login(payload: LoginRequest, response: Response):
    with SessionLocal() as db:
        user = authenticate_user(db, payload.email, payload.password)
        if user is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password",
            )

        token, _ = create_session(db, user.id)
        db.commit()

        _set_session_cookie(response, token)

        return {
            "id": str(user.id),
            "email": user.email,
            "is_admin": user.is_admin,
        }


@router.get("/me")
def current_user(request: Request):
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    return {
        "id": str(user.id),
        "email": user.email,
        "is_admin": user.is_admin,
    }


@router.post("/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)

    with SessionLocal() as db:
        revoke_session(db, token)
        db.commit()

    _clear_session_cookie(response)
    return {"status": "ok"}
