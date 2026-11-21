import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Project, User, Workspace
from app.security.passwords import hash_password
from app.security.tenancy import create_personal_workspace
from app.security.file_versions import sha256_text
import app.main as main
import app.security.api as auth_api
import app.security.tokens_api as tokens_api


@pytest.fixture
def project_client(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(main, "SessionLocal", testing_session)
    monkeypatch.setattr(auth_api, "SessionLocal", testing_session)
    monkeypatch.setattr(tokens_api, "SessionLocal", testing_session)
    monkeypatch.setattr(main.settings, "workspace_root", str(tmp_path))

    with testing_session() as db:
        user = User(
            id=uuid.uuid4(),
            email="files@example.test",
            password_hash=hash_password("CorrectPassword123!"),
            is_active=True,
            is_admin=True,
        )
        db.add(user)
        db.flush()
        workspace = create_personal_workspace(db, user)
        project_id = uuid.uuid4()
        project = Project(
            id=project_id,
            workspace_id=workspace.id,
            name="History test",
            workspace_path=f"projects/project-{project_id}",
            original_filename="history.zip",
            file_count=1,
            expanded_bytes=20,
        )
        db.add(project)
        db.commit()

    project_root = tmp_path / f"projects/project-{project_id}"
    (project_root / "src").mkdir(parents=True)
    file_path = project_root / "src/main.py"
    file_path.write_text("value = 'one'\n", encoding="utf-8")

    with TestClient(main.app) as client:
        login = client.post(
            "/api/auth/login",
            json={"email": "files@example.test", "password": "CorrectPassword123!"},
            headers={"Origin": "http://localhost:5173"},
        )
        assert login.status_code == 200
        yield client, project_id, file_path

    engine.dispose()


def test_project_file_history_and_rollback_are_version_checked(project_client):
    client, project_id, file_path = project_client
    path = "src/main.py"
    url = f"/api/projects/{project_id}/file"
    headers = {"Origin": "http://localhost:5173"}
    first = "value = 'one'\n"
    second = "value = 'two'\n"
    third = "value = 'three'\n"

    update_two = client.put(
        url,
        params={"path": path},
        json={"content": second, "expected_sha256": sha256_text(first)},
        headers=headers,
    )
    assert update_two.status_code == 200

    update_three = client.put(
        url,
        params={"path": path},
        json={"content": third, "expected_sha256": sha256_text(second)},
        headers=headers,
    )
    assert update_three.status_code == 200

    history = client.get(
        f"/api/projects/{project_id}/file-versions",
        params={"path": path},
    )
    assert history.status_code == 200
    versions = history.json()["versions"]
    assert versions[0]["sha256"] == sha256_text(third)
    assert any(item["sha256"] == sha256_text(first) and item["available"] for item in versions)

    restored = client.post(
        f"/api/projects/{project_id}/file-rollback",
        params={"path": path},
        json={
            "target_sha256": sha256_text(first),
            "expected_sha256": sha256_text(third),
        },
        headers=headers,
    )
    assert restored.status_code == 200
    assert file_path.read_text(encoding="utf-8") == first

    stale_restore = client.post(
        f"/api/projects/{project_id}/file-rollback",
        params={"path": path},
        json={
            "target_sha256": sha256_text(second),
            "expected_sha256": sha256_text(third),
        },
        headers=headers,
    )
    assert stale_restore.status_code == 409
    assert stale_restore.json()["detail"]["code"] == "PROJECT_FILE_VERSION_CONFLICT"
