import os
import sqlite3
import subprocess
import pytest
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]

TIMESTAMP_COLUMNS = {
    "audit_log": ["created_at"],
    "credentials": ["created_at"],
    "projects": ["created_at", "updated_at"],
    "runs": ["queued_at"],
    "workflow_schedules": ["created_at", "updated_at"],
    "workflow_templates": ["created_at", "updated_at"],
    "workflow_versions": ["created_at"],
    "workflows": ["created_at", "updated_at"],
}


def _run_alembic(database_url, *args):
    env = os.environ.copy()
    env["DATABASE_URL"] = database_url

    command = [sys.executable, "-m", "alembic", *args]
    result = subprocess.run(
        command,
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        if args and args[0] == "upgrade":
            pytest.fail(
                "Alembic upgrade failed.\n"
                f"stdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )
        raise subprocess.CalledProcessError(
            result.returncode, command, output=result.stdout, stderr=result.stderr
        )
    return result


def _assert_revision(connection, expected):
    revision = connection.execute(
        "SELECT version_num FROM alembic_version"
    ).fetchone()
    assert revision == (expected,)


def _assert_timestamp_nullability(connection, nullable):
    expected_notnull = 0 if nullable else 1

    for table, columns in TIMESTAMP_COLUMNS.items():
        info = connection.execute(
            f'PRAGMA table_info("{table}")'
        ).fetchall()
        actual = {row[1]: row[3] for row in info}

        for column in columns:
            assert actual[column] == expected_notnull, (
                f"{table}.{column}: expected nullable={nullable}"
            )


def _assert_timestamps_populated(connection):
    for table, columns in TIMESTAMP_COLUMNS.items():
        for column in columns:
            count = connection.execute(
                f'SELECT COUNT(*) FROM "{table}" '
                f'WHERE "{column}" IS NULL'
            ).fetchone()[0]

            assert count == 0, (
                f"{table}.{column}: {count} NULL values remain"
            )


def _assert_auth_tables(connection, present):
    for table in ("users", "user_sessions", "login_rate_limits"):
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone() is not None

        assert exists is present, (
            f"{table}: expected present={present}, got {exists}"
        )


def _assert_rate_limit_schema(connection, present):
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = 'login_rate_limits'"
    ).fetchone() is not None

    assert exists is present, (
        f"login_rate_limits: expected present={present}, got {exists}"
    )

    if present:
        columns = {
            row[1]: row
            for row in connection.execute(
                'PRAGMA table_info("login_rate_limits")'
            ).fetchall()
        }
        assert set(columns) == {
            "scope",
            "key_hash",
            "window_started_at",
            "attempts",
        }
        assert columns["scope"][3] == 1
        assert columns["key_hash"][3] == 1
        assert columns["window_started_at"][3] == 1
        assert columns["attempts"][3] == 1

        indexes = {
            row[1]
            for row in connection.execute(
                'PRAGMA index_list("login_rate_limits")'
            ).fetchall()
        }
        assert "ix_login_rate_limits_window_started_at" in indexes

def _assert_foreign_keys(connection):
    errors = connection.execute(
        "PRAGMA foreign_key_check"
    ).fetchall()
    assert errors == []


def _seed_existing_rows(connection):
    workflow_id = "a" * 32

    connection.execute(
        """
        INSERT INTO workflows (id, name, description, created_at, updated_at)
        VALUES (?, ?, ?, NULL, NULL)
        """,
        (workflow_id, "Migration test workflow", "Preserve this workflow"),
    )

    connection.execute(
        """
        INSERT INTO workflow_versions
            (id, workflow_id, version, graph, created_at)
        VALUES (?, ?, ?, ?, NULL)
        """,
        ("b" * 32, workflow_id, 1, '{"nodes": []}'),
    )

    connection.execute(
        """
        INSERT INTO runs
            (id, workflow_id, status, source, graph_snapshot, queued_at)
        VALUES (?, ?, ?, ?, ?, NULL)
        """,
        ("c" * 32, workflow_id, "queued", "ui", '{"nodes": []}'),
    )

    connection.execute(
        """
        INSERT INTO credentials
            (id, workspace_id, name, provider, ciphertext, nonce, key_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
        """,
        ("d" * 32, "e" * 32, "Migration credential", "test", b"cipher", b"nonce", "test-key"),
    )

    connection.execute(
        """
        INSERT INTO audit_log (action, entity, entity_id, details, created_at)
        VALUES (?, ?, ?, ?, NULL)
        """,
        ("migration.test", "workflow", workflow_id, '{"source": "test"}'),
    )

    connection.execute(
        """
        INSERT INTO projects
            (id, name, workspace_path, file_count, expanded_bytes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, NULL, NULL)
        """,
        ("f" * 32, "Migration project", "/tmp/migration-project", 2, 128),
    )

    connection.execute(
        """
        INSERT INTO workflow_schedules
            (id, workflow_id, cron_expression, created_at, updated_at)
        VALUES (?, ?, ?, NULL, NULL)
        """,
        ("1" * 32, workflow_id, "0 0 * * *"),
    )

    connection.execute(
        """
        INSERT INTO workflow_templates
            (id, name, graph, created_at, updated_at)
        VALUES (?, ?, ?, NULL, NULL)
        """,
        ("2" * 32, "Migration template", '{"nodes": []}'),
    )


def _assert_existing_rows_preserved(connection):
    assert connection.execute(
        "SELECT name, description FROM workflows WHERE id = ?",
        ("a" * 32,),
    ).fetchone() == (
        "Migration test workflow",
        "Preserve this workflow",
    )

    assert connection.execute(
        "SELECT workflow_id, version, graph FROM workflow_versions WHERE id = ?",
        ("b" * 32,),
    ).fetchone() == (
        "a" * 32,
        1,
        '{"nodes": []}',
    )

    assert connection.execute(
        "SELECT workflow_id, status, source FROM runs WHERE id = ?",
        ("c" * 32,),
    ).fetchone() == ("a" * 32, "queued", "ui")

    assert connection.execute(
        "SELECT name, provider, ciphertext, nonce, key_id FROM credentials WHERE id = ?",
        ("d" * 32,),
    ).fetchone() == (
        "Migration credential",
        "test",
        b"cipher",
        b"nonce",
        "test-key",
    )

    assert connection.execute(
        "SELECT action, entity, entity_id FROM audit_log"
    ).fetchone() == ("migration.test", "workflow", "a" * 32)

    assert connection.execute(
        "SELECT name, workspace_path, file_count, expanded_bytes FROM projects WHERE id = ?",
        ("f" * 32,),
    ).fetchone() == (
        "Migration project",
        "/tmp/migration-project",
        2,
        128,
    )

    assert connection.execute(
        "SELECT workflow_id, cron_expression FROM workflow_schedules WHERE id = ?",
        ("1" * 32,),
    ).fetchone() == ("a" * 32, "0 0 * * *")

    assert connection.execute(
        "SELECT name, graph FROM workflow_templates WHERE id = ?",
        ("2" * 32,),
    ).fetchone() == ("Migration template", '{"nodes": []}')


def _assert_workspace_backfill(connection):
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    assert {
        "organizations",
        "workspaces",
        "organization_memberships",
        "workspace_memberships",
        "api_tokens",
        "finding_comments",
    }.issubset(tables)

    project = connection.execute(
        "SELECT workspace_id FROM projects WHERE id = ?",
        ("f" * 32,),
    ).fetchone()
    workflow = connection.execute(
        "SELECT workspace_id FROM workflows WHERE id = ?",
        ("a" * 32,),
    ).fetchone()
    credential = connection.execute(
        "SELECT workspace_id FROM credentials WHERE id = ?",
        ("d" * 32,),
    ).fetchone()
    assert project is not None and project[0]
    assert workflow is not None and workflow[0] == project[0]
    assert credential is not None and credential[0] == project[0]

    workspace_count = connection.execute(
        "SELECT COUNT(*) FROM workspaces"
    ).fetchone()[0]
    assert workspace_count == 2
    finding_state_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(finding_states)").fetchall()
    }
    assert "assigned_to_user_id" in finding_state_columns
    admin_workspace = connection.execute(
        "SELECT workspace_memberships.workspace_id FROM workspace_memberships "
        "JOIN organization_memberships ON organization_memberships.organization_id = "
        "(SELECT organization_id FROM workspaces WHERE id = workspace_memberships.workspace_id) "
        "WHERE workspace_memberships.user_id = ? AND organization_memberships.user_id = workspace_memberships.user_id "
        "AND organization_memberships.role = 'owner'",
        ("9" * 32,),
    ).fetchone()
    assert admin_workspace is not None
    assert project[0] == admin_workspace[0]
    assert connection.execute(
        "SELECT COUNT(*) FROM organization_memberships"
    ).fetchone()[0] == 2


def test_alembic_sqlite_upgrade_downgrade_cycle(tmp_path):
    database_path = tmp_path / "migration-test.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    # Prepare the database at the migration immediately before 0005.
    _run_alembic(database_url, "upgrade", "0004_workflow_templates")

    with sqlite3.connect(database_path) as connection:
        _assert_revision(connection, "0004_workflow_templates")
        _assert_timestamp_nullability(connection, nullable=True)
        _assert_auth_tables(connection, present=False)
        _assert_rate_limit_schema(connection, present=False)

        _seed_existing_rows(connection)
        connection.commit()

        _assert_existing_rows_preserved(connection)
        _assert_foreign_keys(connection)

        # Confirm that the test data really contains NULL timestamps.
        for table, columns in TIMESTAMP_COLUMNS.items():
            for column in columns:
                count = connection.execute(
                    f'SELECT COUNT(*) FROM "{table}" '
                    f'WHERE "{column}" IS NULL'
                ).fetchone()[0]
                assert count == 1, (
                    f"{table}.{column}: expected one seeded NULL, got {count}"
                )

    # Upgrade through auth, seed legacy accounts, then apply tenant backfill.
    _run_alembic(database_url, "upgrade", "0007_login_rate_limits")
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "INSERT INTO users (id, email, password_hash, is_active, is_admin) VALUES (?, ?, ?, ?, ?)",
            ("9" * 32, "admin@example.test", "test-hash", 1, 1),
        )
        connection.execute(
            "INSERT INTO users (id, email, password_hash, is_active, is_admin) VALUES (?, ?, ?, ?, ?)",
            ("8" * 32, "member@example.test", "test-hash", 1, 0),
        )
        connection.commit()
    _run_alembic(database_url, "upgrade", "head")

    with sqlite3.connect(database_path) as connection:
        _assert_revision(connection, "0010_finding_collaboration")
        _assert_timestamp_nullability(connection, nullable=False)
        _assert_auth_tables(connection, present=True)
        _assert_rate_limit_schema(connection, present=True)
        _assert_timestamps_populated(connection)
        _assert_existing_rows_preserved(connection)
        _assert_workspace_backfill(connection)
        _assert_foreign_keys(connection)

    # Ownership assignment is deliberately non-reversible without a
    # reviewed export/reconciliation plan; downgrade must fail closed.
    with pytest.raises(subprocess.CalledProcessError):
        _run_alembic(database_url, "downgrade", "0007_login_rate_limits")

    with sqlite3.connect(database_path) as connection:
        _assert_revision(connection, "0010_finding_collaboration")
        _assert_workspace_backfill(connection)
        _assert_existing_rows_preserved(connection)
        _assert_foreign_keys(connection)



