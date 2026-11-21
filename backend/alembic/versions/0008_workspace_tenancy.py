"""Introduce organization/workspace tenancy and backfill legacy resources."""

from alembic import op
import sqlalchemy as sa
import uuid


revision = "0008_workspace_tenancy"
down_revision = "0007_login_rate_limits"
branch_labels = None
depends_on = None


def _uuid():
    # SQLAlchemy Uuid stores UUIDs as 32-character hex on SQLite and native
    # UUID on PostgreSQL; PostgreSQL also accepts the hyphen-free form.
    return uuid.uuid4().hex


def upgrade():
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("kind", sa.String(length=24), nullable=False, server_default="personal"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("kind IN ('personal', 'organization')", name="ck_organizations_kind"),
    )
    op.create_table(
        "workspaces",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.Uuid(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "name", name="uq_workspaces_organization_id_name"),
    )
    op.create_index("ix_workspaces_organization_id", "workspaces", ["organization_id"])
    op.create_index("ix_workspaces_org_default", "workspaces", ["organization_id", "is_default"])

    op.create_table(
        "organization_memberships",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.Uuid(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(length=24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_organization_memberships_organization_id_user_id"),
        sa.CheckConstraint("role IN ('owner', 'admin', 'member')", name="ck_org_membership_role"),
    )
    op.create_index("ix_organization_memberships_organization_id", "organization_memberships", ["organization_id"])
    op.create_index("ix_organization_memberships_user_id", "organization_memberships", ["user_id"])

    op.create_index(
        "uq_organization_single_owner",
        "organization_memberships",
        ["organization_id"],
        unique=True,
        sqlite_where=sa.text("role = 'owner'"),
        postgresql_where=sa.text("role = 'owner'"),
    )

    op.create_table(
        "workspace_memberships",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", sa.Uuid(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(length=24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("workspace_id", "user_id", name="uq_workspace_memberships_workspace_id_user_id"),
        sa.CheckConstraint("role IN ('admin', 'editor', 'analyst', 'viewer')", name="ck_workspace_membership_role"),
    )
    op.create_index("ix_workspace_memberships_workspace_id", "workspace_memberships", ["workspace_id"])
    op.create_index("ix_workspace_memberships_user_id", "workspace_memberships", ["user_id"])

    # Give every pre-existing account a private personal organization/workspace.
    bind = op.get_bind()
    users = bind.execute(sa.text("SELECT id, email, is_admin FROM users ORDER BY CASE WHEN is_admin THEN 0 ELSE 1 END, created_at, id")).mappings().all()
    personal_workspaces = {}
    for user in users:
        org_id, workspace_id = _uuid(), _uuid()
        bind.execute(sa.text(
            "INSERT INTO organizations (id, name, kind) VALUES (:id, :name, 'personal')"
        ), {"id": org_id, "name": f"{user['email']}'s personal organization"})
        bind.execute(sa.text(
            "INSERT INTO workspaces (id, organization_id, name, is_default) VALUES (:id, :org, 'Personal workspace', TRUE)"
        ), {"id": workspace_id, "org": org_id})
        bind.execute(sa.text(
            "INSERT INTO organization_memberships (id, organization_id, user_id, role) VALUES (:id, :org, :user, 'owner')"
        ), {"id": _uuid(), "org": org_id, "user": uuid.UUID(str(user["id"])).hex})
        bind.execute(sa.text(
            "INSERT INTO workspace_memberships (id, workspace_id, user_id, role) VALUES (:id, :workspace, :user, 'admin')"
        ), {"id": _uuid(), "workspace": workspace_id, "user": uuid.UUID(str(user["id"])).hex})
        personal_workspaces[str(user["id"])] = workspace_id

    active_admin = next((user for user in users if user["is_admin"]), None)
    if active_admin is not None:
        legacy_workspace_id = personal_workspaces[str(active_admin["id"])]
    else:
        # Keep pre-authentication data in an unclaimed workspace. The first
        # bootstrap administrator will claim it; ordinary users get no access.
        legacy_org_id, legacy_workspace_id = _uuid(), _uuid()
        bind.execute(sa.text(
            "INSERT INTO organizations (id, name, kind) VALUES (:id, 'Legacy organization', 'organization')"
        ), {"id": legacy_org_id})
        bind.execute(sa.text(
            "INSERT INTO workspaces (id, organization_id, name, is_default) VALUES (:id, :org, 'Legacy workspace', TRUE)"
        ), {"id": legacy_workspace_id, "org": legacy_org_id})

    op.add_column("projects", sa.Column("workspace_id", sa.Uuid(as_uuid=True), nullable=True))
    op.add_column("workflows", sa.Column("workspace_id", sa.Uuid(as_uuid=True), nullable=True))
    op.add_column("workflows", sa.Column("project_id", sa.Uuid(as_uuid=True), nullable=True))
    op.add_column("user_sessions", sa.Column("current_workspace_id", sa.Uuid(as_uuid=True), nullable=True))

    bind.execute(sa.text("UPDATE projects SET workspace_id = :workspace"), {"workspace": legacy_workspace_id})
    bind.execute(sa.text("UPDATE workflows SET workspace_id = :workspace"), {"workspace": legacy_workspace_id})
    bind.execute(sa.text("UPDATE credentials SET workspace_id = :workspace"), {"workspace": legacy_workspace_id})

    with op.batch_alter_table("projects") as batch:
        batch.alter_column("workspace_id", existing_type=sa.Uuid(as_uuid=True), nullable=False)
        batch.create_foreign_key("fk_projects_workspace_id_workspaces", "workspaces", ["workspace_id"], ["id"], ondelete="RESTRICT")
    with op.batch_alter_table("workflows") as batch:
        batch.alter_column("workspace_id", existing_type=sa.Uuid(as_uuid=True), nullable=False)
        batch.create_foreign_key("fk_workflows_workspace_id_workspaces", "workspaces", ["workspace_id"], ["id"], ondelete="RESTRICT")
        batch.create_foreign_key("fk_workflows_project_id_projects", "projects", ["project_id"], ["id"], ondelete="SET NULL")
    with op.batch_alter_table("user_sessions") as batch:
        batch.create_foreign_key("fk_user_sessions_current_workspace_id_workspaces", "workspaces", ["current_workspace_id"], ["id"], ondelete="SET NULL")
    with op.batch_alter_table("credentials") as batch:
        batch.create_foreign_key("fk_credentials_workspace_id_workspaces", "workspaces", ["workspace_id"], ["id"], ondelete="CASCADE")

    op.create_index("ix_projects_workspace_id", "projects", ["workspace_id"])
    op.create_index("ix_workflows_workspace_id", "workflows", ["workspace_id"])
    op.create_index("ix_workflows_project_id", "workflows", ["project_id"])
    op.create_index("ix_user_sessions_current_workspace_id", "user_sessions", ["current_workspace_id"])


def downgrade():
    # Ownership backfill is not safely reversible: dropping these columns
    # would erase tenant assignment. Require an explicit data export/rollback.
    raise RuntimeError(
        "0008_workspace_tenancy downgrade is intentionally blocked; export and "
        "reconcile workspace ownership before designing a data-preserving rollback."
    )
