"""Initial workflow persistence schema."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

UUID_TYPE = sa.Uuid(as_uuid=True)
JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "workflows",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "workflow_versions",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("workflow_id", UUID_TYPE, sa.ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("graph", JSON_TYPE, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("workflow_id", "version"),
    )
    op.create_table(
        "runs",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("workflow_id", UUID_TYPE, sa.ForeignKey("workflows.id", ondelete="SET NULL")),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("source", sa.String(24), nullable=False),
        sa.Column("graph_snapshot", JSON_TYPE, nullable=False),
        sa.Column("result", JSON_TYPE),
        sa.Column("error", sa.Text()),
        sa.Column("queued_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("locked_by", sa.String(120)),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "findings",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("run_id", UUID_TYPE, sa.ForeignKey("runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("rule_id", sa.String(160), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("line", sa.Integer()),
        sa.Column("payload", JSON_TYPE, nullable=False),
    )
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_table(
        "finding_states",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("workflow_id", UUID_TYPE, sa.ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("workflow_id", "fingerprint"),
    )
    op.create_table(
        "credentials",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("workspace_id", UUID_TYPE, nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("provider", sa.String(80), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("key_id", sa.String(80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_credentials_workspace_id", "credentials", ["workspace_id"])
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("action", sa.String(160), nullable=False),
        sa.Column("entity", sa.String(120), nullable=False),
        sa.Column("entity_id", sa.String(120)),
        sa.Column("details", JSON_TYPE, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

def downgrade():
    op.drop_table("audit_log")
    op.drop_index("ix_credentials_workspace_id", table_name="credentials")
    op.drop_table("credentials")
    op.drop_table("finding_states")
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_table("findings")
    op.drop_table("runs")
    op.drop_table("workflow_versions")
    op.drop_table("workflows")
