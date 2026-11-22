"""Persist workspace-scoped integration allowlists."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0011_workspace_integrations"
down_revision = "0010_finding_collaboration"
branch_labels = None
depends_on = None


JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade():
    op.create_table(
        "workspace_integrations",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", sa.Uuid(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(40), nullable=False),
        sa.Column("config", JSON_TYPE, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("workspace_id", "provider", name="uq_workspace_integrations_provider"),
    )
    op.create_index(
        "ix_workspace_integrations_workspace_id",
        "workspace_integrations",
        ["workspace_id"],
    )


def downgrade():
    raise RuntimeError(
        "0011_workspace_integrations downgrade is intentionally blocked; "
        "workspace integration settings and encrypted credentials require an explicit export."
    )
