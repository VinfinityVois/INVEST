"""Persist cron schedules for saved workflows."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

UUID_TYPE = sa.Uuid(as_uuid=True)

revision = "0003_workflow_schedules"
down_revision = "0002_projects"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "workflow_schedules",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("workflow_id", UUID_TYPE, sa.ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("cron_expression", sa.String(120), nullable=False),
        sa.Column("timezone", sa.String(80), nullable=False, server_default="UTC"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_workflow_schedules_due", "workflow_schedules", ["enabled", "next_run_at"])


def downgrade():
    op.drop_index("ix_workflow_schedules_due", table_name="workflow_schedules")
    op.drop_table("workflow_schedules")
