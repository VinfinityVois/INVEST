"""Public, sanitized workflow templates."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

UUID_TYPE = sa.Uuid(as_uuid=True)
JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

revision = "0004_workflow_templates"
down_revision = "0003_workflow_schedules"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "workflow_templates",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False, server_default=""),
        sa.Column("category", sa.String(60), nullable=False, server_default="general"),
        sa.Column("graph", JSON_TYPE, nullable=False),
        sa.Column("published", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_workflow_templates_published_category", "workflow_templates", ["published", "category"])


def downgrade():
    op.drop_index("ix_workflow_templates_published_category", table_name="workflow_templates")
    op.drop_table("workflow_templates")
