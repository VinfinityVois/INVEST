"""Add finding assignment and comments."""

from alembic import op
import sqlalchemy as sa


revision = "0010_finding_collaboration"
down_revision = "0009_workspace_api_tokens"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "finding_states",
        sa.Column(
            "assigned_to_user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_finding_states_assigned_to_user_id",
        "finding_states",
        ["assigned_to_user_id"],
    )
    op.create_table(
        "finding_comments",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("workflow_id", sa.Uuid(as_uuid=True), sa.ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("author_user_id", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_finding_comments_workflow_id", "finding_comments", ["workflow_id"])
    op.create_index("ix_finding_comments_fingerprint", "finding_comments", ["fingerprint"])
    op.create_index("ix_finding_comments_author_user_id", "finding_comments", ["author_user_id"])


def downgrade():
    raise RuntimeError(
        "0010_finding_collaboration downgrade is intentionally blocked; "
        "finding comments and assignment history require an explicit export."
    )
