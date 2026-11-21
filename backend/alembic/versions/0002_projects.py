"""Persistent project library."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

UUID_TYPE = sa.Uuid(as_uuid=True)

revision = "0002_projects"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "projects",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("workspace_path", sa.String(260), nullable=False, unique=True),
        sa.Column("original_filename", sa.String(255)),
        sa.Column("file_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expanded_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade():
    op.drop_table("projects")
