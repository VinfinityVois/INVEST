"""Require non-null timestamps on persisted records."""
from alembic import op
import sqlalchemy as sa


revision = "0005_not_null_timestamps"
down_revision = "0004_workflow_templates"
branch_labels = None
depends_on = None


_TIMESTAMP_COLUMNS = (
    ("audit_log", "created_at"),
    ("credentials", "created_at"),
    ("projects", "created_at"),
    ("projects", "updated_at"),
    ("runs", "queued_at"),
    ("workflow_schedules", "created_at"),
    ("workflow_schedules", "updated_at"),
    ("workflow_templates", "created_at"),
    ("workflow_templates", "updated_at"),
    ("workflow_versions", "created_at"),
    ("workflows", "created_at"),
    ("workflows", "updated_at"),
)


def _set_nullable(table_name, column_name, nullable):
    bind = op.get_bind()
    column_type = sa.DateTime(timezone=True)

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table(table_name) as batch_op:
            batch_op.alter_column(
                column_name,
                existing_type=column_type,
                nullable=nullable,
            )
    else:
        op.alter_column(
            table_name,
            column_name,
            existing_type=column_type,
            nullable=nullable,
        )


def upgrade():
    for table_name, column_name in _TIMESTAMP_COLUMNS:
        op.execute(
            sa.text(
                f'UPDATE "{table_name}" '
                f'SET "{column_name}" = CURRENT_TIMESTAMP '
                f'WHERE "{column_name}" IS NULL'
            )
        )
        _set_nullable(table_name, column_name, False)


def downgrade():
    for table_name, column_name in reversed(_TIMESTAMP_COLUMNS):
        _set_nullable(table_name, column_name, True)
