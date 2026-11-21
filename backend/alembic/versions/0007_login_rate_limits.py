"""Add persistent login rate-limit counters."""

from alembic import op
import sqlalchemy as sa


revision = "0007_login_rate_limits"
down_revision = "0006_user_auth"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "login_rate_limits",
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "window_started_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint(
            "scope",
            "key_hash",
            name="pk_login_rate_limits",
        ),
        sa.CheckConstraint(
            "scope IN ('email', 'ip')",
            name="ck_login_rate_limits_scope",
        ),
        sa.CheckConstraint(
            "attempts > 0",
            name="ck_login_rate_limits_attempts_positive",
        ),
    )

    op.create_index(
        "ix_login_rate_limits_window_started_at",
        "login_rate_limits",
        ["window_started_at"],
        unique=False,
    )


def downgrade():
    op.drop_index(
        "ix_login_rate_limits_window_started_at",
        table_name="login_rate_limits",
    )
    op.drop_table("login_rate_limits")
