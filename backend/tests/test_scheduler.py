from datetime import datetime, timezone
import pytest
from app.scheduler import next_run_time

def test_cron_next_run_respects_timezone():
    after = datetime(2026, 1, 1, 10, 1, tzinfo=timezone.utc)
    assert next_run_time("0 12 * * *", "Europe/Stockholm", after) == datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc)

def test_cron_rejects_invalid_expression():
    with pytest.raises(ValueError, match="cron"):
        next_run_time("not a cron", "UTC")

def test_cron_rejects_unknown_timezone():
    with pytest.raises(ValueError, match="часовой пояс"):
        next_run_time("0 12 * * *", "Mars/Olympus")
