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

def test_cron_rejects_six_field_seconds_extension():
    with pytest.raises(ValueError, match="cron"):
        next_run_time("*/5 * * * * *", "UTC")


def test_cron_next_run_tracks_summer_daylight_saving_time():
    after = datetime(2026, 3, 28, 10, 0, tzinfo=timezone.utc)
    assert next_run_time("0 9 * * *", "Europe/Stockholm", after) == datetime(2026, 3, 29, 7, 0, tzinfo=timezone.utc)


def test_cron_next_run_tracks_winter_daylight_saving_time():
    after = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    assert next_run_time("0 9 * * *", "Europe/Stockholm", after) == datetime(2026, 10, 25, 8, 0, tzinfo=timezone.utc)
