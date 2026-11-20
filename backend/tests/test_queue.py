from datetime import datetime, timezone

import pytest

from app.queue import _findings_from_result, _next_schedule_at, make_worker_id


def test_queue_deduplicates_findings_by_fingerprint():
    result = {
        "outputs": {
            "secrets": {
                "findings": [
                    {"fingerprint": "same", "rule_id": "SECRET_A"},
                    {"fingerprint": "unique", "rule_id": "SECRET_B"},
                ]
            },
            "merge": {
                "findings": [
                    {"fingerprint": "same", "rule_id": "SECRET_A"},
                    {"rule_id": "NO_FINGERPRINT"},
                ]
            },
        }
    }

    findings = _findings_from_result(result)

    assert [item["fingerprint"] for item in findings] == ["same", "unique"]


def test_worker_id_is_non_empty_and_unique():
    first = make_worker_id()
    second = make_worker_id()

    assert first
    assert first != second



def test_cron_schedule_computes_next_occurrence_in_timezone():
    base = datetime(2026, 11, 21, 10, 2, tzinfo=timezone.utc)

    next_run = _next_schedule_at("*/5 * * * *", "Europe/Amsterdam", base)

    assert next_run == datetime(2026, 11, 21, 10, 5, tzinfo=timezone.utc)


def test_cron_schedule_rejects_unknown_timezone():
    with pytest.raises(Exception):
        _next_schedule_at("*/5 * * * *", "Mars/Olympus", datetime.now(timezone.utc))
