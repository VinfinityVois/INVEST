from app.queue import _findings_from_result, make_worker_id


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
