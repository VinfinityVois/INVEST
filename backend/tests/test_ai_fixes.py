import json

import httpx
import pytest

from app.ai.fixes import AIFixError, apply_line_changes, generate_fix_proposal


def test_apply_line_changes_requires_exact_source_context():
    original = "def handler():\n    return True\n"
    changed = apply_line_changes(original, [{
        "start_line": 2,
        "expected": ["    return True"],
        "replacement": ["    return False"],
    }])
    assert changed == "def handler():\n    return False\n"


def test_apply_line_changes_preserves_crlf_and_final_newline():
    original = "first\r\nsecond\r\n"
    changed = apply_line_changes(original, [{
        "start_line": 2,
        "expected": ["second"],
        "replacement": ["updated"],
    }])
    assert changed == "first\r\nupdated\r\n"


def test_apply_line_changes_rejects_stale_context():
    with pytest.raises(AIFixError, match="не совпал"):
        apply_line_changes("safe = True\n", [{
            "start_line": 1,
            "expected": ["safe = False"],
            "replacement": ["safe = True"],
        }])


def test_apply_line_changes_rejects_overlapping_hunks():
    source = "one\ntwo\nthree\n"
    with pytest.raises(AIFixError, match="пересекающиеся"):
        apply_line_changes(source, [
            {"start_line": 1, "expected": ["one", "two"], "replacement": ["first"]},
            {"start_line": 2, "expected": ["two", "three"], "replacement": ["second"]},
        ])


def test_apply_line_changes_rejects_noop():
    with pytest.raises(AIFixError, match="реального изменения"):
        apply_line_changes("same\n", [{
            "start_line": 1,
            "expected": ["same"],
            "replacement": ["same"],
        }])


def test_generate_fix_proposal_sends_only_bounded_safe_finding(monkeypatch):
    from app.ai import fixes

    monkeypatch.setattr(fixes, "provider_configuration", lambda: {
        "configured": True, "endpoint_valid": True,
    })
    monkeypatch.setattr(fixes.settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(fixes.settings, "llm_model", "test-model")
    monkeypatch.setattr(fixes.settings, "llm_api_key", "test-key")

    captured = {}

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": json.dumps({
                "summary": "Use a secure default.",
                "changes": [{
                    "start_line": 1,
                    "expected": ["DEBUG = True"],
                    "replacement": ["DEBUG = False"],
                }],
                "tests": ["Run the unit tests."],
            })}}]}

    def fake_post(url, headers, json, timeout):
        captured["url"] = url
        captured["headers"] = headers
        captured["payload"] = json
        return FakeResponse()

    monkeypatch.setattr(fixes.httpx, "post", fake_post)
    result = generate_fix_proposal(
        {
            "fingerprint": "abc",
            "category": "SAST",
            "rule_id": "debug-enabled",
            "severity": "HIGH",
            "path": "settings.py",
            "line": 1,
            "masked_value": "must-not-be-sent",
        },
        "DEBUG = True\n",
        "settings.py",
    )

    assert result["proposed_content"] == "DEBUG = False\n"
    assert "masked_value" not in captured["payload"]["messages"][1]["content"]
    assert captured["headers"]["Authorization"] == "Bearer test-key"


def test_generate_fix_proposal_rejects_secret_category():
    with pytest.raises(AIFixError, match="только для находок SAST и SCA"):
        generate_fix_proposal({"category": "SECRET"}, "token = '[REDACTED]'\n", "app.py")
