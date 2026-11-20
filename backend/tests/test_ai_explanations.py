import json

from app.ai import explanations
from app.config import settings


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_gateway_requires_provider_configuration(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", None)
    monkeypatch.setattr(settings, "llm_model", None)
    monkeypatch.setattr(settings, "llm_api_key", None)

    result = explanations.explain_findings([{"fingerprint": "abc"}])

    assert result["status"] == "configuration_required"
    assert result["explanations"] == []


def test_gateway_sends_only_redacted_finding_fields(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["payload"] = kwargs["json"]
        return FakeResponse({
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "explanations": [{
                            "fingerprint": "abc",
                            "root_cause": "Unsafe route",
                            "impact": "Unauthenticated access",
                            "recommendation": "Require authorization",
                            "confidence": 0.91,
                            "evidence_limits": "No runtime test",
                        }, {
                            "fingerprint": "invented",
                            "root_cause": "Hallucinated",
                        }]
                    })
                }
            }]
        })

    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    result = explanations.explain_findings([{
        "fingerprint": "abc",
        "rule_id": "test.rule",
        "severity": "HIGH",
        "path": "Security.kt",
        "line": 12,
        "masked_value": "[REDACTED]",
        "value_hash": "must-not-be-sent",
        "code_context": [{"line": 12, "text": 'token = "[REDACTED]"', "is_finding": True}],
    }])

    assert captured["url"] == "https://llm.example/v1/chat/completions"
    prompt = captured["payload"]["messages"][1]["content"]
    assert "must-not-be-sent" not in prompt
    assert "masked_value" not in prompt
    assert result["status"] == "completed"
    assert len(result["explanations"]) == 1
    assert result["explanations"][0]["fingerprint"] == "abc"


def test_gateway_rejects_non_https_remote_endpoint(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "http://remote.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")

    result = explanations.explain_findings([{"fingerprint": "abc"}])

    assert result["status"] == "failed"
    assert result["explanations"] == []



def test_gateway_retries_without_response_format(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")
    calls = []

    def fake_post(url, **kwargs):
        calls.append(kwargs["json"])
        if len(calls) == 1:
            return FakeResponse({"error": "response_format unsupported"}, status_code=400)
        return FakeResponse({"choices": [{"message": {"content": json.dumps({
            "explanations": [{
                "fingerprint": "abc", "root_cause": "Cause", "impact": "Impact",
                "recommendation": "Fix", "confidence": 0.8, "evidence_limits": ""
            }]
        })}}]})

    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    result = explanations.explain_findings([{"fingerprint": "abc"}])

    assert len(calls) == 2
    assert "response_format" in calls[0]
    assert "response_format" not in calls[1]
    assert result["status"] == "completed"


def test_gateway_reports_authentication_failure_without_leaking_key(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "very-secret-key")

    def fake_post(url, **kwargs):
        request = httpx.Request("POST", url)
        response = httpx.Response(401, request=request)
        raise httpx.HTTPStatusError("unauthorized", request=request, response=response)

    import httpx
    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    result = explanations.explain_findings([{"fingerprint": "abc"}])

    assert result["status"] == "failed"
    assert "401" in result["message"]
    assert "very-secret-key" not in result["message"]


def test_provider_configuration_never_returns_api_key(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "very-secret-key")

    status = explanations.provider_configuration()

    assert status["configured"] is True
    assert status["endpoint_valid"] is True
    assert "very-secret-key" not in str(status)
