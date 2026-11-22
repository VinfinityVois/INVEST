import json
import httpx

from app.ai import explanations
from app.config import settings


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "https://llm.example/v1/chat/completions")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("provider error", request=request, response=response)

    def json(self):
        return self.payload


def test_gateway_reports_empty_input_without_calling_provider(monkeypatch):
    def unexpected_post(*args, **kwargs):
        raise AssertionError("AI provider must not be called when there are no findings")

    monkeypatch.setattr(explanations.httpx, "post", unexpected_post)
    result = explanations.explain_findings([])

    assert result["status"] == "completed"
    assert result["findings"] == []
    assert result["explanations"] == []
    assert result["explained_count"] == 0
    assert result["provider_attempts"] == 0
    assert "не передали находок" in result["message"]


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
    monkeypatch.setattr(settings, "llm_max_tokens", 8192)
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["payload"] = kwargs["json"]
        captured["timeout"] = kwargs["timeout"]
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
    assert captured["timeout"].read == 180.0
    assert captured["payload"]["max_tokens"] == 8192
    prompt = captured["payload"]["messages"][1]["content"]
    assert "must-not-be-sent" not in prompt
    assert "masked_value" not in prompt
    assert result["status"] == "completed"
    assert len(result["explanations"]) == 1
    assert result["explanations"][0]["fingerprint"] == "abc"
    assert result["explained_count"] == 1
    assert result["coverage"] == 1.0
    assert result["explanations"][0]["source_evidence"] == [
        {"line": 12, "text": 'token = "[REDACTED]"', "is_finding": True}
    ]


def test_gateway_honors_llm_max_tokens_above_4096(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")
    monkeypatch.setattr(settings, "llm_max_tokens", 8192)
    captured = {}

    def fake_post(url, **kwargs):
        captured["max_tokens"] = kwargs["json"]["max_tokens"]
        return FakeResponse({"choices": [{"message": {"content": json.dumps({
            "explanations": [{
                "fingerprint": "abc", "root_cause": "Cause", "impact": "Impact",
                "recommendation": "Fix", "confidence": 0.8, "evidence_limits": ""
            }]
        })}}]})

    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    result = explanations.explain_findings([{"fingerprint": "abc"}])

    assert result["status"] == "completed"
    assert captured["max_tokens"] == 8192


def test_gateway_explicitly_enforces_requested_russian_language(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")
    captured = {}

    def fake_post(url, **kwargs):
        captured["system_prompt"] = kwargs["json"]["messages"][0]["content"]
        return FakeResponse({"choices": [{"message": {"content": json.dumps({
            "explanations": [{
                "fingerprint": "abc", "root_cause": "Причина", "impact": "Влияние",
                "recommendation": "Исправление", "confidence": 0.8, "evidence_limits": ""
            }]
        }, ensure_ascii=False)}}]})

    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    result = explanations.explain_findings([{"fingerprint": "abc"}], {"language": "ru"})

    assert result["status"] == "completed"
    assert "exclusively in Russian" in captured["system_prompt"]
    assert "Do not use Chinese" in captured["system_prompt"]


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

    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    result = explanations.explain_findings([{"fingerprint": "abc"}])

    assert result["status"] == "failed"
    assert "401" in result["message"]
    assert "very-secret-key" not in result["message"]
    assert result["analyzed_count"] == 1
    assert result["skipped_count"] == 0
    assert result["unexplained_count"] == 1


def test_provider_configuration_never_returns_api_key(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "very-secret-key")

    status = explanations.provider_configuration()

    assert status["configured"] is True
    assert status["endpoint_valid"] is True
    assert "very-secret-key" not in str(status)



def test_gateway_rejects_incomplete_model_explanation(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")

    def fake_post(url, **kwargs):
        return FakeResponse({"choices": [{"message": {"content": json.dumps({
            "explanations": [{
                "fingerprint": "abc",
                "root_cause": "Cause",
                "impact": "",
                "recommendation": "Fix",
                "confidence": 0.8,
            }]
        })}}]})

    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    result = explanations.explain_findings([{
        "fingerprint": "abc",
        "code_context": [{"line": 7, "text": "dangerousCall()", "is_finding": True}],
    }])

    assert result["status"] == "completed"
    assert result["explained_count"] == 0
    assert result["unexplained_count"] == 1
    assert result["coverage"] == 0.0
    assert result["explanations"] == []
    assert "0 из 1" in result["message"]


def test_gateway_does_not_accept_model_explanation_without_fingerprint(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")

    def fake_post(url, **kwargs):
        return FakeResponse({"choices": [{"message": {"content": json.dumps({
            "explanations": [{
                "root_cause": "Cause", "impact": "Impact",
                "recommendation": "Fix", "confidence": 0.8,
            }]
        })}}]})

    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    result = explanations.explain_findings([{"code_context": [{"line": 1, "text": "x"}]}])

    assert result["explained_count"] == 0
    assert result["explanations"] == []



def test_gateway_reports_max_findings_coverage_and_skipped_count(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")

    def fake_post(url, **kwargs):
        return FakeResponse({"choices": [{"message": {"content": json.dumps({
            "explanations": [{
                "fingerprint": "finding-0", "root_cause": "Cause",
                "impact": "Impact", "recommendation": "Fix", "confidence": 0.8,
            }]
        })}}]})

    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    findings = [{"fingerprint": f"finding-{index}"} for index in range(4)]
    result = explanations.explain_findings(findings, {"max_findings": 2})

    assert result["status"] == "completed"
    assert result["analyzed_count"] == 2
    assert result["skipped_count"] == 2
    assert result["explained_count"] == 1
    assert result["unexplained_count"] == 1
    assert result["coverage"] == 0.5


def test_gateway_configuration_required_reports_not_attempted(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", None)
    monkeypatch.setattr(settings, "llm_model", None)
    monkeypatch.setattr(settings, "llm_api_key", None)

    result = explanations.explain_findings([{"fingerprint": "one"}, {"fingerprint": "two"}])

    assert result["status"] == "configuration_required"
    assert result["analyzed_count"] == 0
    assert result["skipped_count"] == 2
    assert result["coverage"] == 0.0



def test_provider_status_redacts_credentials_and_query_from_base_url(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://user:embedded-secret@llm.example/v1?token=query-secret")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "separate-secret")

    status = explanations.provider_configuration()

    assert status["endpoint_valid"] is False
    assert status["base_url"] == "https://llm.example/v1"
    assert "embedded-secret" not in str(status)
    assert "query-secret" not in str(status)
    assert "separate-secret" not in str(status)


def test_gateway_rejects_credentials_embedded_in_base_url(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://user:secret@llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")

    result = explanations.explain_findings([{"fingerprint": "abc"}])

    assert result["status"] == "failed"
    assert "не должен содержать логин" in result["message"]
    assert "secret" not in result["message"]


def test_gateway_returns_safe_provider_request_diagnostics(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "never-expose-this")
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
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

    assert result["provider"] == "openai-compatible"
    assert result["provider_attempts"] == 2
    assert result["provider_http_status"] == 200
    assert result["provider_error_code"] is None
    assert result["provider_request_ms"] >= 0
    assert "never-expose-this" not in json.dumps(result)


def test_gateway_returns_machine_readable_provider_failure(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "never-expose-this")

    def fake_post(url, **kwargs):
        request = httpx.Request("POST", url)
        response = httpx.Response(429, request=request)
        raise httpx.HTTPStatusError("provider rate limit", request=request, response=response)

    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    result = explanations.explain_findings([{"fingerprint": "abc"}])

    assert result["provider_error_code"] == "PROVIDER_HTTP_429"
    assert result["provider_http_status"] == 429
    assert result["provider_attempts"] == 1
    assert "never-expose-this" not in json.dumps(result)


def test_gateway_allows_http_host_docker_internal_for_local_ollama(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "http://host.docker.internal:11434/v1")
    monkeypatch.setattr(settings, "llm_model", "qwen2.5:3b")
    monkeypatch.setattr(settings, "llm_api_key", "ollama")

    status = explanations.provider_configuration()

    assert status["configured"] is True
    assert status["endpoint_valid"] is True
    assert status["base_url"] == "http://host.docker.internal:11434/v1"


def test_gateway_still_rejects_plain_http_for_other_hosts(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "http://192.168.1.20:11434/v1")
    monkeypatch.setattr(settings, "llm_model", "qwen2.5:3b")
    monkeypatch.setattr(settings, "llm_api_key", "ollama")

    status = explanations.provider_configuration()

    assert status["endpoint_valid"] is False



def test_secret_finding_with_redaction_only_context_is_not_counted_as_explained(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")
    calls = []

    def fake_post(url, **kwargs):
        calls.append(kwargs)
        raise AssertionError("AI provider must not receive redaction-only evidence")

    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    result = explanations.explain_findings([{
        "fingerprint": "secret-1",
        "category": "SECRET",
        "rule_id": "generic_assignment",
        "code_context": [{
            "line": 10,
            "text": "[REDACTED: secret-bearing source context]",
            "is_finding": True,
        }],
    }])

    assert calls == []
    assert result["status"] == "completed"
    assert result["explained_count"] == 0
    assert result["analyzed_count"] == 0
    assert result["unexplained_count"] == 0
    assert result["insufficient_evidence_count"] == 1
    assert result["evidence_coverage"] == 0.0
    assert result["coverage"] == 0.0
    assert "безопасный исходный контекст" in result["message"]


def test_secret_finding_sends_only_dedicated_masked_ai_context(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")
    captured = {}

    def fake_post(url, **kwargs):
        captured["prompt"] = kwargs["json"]["messages"][1]["content"]
        return FakeResponse({"choices": [{"message": {"content": json.dumps({
            "explanations": [{
                "fingerprint": "secret-2",
                "root_cause": "Credential is hard-coded",
                "impact": "May be exposed through source control",
                "recommendation": "Load it from a secret manager",
                "confidence": 0.8,
                "evidence_limits": "Runtime validity is unknown",
            }]
        })}}]})

    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    result = explanations.explain_findings([{
        "fingerprint": "secret-2",
        "category": "SECRET",
        "rule_id": "generic_assignment",
        "code_context": [{
            "line": 10,
            "text": "[REDACTED: secret-bearing source context]",
            "is_finding": True,
        }],
        "ai_code_context": [{
            "line": 10,
            "text": 'api_key = "[REDACTED]"',
            "is_finding": True,
        }],
    }])

    prompt_data = json.loads(captured["prompt"])
    sent_context = prompt_data["findings"][0]["code_context"][0]["text"]
    assert sent_context == 'api_key = "[REDACTED]"'
    assert "[REDACTED: secret-bearing source context]" not in captured["prompt"]
    assert result["explained_count"] == 1
    assert result["insufficient_evidence_count"] == 0
    assert result["evidence_coverage"] == 1.0
    assert result["explanations"][0]["source_evidence"][0]["text"] == 'api_key = "[REDACTED]"'


def test_parser_accepts_json_with_markdown_fence_and_preamble():
    payload = {
        "choices": [{
            "message": {
                "content": 'Результат анализа:\n```json\n{"explanations": []}\n```'
            }
        }]
    }
    response = FakeResponse(payload)
    assert explanations._parse_response(response) == []


def test_parser_reports_non_chat_completions_response_shape():
    response = FakeResponse({"message": "Ollama native API response"})
    try:
        explanations._parse_response(response)
    except explanations.ExplanationGatewayError as exc:
        assert "choices[]" in str(exc)
        assert "message" in str(exc)
    else:
        raise AssertionError("Unexpected response shape must be rejected clearly")


def test_parser_accepts_content_as_structured_text_parts():
    response = FakeResponse({
        "choices": [{
            "message": {
                "content": [{"type": "text", "text": '{"explanations": []}'}]
            }
        }]
    })
    assert explanations._parse_response(response) == []


def test_parser_accepts_issues_alias_for_explanations_array():
    response = FakeResponse({
        "choices": [{
            "finish_reason": "stop",
            "message": {"content": json.dumps({"issues": [{"fingerprint": "abc"}]})},
        }],
    })
    assert explanations._parse_response(response) == [{"fingerprint": "abc"}]


def test_parser_logs_safe_metadata_when_explanations_array_is_missing(caplog):
    response = FakeResponse({
        "choices": [{
            "finish_reason": "stop",
            "message": {"content": json.dumps({"result": [], "status": "ok"})},
        }],
        "usage": {"completion_tokens": 321, "prompt_tokens": 654},
    })

    with __import__("pytest").raises(explanations.ExplanationGatewayError):
        explanations._parse_response(response)

    diagnostic = caplog.text
    assert "phase=explanations_array" in diagnostic
    assert "json_keys=result, status" in diagnostic
    assert "finish_reason=stop" in diagnostic
    assert "completion_tokens=321" in diagnostic
    assert "prompt_tokens=654" in diagnostic
    assert '"result"' not in diagnostic


def test_parser_logs_safe_metadata_for_invalid_model_json(caplog):
    response = FakeResponse({
        "choices": [{
            "finish_reason": "length",
            "message": {"content": '{"explanations":[{"fingerprint":"secret-fingerprint"'}
        }],
        "usage": {"completion_tokens": 1400},
    })

    with __import__("pytest").raises(json.JSONDecodeError):
        explanations._parse_response(response)

    diagnostic = caplog.text
    assert "phase=model_content_json" in diagnostic
    assert "finish_reason=length" in diagnostic
    assert "completion_tokens=1400" in diagnostic
    assert "secret-fingerprint" not in diagnostic


def test_parser_logs_safe_metadata_for_invalid_http_json(caplog):
    class InvalidJsonResponse(FakeResponse):
        content = b'{"private":"do-not-log"}'

        def json(self):
            raise json.JSONDecodeError("invalid", self.content.decode(), 0)

    with __import__("pytest").raises(json.JSONDecodeError):
        explanations._parse_response(InvalidJsonResponse({}))

    diagnostic = caplog.text
    assert "phase=http_body_json" in diagnostic
    assert "body_bytes=" in diagnostic
    assert "do-not-log" not in diagnostic




def test_gateway_logs_safe_counts_for_rejected_model_explanations(monkeypatch, caplog):
    caplog.set_level("INFO", logger="secworkflow.ai")
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")
    payload = {
        "explanations": [
            "not-an-object",
            {},
            {"fingerprint": "invented-secret-fingerprint", "root_cause": "private text"},
            {
                "fingerprint": "finding-a",
                "root_cause": "Cause",
                "impact": "Impact",
                "recommendation": "Fix",
            },
            {
                "fingerprint": "finding-a",
                "root_cause": "Duplicate",
                "impact": "Duplicate",
                "recommendation": "Duplicate",
            },
            {
                "fingerprint": "finding-b",
                "root_cause": "",
                "impact": None,
                "recommendation": "",
            },
        ]
    }

    monkeypatch.setattr(
        explanations.httpx,
        "post",
        lambda *args, **kwargs: FakeResponse({
            "choices": [{"message": {"content": json.dumps(payload)}}]
        }),
    )

    result = explanations.explain_findings([
        {"fingerprint": "finding-a"},
        {"fingerprint": "finding-b"},
    ])

    assert result["explained_count"] == 1
    assert result["unexplained_count"] == 1
    diagnostic = caplog.text
    assert "AI explanation normalization: raw_items=6 accepted=1" in diagnostic
    assert "rejected_non_object=1" in diagnostic
    assert "rejected_missing_fingerprint=1" in diagnostic
    assert "rejected_unknown_fingerprint=1" in diagnostic
    assert "rejected_duplicate_fingerprint=1" in diagnostic
    assert "rejected_missing_root_cause=1" in diagnostic
    assert "rejected_missing_impact=1" in diagnostic
    assert "rejected_missing_recommendation=1" in diagnostic
    assert "invented-secret-fingerprint" not in diagnostic
    assert "private text" not in diagnostic



def test_gateway_uses_scanner_why_it_matters_when_model_omits_impact(monkeypatch, caplog):
    caplog.set_level("INFO", logger="secworkflow.ai")
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")

    def fake_post(url, **kwargs):
        return FakeResponse({"choices": [{"message": {"content": json.dumps({
            "explanations": [{
                "fingerprint": "finding-impact",
                "root_cause": "Cause",
                "recommendation": "Fix",
                "confidence": 0.8,
            }]
        })}}]})

    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    result = explanations.explain_findings([{
        "fingerprint": "finding-impact",
        "why_it_matters": "An attacker could access protected account data.",
    }])

    assert result["explained_count"] == 1
    assert result["explanations"][0]["impact"] == (
        "An attacker could access protected account data."
    )
    assert "impact_fallback_from_scanner=1" in caplog.text


def test_gateway_does_not_fabricate_impact_when_scanner_has_no_context(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")
    monkeypatch.setattr(settings, "llm_api_key", "test-api-key")

    def fake_post(url, **kwargs):
        return FakeResponse({"choices": [{"message": {"content": json.dumps({
            "explanations": [{
                "fingerprint": "finding-impact",
                "root_cause": "Cause",
                "recommendation": "Fix",
                "confidence": 0.8,
            }]
        })}}]})

    monkeypatch.setattr(explanations.httpx, "post", fake_post)
    result = explanations.explain_findings([{"fingerprint": "finding-impact"}])

    assert result["explained_count"] == 0
    assert result["unexplained_count"] == 1
    assert result["explanations"] == []
