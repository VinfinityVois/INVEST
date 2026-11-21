from types import SimpleNamespace
from uuid import uuid4

from app import main


def test_list_run_findings_attaches_ai_explanations_by_fingerprint(monkeypatch):
    run_id = uuid4()
    first_id = uuid4()
    first = SimpleNamespace(
        id=first_id,
        fingerprint="finding-one",
        rule_id="generic_assignment",
        severity="MEDIUM",
        path="settings.js",
        line=12,
        payload={"category": "SECRET", "code_context": [
            {"line": 12, "text": "[REDACTED: secret-bearing source context]", "is_finding": True}
        ]},
    )
    second = SimpleNamespace(
        id=uuid4(),
        fingerprint="finding-two",
        rule_id="unsafe-call",
        severity="HIGH",
        path="app.py",
        line=40,
        payload={"category": "SAST"},
    )
    explanation = {
        "fingerprint": "finding-one",
        "root_cause": "Credential is hard-coded",
        "impact": "May be exposed through source control",
        "recommendation": "Load it from a secret manager",
        "confidence": 0.8,
        "evidence_limits": "Runtime validity is unknown",
        "source_evidence": [
            {"line": 12, "text": 'api_key = "[REDACTED]"', "is_finding": True}
        ],
    }
    run = SimpleNamespace(result={
        "outputs": {"ai-explain": {"status": "completed", "explanations": [explanation]}}
    })

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def scalars(self, _statement):
            return SimpleNamespace(all=lambda: [first, second])

    monkeypatch.setattr(main, "SessionLocal", FakeSession)
    monkeypatch.setattr(main, "_run_in_active_workspace", lambda *_args: run)

    result = main.list_run_findings(run_id, SimpleNamespace())

    assert result[0]["ai_explanation"] == explanation
    assert result[0]["code_context"][0]["text"] == "[REDACTED: secret-bearing source context]"
    assert "ai_explanation" not in result[1]
