from app.main import _summarize_report_findings


def test_report_summary_counts_every_finding_and_ai_coverage():
    findings = [
        {"severity": "CRITICAL", "category": "SAST", "ai_explanation": {"root_cause": "unsafe input"}},
        {"severity": "HIGH", "category": "SCA"},
        {"severity": "HIGH", "analyzer": "SAST", "ai_explanation": {"root_cause": "missing check"}},
        {"severity": "LOW"},
    ]

    summary = _summarize_report_findings(findings)

    assert summary == {
        "total_findings": 4,
        "by_severity": {"CRITICAL": 1, "HIGH": 2, "LOW": 1},
        "by_category": {"SAST": 2, "SCA": 1, "UNCATEGORIZED": 1},
        "ai_explained": 2,
        "without_ai_explanation": 2,
    }
