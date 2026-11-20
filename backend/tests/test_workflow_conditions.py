from types import SimpleNamespace

from app.workflows.engine import _active_parent_ids, _evaluate_condition


def test_condition_compares_total_findings():
    parents = [{"findings": [{"severity": "HIGH"}, {"severity": "LOW"}]}]
    assert _evaluate_condition({"field": "finding_count", "operator": "gte", "value": 2}, parents) == (True, None)


def test_condition_compares_severity_counts():
    parents = [{"findings": [{"severity": "CRITICAL"}, {"severity": "HIGH"}]}]
    assert _evaluate_condition({"field": "critical_count", "operator": "eq", "value": 1}, parents) == (True, None)


def test_condition_supports_regex_over_nested_finding_fields():
    parents = [{"findings": [{"rule_id": "KOTLIN-SQL-INJECTION"}]}]
    assert _evaluate_condition(
        {"field": "findings.0.rule_id", "operator": "regex", "value": r"SQL.*INJECTION"},
        parents,
    ) == (True, None)


def test_condition_supports_contains():
    parents = [{"findings": [{"severity": "HIGH"}]}]
    assert _evaluate_condition(
        {"field": "severity_counts", "operator": "contains", "value": "HIGH"},
        parents,
    ) == (True, None)


def test_condition_rejects_invalid_regex():
    parents = [{"findings": [{"rule_id": "RULE"}]}]
    matched, error = _evaluate_condition(
        {"field": "findings.0.rule_id", "operator": "regex", "value": "["},
        parents,
    )
    assert matched is False
    assert "регулярное выражение" in error


def test_condition_rejects_non_numeric_comparison():
    matched, error = _evaluate_condition(
        {"field": "finding_count", "operator": "gt", "value": "many"},
        [{"findings": []}],
    )
    assert matched is False
    assert "числовые" in error


def test_condition_supports_exists():
    parents = [{"findings": [{"rule_id": "RULE"}]}]
    assert _evaluate_condition({"field": "critical_count", "operator": "exists"}, parents) == (True, None)


def test_condition_rejects_unknown_operator():
    matched, error = _evaluate_condition(
        {"field": "finding_count", "operator": "approx", "value": 1},
        [{"findings": []}],
    )
    assert matched is False
    assert "оператор" in error


def test_branch_routing_activates_only_selected_output_handle():
    edges = [
        SimpleNamespace(source="condition", source_handle="true"),
        SimpleNamespace(source="condition", source_handle="false"),
    ]
    outputs = {"condition": {"status": "completed", "branch": "true"}}
    assert _active_parent_ids(edges, outputs) == ["condition"]


def test_branch_routing_ignores_skipped_upstream_nodes():
    edges = [SimpleNamespace(source="inactive", source_handle=None)]
    outputs = {"inactive": {"status": "skipped"}}
    assert _active_parent_ids(edges, outputs) == []


def test_branch_routing_keeps_unconditional_parent():
    edges = [SimpleNamespace(source="merge", source_handle=None)]
    outputs = {"merge": {"status": "completed", "findings": []}}
    assert _active_parent_ids(edges, outputs) == ["merge"]
