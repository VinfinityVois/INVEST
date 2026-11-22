"""Shared ground-truth matching for scanner evaluation."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any


def _location_candidates(target: dict[str, Any]) -> list[dict[str, Any]]:
    """Return primary and alternate source locations with target metadata retained."""
    candidates = [{**target, "path": target.get("path")}]
    for alternate in target.get("alternateLocations", []) or []:
        candidates.append({**target, **alternate})
    return candidates


def _matches_location(finding: dict[str, Any], target: dict[str, Any]) -> bool:
    finding_path = str(finding.get("path", "")).replace("\\\\", "/").lstrip("./")
    target_path = str(target.get("path", "")).replace("\\\\", "/").lstrip("./")
    try:
        line = int(finding.get("line", 0))
        start = int(target["line"])
        end = int(target.get("endLine", start))
    except (KeyError, TypeError, ValueError):
        return False
    return finding_path == target_path and start <= line <= end


def evaluate_category(
    truth: dict[str, Any],
    actual: list[dict[str, Any]],
    category: str,
    extra_match: Callable[[dict[str, Any], dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    """Match detections one-to-one against primary/alternate ground-truth locations.

    Maximum bipartite matching prevents one broad finding from satisfying multiple
    expected findings. Alternate locations inherit category-specific metadata.
    """
    expected = [item for item in truth.get("findings", []) if item.get("category") == category]
    controls = [item for item in truth.get("controls", []) if item.get("category") == category]

    def matches(finding: dict[str, Any], target: dict[str, Any]) -> bool:
        if not _matches_location(finding, target):
            return False
        return extra_match(finding, target) if extra_match else True

    edges: list[list[int]] = []
    for target in expected:
        candidates = _location_candidates(target)
        edges.append([
            index for index, finding in enumerate(actual)
            if any(matches(finding, location) for location in candidates)
        ])

    # Kuhn augmenting paths: maximize TP even where target location ranges overlap.
    actual_to_expected: dict[int, int] = {}

    def assign(expected_index: int, seen: set[int]) -> bool:
        for actual_index in edges[expected_index]:
            if actual_index in seen:
                continue
            seen.add(actual_index)
            previous = actual_to_expected.get(actual_index)
            if previous is None or assign(previous, seen):
                actual_to_expected[actual_index] = expected_index
                return True
        return False

    expected_to_actual: dict[int, int] = {}
    for expected_index in range(len(expected)):
        assign(expected_index, set())
    for actual_index, expected_index in actual_to_expected.items():
        expected_to_actual[expected_index] = actual_index

    matched = [
        {"id": target.get("id"), "finding": actual[expected_to_actual[index]]}
        for index, target in enumerate(expected) if index in expected_to_actual
    ]
    missed = [
        {"id": target.get("id"), "finding": None}
        for index, target in enumerate(expected) if index not in expected_to_actual
    ]
    matched_actual = set(actual_to_expected)
    false_positive_findings = [
        finding for index, finding in enumerate(actual) if index not in matched_actual
    ]

    control_hits = []
    for control in controls:
        locations = _location_candidates(control)
        hits = [
            finding for finding in actual
            if any(matches(finding, location) for location in locations)
        ]
        if hits:
            control_hits.append({"id": control.get("id"), "matches": hits})

    tp = len(matched)
    fp = len(false_positive_findings)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / len(expected) if expected else 1.0
    return {
        "dataset": truth.get("dataset", "unknown"),
        "category": category,
        "expected": len(expected),
        "detected": tp,
        "missed": missed,
        "false_positives": fp,
        "false_positive_findings": false_positive_findings,
        "controls_triggered": control_hits,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "findings": actual,
    }
