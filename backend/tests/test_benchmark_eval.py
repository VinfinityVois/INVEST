from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "eval"))
from benchmark_utils import evaluate_category


def test_alternate_location_counts_as_true_positive():
    truth = {"dataset": "fixture", "findings": [{
        "id": "F-1", "category": "SAST", "path": "src/Main.kt", "line": 10,
        "alternateLocations": [{"path": "src/Controller.kt", "line": 22, "endLine": 23}],
    }]}
    report = evaluate_category(truth, [{"path": "src/Controller.kt", "line": 23}], "SAST")
    assert report["detected"] == 1
    assert report["missed"] == []
    assert report["false_positives"] == 0


def test_primary_and_alternate_location_preserve_sca_coordinate_constraints():
    truth = {"findings": [{
        "id": "SCA-1", "category": "SCA", "path": "build.gradle.kts", "line": 10,
        "group": "org.example", "artifact": "unsafe-lib",
        "alternateLocations": [{"path": "gradle.properties", "line": 2}],
    }]}
    report = evaluate_category(
        truth,
        [{"path": "gradle.properties", "line": 2, "group": "org.example", "artifact": "other-lib"}],
        "SCA",
        lambda finding, target: (
            (not target.get("group") or finding.get("group") == target["group"])
            and (not target.get("artifact") or finding.get("artifact") == target["artifact"])
        ),
    )
    assert report["detected"] == 0
    assert report["missed"][0]["id"] == "SCA-1"


def test_one_actual_finding_cannot_satisfy_two_expected_findings():
    truth = {"findings": [
        {"id": "F-1", "category": "SECRET", "path": "config.yml", "line": 5},
        {"id": "F-2", "category": "SECRET", "path": "config.yml", "line": 5},
    ]}
    report = evaluate_category(truth, [{"path": "config.yml", "line": 5}], "SECRET")
    assert report["detected"] == 1
    assert len(report["missed"]) == 1
    assert report["false_positives"] == 0


def test_distinct_actual_findings_are_matched_one_to_one():
    truth = {"findings": [
        {"id": "F-1", "category": "SECRET", "path": "config.yml", "line": 5},
        {"id": "F-2", "category": "SECRET", "path": "config.yml", "line": 5},
    ]}
    actual = [{"path": "config.yml", "line": 5}, {"path": "config.yml", "line": 5}]
    report = evaluate_category(truth, actual, "SECRET")
    assert report["detected"] == 2
    assert report["false_positives"] == 0


def test_alternate_location_is_used_for_negative_controls_too():
    truth = {"findings": [], "controls": [{
        "id": "CTRL-1", "category": "SAST", "path": "safe.kt", "line": 1,
        "alternateLocations": [{"path": "controller.kt", "line": 9}],
    }]}
    report = evaluate_category(truth, [{"path": "controller.kt", "line": 9}], "SAST")
    assert report["controls_triggered"][0]["id"] == "CTRL-1"
