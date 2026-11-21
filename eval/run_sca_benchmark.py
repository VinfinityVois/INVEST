#!/usr/bin/env python3
"""Evaluate the Gradle SCA detector against the public training ground truth."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.scanners.sca import scan_gradle_project


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True, help="Path to training-project")
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    expected = [item for item in truth["findings"] if item["category"] == "SCA"]
    controls = [item for item in truth.get("controls", []) if item["category"] == "SCA"]
    actual = scan_gradle_project(args.repo_root)

    def matches(item, target):
        return (
            item["path"] == target["path"]
            and target["line"] <= item["line"] <= target.get("endLine", target["line"])
            and (not target.get("group") or item.get("group") == target["group"])
            and (not target.get("artifact") or item.get("artifact") == target["artifact"])
        )

    matched, missed = [], []
    for target in expected:
        hit = next((item for item in actual if matches(item, target)), None)
        (matched if hit else missed).append({"id": target["id"], "finding": hit})

    control_hits = [
        {"id": control["id"], "matches": [item for item in actual if matches(item, control)]}
        for control in controls
    ]
    control_hits = [item for item in control_hits if item["matches"]]
    true_positive = len(matched)
    false_positive = len(actual) - true_positive
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 1.0
    recall = true_positive / len(expected) if expected else 1.0
    report = {
        "dataset": truth.get("dataset", "unknown"),
        "category": "SCA",
        "expected": len(expected),
        "detected": true_positive,
        "missed": missed,
        "false_positives": false_positive,
        "controls_triggered": control_hits,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "findings": actual,
    }
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 1 if missed or false_positive > 0 or control_hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
