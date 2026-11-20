#!/usr/bin/env python3
"""Evaluate Kotlin/Spring SAST rules against the pinned training ground truth."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.scanners.sast import scan_kotlin_project


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    expected = [x for x in truth["findings"] if x["category"] == "SAST"]
    controls = [x for x in truth.get("controls", []) if x["category"] == "SAST"]
    actual = scan_kotlin_project(args.repo_root)

    def matches(item, target):
        return item["path"] == target["path"] and target["line"] <= item["line"] <= target.get("endLine", target["line"])

    matched, missed = [], []
    for target in expected:
        hit = next((x for x in actual if matches(x, target)), None)
        (matched if hit else missed).append({"id": target["id"], "finding": hit})
    control_hits = [{"id": c["id"], "matches": [x for x in actual if matches(x, c)]} for c in controls]
    control_hits = [x for x in control_hits if x["matches"]]
    tp = len(matched)
    fp = len(actual) - tp
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / len(expected) if expected else 1.0
    report = {
        "dataset": truth.get("dataset", "unknown"), "category": "SAST",
        "expected": len(expected), "detected": tp, "missed": missed,
        "false_positives": fp, "controls_triggered": control_hits,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "findings": actual,
    }
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 1 if missed or control_hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
