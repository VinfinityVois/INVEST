#!/usr/bin/env python3
"""Evaluate INVEST's custom secrets detector against the public training ground truth."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "eval"))
from app.scanners.secrets import scan_directory
from benchmark_utils import evaluate_category


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    report = evaluate_category(truth, scan_directory(args.repo_root), "SECRET")
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\\n", encoding="utf-8")
    return 1 if report["missed"] or report["false_positives"] or report["controls_triggered"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
