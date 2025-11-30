#!/usr/bin/env python3
"""
Compare two benchmark result files and highlight regressions/improvements.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


Metric = tuple[str, float]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare benchmark result JSON files.")
    parser.add_argument("--baseline", required=True, type=Path, help="Baseline JSON path")
    parser.add_argument("--current", required=True, type=Path, help="Current JSON path")
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write comparison JSON (default: stdout only)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.05,
        help="Relative change threshold for highlighting regressions (default: 5%%).",
    )
    return parser.parse_args()


def load_results(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    cases: dict[str, dict[str, Any]] = {}
    for entry in payload.get("results", []):
        key = f"{entry['suite']}::{entry['case_id']}"
        cases[key] = entry
    return cases


def extract_metric(entry: dict[str, Any], metric: str) -> float | None:
    aggregates = entry.get("aggregates", {})
    value = aggregates.get(metric, {}).get("avg")
    if value is None:
        return None
    return float(value)


def compare_metrics(
    baseline_cases: dict[str, dict[str, Any]],
    current_cases: dict[str, dict[str, Any]],
    threshold: float,
) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    metrics = ["wall_time_sec", "user_time_sec", "system_time_sec", "max_rss_kb"]
    for case_id, cur_entry in current_cases.items():
        base_entry = baseline_cases.get(case_id)
        if not base_entry:
            summary.append(
                {
                    "case": case_id,
                    "status": "new",
                    "details": "No baseline data",
                }
            )
            continue

        case_result = {"case": case_id, "status": "ok", "metrics": []}
        for metric_name in metrics:
            cur_val = extract_metric(cur_entry, metric_name)
            base_val = extract_metric(base_entry, metric_name)
            if cur_val is None or base_val is None or base_val == 0:
                continue
            delta = cur_val - base_val
            rel = delta / base_val
            metric_record = {
                "metric": metric_name,
                "baseline": base_val,
                "current": cur_val,
                "delta": delta,
                "relative": rel,
            }
            if rel > threshold:
                metric_record["flag"] = "regression"
                case_result["status"] = "regression"
            elif rel < -threshold:
                metric_record["flag"] = "improvement"
            case_result["metrics"].append(metric_record)
        summary.append(case_result)
    return summary


def main() -> None:
    args = parse_args()
    baseline_cases = load_results(args.baseline)
    current_cases = load_results(args.current)
    comparison = compare_metrics(baseline_cases, current_cases, args.threshold)

    printable_lines = ["Benchmark comparison:"]
    for item in comparison:
        printable_lines.append(f"- {item['case']}: {item['status']}")
        for metric in item.get("metrics", []):
            rel_pct = metric["relative"] * 100
            flag = metric.get("flag", "")
            printable_lines.append(
                f"    * {metric['metric']}: baseline={metric['baseline']:.3f}, "
                f"current={metric['current']:.3f}, delta={metric['delta']:.3f} "
                f"({rel_pct:+.2f}%) {flag}"
            )

    output_text = "\n".join(printable_lines)
    print(output_text)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as f:
            json.dump({"comparison": comparison}, f, indent=2)


if __name__ == "__main__":
    main()

