#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Run capmaster match on all TC-* subdirectories under a root directory (e.g. /Users/ricky/Downloads/2hops)
and summarize results into Markdown and JSON.

- Uses AUTO bucket by default (now NAT-aware), can be overridden via --bucket
- Parses the Statistics block
- Counts strong IPID matches (evidence contains 'ipid*') and normal ipid matches (' ipid')

Outputs:
- analysis/2hops_match_summary.md
- analysis/2hops_match_summary.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Any
import sys

STAT_RE = re.compile(r"^\s*(Total connections \(file 1\):|Total connections \(file 2\):|Matched pairs:|Unmatched \(file 1\):|Unmatched \(file 2\):|Match rate \(file 1\):|Match rate \(file 2\):|Average score:)\s*(.*)")
EVIDENCE_RE = re.compile(r"证据\s*:\s*(.*)")

@dataclass
class CaseResult:
    case: str
    total1: int = 0
    total2: int = 0
    matched_pairs: int = 0
    unmatched1: int = 0
    unmatched2: int = 0
    match_rate1: float = 0.0
    match_rate2: float = 0.0
    average_score: float = 0.0
    strong_ipid_matches: int = 0
    normal_ipid_matches: int = 0


def run_match(case_dir: Path, bucket: str) -> str:
    # Use the current Python interpreter to run the module to avoid relying on a global 'capmaster' entry point
    cmd = [
        sys.executable, "-m", "capmaster", "match",
        "--bucket", bucket,
        "-i", str(case_dir),
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return proc.stdout


def parse_output(case: str, output: str) -> CaseResult:
    res = CaseResult(case=case)
    in_stats = False
    for line in output.splitlines():
        if line.strip() == "Statistics:":
            in_stats = True
            continue
        if in_stats:
            if not line.strip():
                in_stats = False
                continue
            m = STAT_RE.match(line)
            if m:
                key, val = m.group(1), m.group(2).strip()
                if key.startswith("Total connections (file 1)"):
                    res.total1 = int(val)
                elif key.startswith("Total connections (file 2)"):
                    res.total2 = int(val)
                elif key.startswith("Matched pairs"):
                    res.matched_pairs = int(val)
                elif key.startswith("Unmatched (file 1)"):
                    res.unmatched1 = int(val)
                elif key.startswith("Unmatched (file 2)"):
                    res.unmatched2 = int(val)
                elif key.startswith("Match rate (file 1)"):
                    res.match_rate1 = float(val.rstrip('%')) / 100.0 if val.endswith('%') else float(val)
                elif key.startswith("Match rate (file 2)"):
                    res.match_rate2 = float(val.rstrip('%')) / 100.0 if val.endswith('%') else float(val)
                elif key.startswith("Average score"):
                    try:
                        res.average_score = float(val)
                    except ValueError:
                        res.average_score = 0.0
        # Count evidence lines for ipid/ipid*
        m2 = EVIDENCE_RE.search(line)
        if m2:
            ev = m2.group(1)
            if 'ipid*' in ev:
                res.strong_ipid_matches += 1
            elif 'ipid' in ev:
                res.normal_ipid_matches += 1
    return res


def format_markdown(results: List[CaseResult]) -> str:
    total_cases = len(results)
    sum_total1 = sum(r.total1 for r in results)
    sum_total2 = sum(r.total2 for r in results)
    sum_matched = sum(r.matched_pairs for r in results)
    avg_score = sum((r.average_score if r.matched_pairs > 0 else 0.0) for r in results)
    # average of case-average scores across cases that had matches
    avg_score_cases = (
        avg_score / max(1, sum(1 for r in results if r.matched_pairs > 0))
    )
    strong_sum = sum(r.strong_ipid_matches for r in results)
    normal_sum = sum(r.normal_ipid_matches for r in results)

    lines = []
    lines.append(f"# 2hops Match 汇总结果\n")
    lines.append(f"- 用例总数: {total_cases}")
    lines.append(f"- 总连接数: file1={sum_total1}, file2={sum_total2}")
    lines.append(f"- 总匹配对数: {sum_matched}")
    lines.append(f"- 平均置信度(跨有匹配的用例): {avg_score_cases:.2f}")
    lines.append(f"- 强 IPID 匹配总数: {strong_sum}")
    lines.append(f"- 普通 IPID 匹配总数: {normal_sum}")
    lines.append("")

    # Table header
    lines.append("| 用例 | f1连接 | f2连接 | 匹配对 | 强IPID | 普通IPID | 平均分 |")
    lines.append("|------|--------|--------|--------|--------|----------|--------|")
    for r in results:
        lines.append(
            f"| {r.case} | {r.total1} | {r.total2} | {r.matched_pairs} | "
            f"{r.strong_ipid_matches} | {r.normal_ipid_matches} | {r.average_score:.2f} |"
        )
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Run capmaster match across 2hops cases and summarize")
    parser.add_argument("root", nargs="?", default="/Users/ricky/Downloads/2hops", help="Root dir containing TC-* subdirs")
    parser.add_argument("--bucket", default="auto", choices=["auto", "server", "port", "none"], help="Bucketing strategy")
    args = parser.parse_args()

    root = Path(args.root)
    if not root.is_dir():
        raise SystemExit(f"Root not found: {root}")

    def has_exactly_two_pcaps(d: Path) -> bool:
        try:
            files = [f for f in d.iterdir() if f.is_file() and f.suffix.lower() in (".pcap", ".pcapng")]
            return len(files) == 2
        except Exception:
            return False

    # Recursively find all subdirectories that contain exactly two pcap/pcapng files
    # Prefer TC-* directories but fall back to any dir with exactly two pcaps
    candidate_dirs = set()
    for d in root.rglob("*"):
        if d.is_dir() and has_exactly_two_pcaps(d):
            candidate_dirs.add(d)

    # Sort by path for stable output
    cases = sorted(candidate_dirs)
    results: List[CaseResult] = []

    for case_dir in cases:
        try:
            out = run_match(case_dir, args.bucket)
            res = parse_output(case_dir.name, out)
            results.append(res)
        except Exception:
            # Record an empty result with error indicator
            results.append(CaseResult(case=case_dir.name))

    # Ensure analysis dir exists
    analysis_dir = Path("analysis")
    analysis_dir.mkdir(parents=True, exist_ok=True)

    # Write Markdown
    md = format_markdown(results)
    (analysis_dir / "2hops_match_summary.md").write_text(md, encoding="utf-8")

    # Write JSON
    obj: Dict[str, Any] = {
        "root": str(root),
        "bucket": args.bucket,
        "cases": [asdict(r) for r in results],
    }
    (analysis_dir / "2hops_match_summary.json").write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")

    # Also print summary to stdout
    print(md)


if __name__ == "__main__":
    main()

