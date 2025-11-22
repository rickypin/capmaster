#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Run capmaster match on all TC-* subdirectories under a root directory (e.g. /Users/ricky/Downloads/2hops)
and summarize results into Markdown and JSON.

- Uses AUTO bucket by default (now NAT-aware), can be overridden via --bucket
- Parses the Statistics block from CLI output
- Uses match JSON to count strong/normal IPID matches, and F5 / TLS based matches

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
    f5_matches: int = 0
    tls_matches: int = 0
    evidence_types: List[str] | None = None


def run_match(case_dir: Path, bucket: str, match_json: Path | None = None) -> str:
    """Run `capmaster match` for a single case and optionally emit match JSON.

    Using the current Python interpreter avoids relying on a global `capmaster` entry point.
    """
    cmd = [
        sys.executable,
        "-m",
        "capmaster",
        "match",
        "--bucket",
        bucket,
        "-i",
        str(case_dir),
    ]
    if match_json is not None:
        cmd.extend(["--match-json", str(match_json)])
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.stdout


def parse_output(case: str, output: str) -> CaseResult:
    """Parse the CLI output `Statistics` block into a CaseResult.

    Evidence-related statistics (IPID/F5/TLS) are populated separately from match JSON.
    """
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
                    res.match_rate1 = float(val.rstrip("%")) / 100.0 if val.endswith("%") else float(val)
                elif key.startswith("Match rate (file 2)"):
                    res.match_rate2 = float(val.rstrip("%")) / 100.0 if val.endswith("%") else float(val)
                elif key.startswith("Average score"):
                    try:
                        res.average_score = float(val)
                    except ValueError:
                        res.average_score = 0.0
    return res


def _normalize_evidence_token(token: str) -> str:
    """Normalize a single evidence token to its *kind*.

    Examples:
      - "ipid(n=...,r=...)" -> "ipid"
      - "ipid*(n=...,r=...)" -> "ipid*"
      - "F5_TRAILER(0.99)" -> "F5_TRAILER"
      - "TLS_CLIENT_HELLO(1.00)" -> "TLS_CLIENT_HELLO"
    """
    token = token.strip()
    if not token:
        return ""
    # Strip any trailing comma
    if token.endswith(","):
        token = token[:-1]
    # Split at first "(" to drop parameters
    if "(" in token:
        token = token.split("(", 1)[0]
    return token


def count_evidence_from_json(match_json: Path, res: CaseResult) -> None:
    """Populate IPID/F5/TLS statistics and evidence kinds for a case.

    The JSON structure is produced by MatchSerializer.save_matches and contains:
      - "matches": [{"score": {"evidence": str, ...}}, ...]
    """
    if not match_json.is_file():
        return

    try:
        with match_json.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    seen_kinds: set[str] = set(res.evidence_types or [])

    for match in data.get("matches", []):
        score = match.get("score", {})
        evidence = str(score.get("evidence", "")) or ""

        # IPID statistics
        if "ipid*" in evidence:
            res.strong_ipid_matches += 1
        elif "ipid" in evidence:
            res.normal_ipid_matches += 1

        # F5 / TLS statistics
        if "F5_TRAILER(" in evidence:
            res.f5_matches += 1
        if "TLS_CLIENT_HELLO(" in evidence:
            res.tls_matches += 1

        # Collect evidence kinds
        for raw_token in evidence.split():
            kind = _normalize_evidence_token(raw_token)
            if kind:
                seen_kinds.add(kind)

    # Store sorted list for stable JSON/Markdown output
    res.evidence_types = sorted(seen_kinds)


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
    f5_sum = sum(r.f5_matches for r in results)
    tls_sum = sum(r.tls_matches for r in results)

    lines = []
    lines.append(f"# 2hops Match 汇总结果\n")
    lines.append(f"- 用例总数: {total_cases}")
    lines.append(f"- 总连接数: file1={sum_total1}, file2={sum_total2}")
    lines.append(f"- 总匹配对数: {sum_matched}")
    lines.append(f"- 平均置信度(跨有匹配的用例): {avg_score_cases:.2f}")
    lines.append(f"- 强 IPID 匹配总数: {strong_sum}")
    lines.append(f"- 普通 IPID 匹配总数: {normal_sum}")
    lines.append(f"- F5 匹配总数: {f5_sum}")
    lines.append(f"- TLS 匹配总数: {tls_sum}")
    lines.append("")

    # Table header
    lines.append("| 用例 | f1连接 | f2连接 | 匹配对 | 强IPID | 普通IPID | F5 | TLS | 平均分 | Evidence种类 |")
    lines.append("|------|--------|--------|--------|--------|----------|----|-----|--------|--------------|")
    for r in results:
        evidence_col = ",".join(r.evidence_types) if r.evidence_types else ""
        lines.append(
            f"| {r.case} | {r.total1} | {r.total2} | {r.matched_pairs} | "
            f"{r.strong_ipid_matches} | {r.normal_ipid_matches} | {r.f5_matches} | {r.tls_matches} | {r.average_score:.2f} | {evidence_col} |"
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

    # Ensure analysis dir exists and prepare directory for per-case match JSON files
    analysis_dir = Path("analysis")
    analysis_dir.mkdir(parents=True, exist_ok=True)
    match_json_dir = analysis_dir / "2hops_matches"
    match_json_dir.mkdir(parents=True, exist_ok=True)

    for case_dir in cases:
        try:
            match_json = match_json_dir / f"{case_dir.name}.json"
            out = run_match(case_dir, args.bucket, match_json=match_json)
            res = parse_output(case_dir.name, out)
            count_evidence_from_json(match_json, res)
            results.append(res)
        except Exception:
            # Record an empty result with error indicator
            results.append(CaseResult(case=case_dir.name))


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

