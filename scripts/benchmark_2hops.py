#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Run capmaster match over all subdirectories under a base directory (default: /Users/ricky/Downloads/2hops),
collect summary statistics, and store both raw outputs and an aggregated CSV.

Usage:
  python scripts/benchmark_2hops.py [BASE_DIR] [--tag AFTER]

Outputs:
  - benchmarks/2hops_<tag>/<case>.out.txt  (raw stdout of capmaster)
  - benchmarks/2hops_<tag>/summary.csv     (aggregated summary)
"""
from __future__ import annotations

import csv
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Optional

BASE_DEFAULT = "/Users/ricky/Downloads/2hops"
TAG_DEFAULT = "after"

RE_INT = re.compile(r"^\s*Total connections \(file 1\):\s*(\d+)")
RE_INT2 = re.compile(r"^\s*Total connections \(file 2\):\s*(\d+)")
RE_MATCHED = re.compile(r"^\s*Matched pairs:\s*(\d+)")
RE_UNMATCH1 = re.compile(r"^\s*Unmatched \(file 1\):\s*(\d+)")
RE_UNMATCH2 = re.compile(r"^\s*Unmatched \(file 2\):\s*(\d+)")
RE_RATE1 = re.compile(r"^\s*Match rate \(file 1\):\s*([0-9.]+)%")
RE_RATE2 = re.compile(r"^\s*Match rate \(file 2\):\s*([0-9.]+)%")
RE_AVG = re.compile(r"^\s*Average score:\s*([0-9.]+)")

RE_FIRST_MATCH = re.compile(r"^\[1\]\s+A:\s+(.*)$")
RE_EVIDENCE = re.compile(r"^\s+置信度:\s*([0-9.]+)\s*\|\s*证据:\s*(.*)$")


def find_case_dirs(base_dir: Path) -> list[Path]:
    case_dirs: list[Path] = []
    for entry in sorted(base_dir.iterdir()):
        if not entry.is_dir():
            continue
        # Require exactly 2 pcap files inside (capmaster match expects two files)
        pcaps = list(entry.glob("*.pcap")) + list(entry.glob("*.pcapng"))
        if len(pcaps) == 2:
            case_dirs.append(entry)
    return case_dirs


def run_case(case_dir: Path) -> str:
    proc = subprocess.run(
        ["capmaster", "match", "-i", str(case_dir)],
        capture_output=True,
        text=True,
    )
    out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    return out


def parse_summary(output: str) -> Dict[str, Any]:
    stats: Dict[str, Any] = {
        "total1": None,
        "total2": None,
        "matched": None,
        "unmatched1": None,
        "unmatched2": None,
        "rate1": None,
        "rate2": None,
        "avg": None,
        "first_match_conf": None,
        "first_match_evidence": None,
    }
    for line in output.splitlines():
        if stats["total1"] is None:
            m = RE_INT.search(line)
            if m:
                stats["total1"] = int(m.group(1))
                continue
        if stats["total2"] is None:
            m = RE_INT2.search(line)
            if m:
                stats["total2"] = int(m.group(1))
                continue
        if stats["matched"] is None:
            m = RE_MATCHED.search(line)
            if m:
                stats["matched"] = int(m.group(1))
                continue
        if stats["unmatched1"] is None:
            m = RE_UNMATCH1.search(line)
            if m:
                stats["unmatched1"] = int(m.group(1))
                continue
        if stats["unmatched2"] is None:
            m = RE_UNMATCH2.search(line)
            if m:
                stats["unmatched2"] = int(m.group(1))
                continue
        if stats["rate1"] is None:
            m = RE_RATE1.search(line)
            if m:
                stats["rate1"] = float(m.group(1))
                continue
        if stats["rate2"] is None:
            m = RE_RATE2.search(line)
            if m:
                stats["rate2"] = float(m.group(1))
                continue
        if stats["avg"] is None:
            m = RE_AVG.search(line)
            if m:
                stats["avg"] = float(m.group(1))
                continue

    # Try parse first match evidence if present
    found_first = False
    for i, line in enumerate(output.splitlines()):
        if RE_FIRST_MATCH.search(line):
            found_first = True
        if found_first:
            m = RE_EVIDENCE.search(line)
            if m:
                stats["first_match_conf"] = float(m.group(1))
                stats["first_match_evidence"] = m.group(2).strip()
                break
    return stats


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def main() -> int:
    base_dir = Path(sys.argv[1]) if len(sys.argv) >= 2 and not sys.argv[1].startswith("--") else Path(BASE_DEFAULT)
    tag: str = TAG_DEFAULT
    if len(sys.argv) >= 2:
        for idx, arg in enumerate(sys.argv[1:], 1):
            if arg == "--tag" and idx + 1 < len(sys.argv):
                tag = sys.argv[idx + 1]

    out_root = Path("benchmarks") / f"2hops_{tag}"
    ensure_dir(out_root)

    cases = find_case_dirs(base_dir)
    if not cases:
        print(f"No valid case directories under {base_dir}")
        return 1

    rows = []
    for i, case_dir in enumerate(cases, 1):
        print(f"[{i}/{len(cases)}] Running: {case_dir}")
        out_text = run_case(case_dir)

        out_file = out_root / f"{case_dir.name}.out.txt"
        out_file.write_text(out_text)

        stats = parse_summary(out_text)
        rows.append({
            "case": case_dir.name,
            **stats,
        })

    # Write CSV summary
    csv_file = out_root / "summary.csv"
    with csv_file.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "case","total1","total2","matched","unmatched1","unmatched2","rate1","rate2","avg","first_match_conf","first_match_evidence"
        ])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    print(f"Done. Results saved to {out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

