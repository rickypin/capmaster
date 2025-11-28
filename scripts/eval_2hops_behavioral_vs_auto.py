from __future__ import annotations

import csv
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

ROOT_CASES = Path(os.environ.get("EVAL_CASES_DIR", "data/2hops"))
OUT_ROOT = Path(os.environ.get("EVAL_OUT_DIR", "eval_results/2hops"))
PARALLEL = int(os.environ.get("EVAL_PARALLEL", "3"))
MAX_CASES: Optional[int] = int(os.environ["EVAL_MAX_CASES"]) if os.environ.get("EVAL_MAX_CASES") else None
SKIP_EXISTING = os.environ.get("EVAL_SKIP_EXISTING", "1") != "0"
# Extra CLI args passed to both modes to speed up (fair for both): bucket by port and enable sampling
FAST_ARGS = os.environ.get("EVAL_FAST_ARGS", "--bucket port --enable-sampling --sample-rate 0.5 --sample-threshold 800")

STATS_KEYS = {
    "total1": re.compile(r"Total connections \(file 1\):\s*(\d+)"),
    "total2": re.compile(r"Total connections \(file 2\):\s*(\d+)"),
    "matched": re.compile(r"Matched pairs:\s*(\d+)"),
    "unmatched1": re.compile(r"Unmatched \(file 1\):\s*(\d+)"),
    "unmatched2": re.compile(r"Unmatched \(file 2\):\s*(\d+)"),
    "rate1": re.compile(r"Match rate \(file 1\):\s*([0-9.]+)%"),
    "rate2": re.compile(r"Match rate \(file 2\):\s*([0-9.]+)%"),
    "avg": re.compile(r"Average score:\s*([0-9.]+)"),
}


def find_two_pcaps(case_dir: Path) -> list[Path]:
    pcaps = [p for p in case_dir.iterdir() if p.is_file() and p.suffix.lower() == ".pcap"]
    return pcaps if len(pcaps) == 2 else []


def run_match(case_dir: Path, mode: str, out_txt: Path) -> tuple[int, str]:
    out_txt.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "python", "-m", "capmaster", "match",
        "-i", str(case_dir),
        "-o", str(out_txt),
        "--mode", mode,
    ] + FAST_ARGS.split()
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.returncode, (res.stdout + "\n" + res.stderr)


def parse_stats(txt_file: Path) -> dict | None:
    if not txt_file.exists():
        return None
    text = txt_file.read_text(errors="ignore")
    stats: dict[str, float | int] = {}
    for key, pat in STATS_KEYS.items():
        m = pat.search(text)
        if not m:
            return None
        val = m.group(1)
        if key in {"total1", "total2", "matched", "unmatched1", "unmatched2"}:
            stats[key] = int(val)
        elif key in {"rate1", "rate2", "avg"}:
            stats[key] = float(val)
    return stats


def process_case(case_dir: Path) -> dict:
    pcaps = find_two_pcaps(case_dir)
    if not pcaps:
        return {"case": case_dir.name, "rc_auto": -1, "rc_beh": -1, "auto_stats": None, "beh_stats": None}
    out_dir = OUT_ROOT / case_dir.name
    auto_txt = out_dir / "auto.txt"
    beh_txt = out_dir / "behavioral.txt"

    # Run original (auto)
    if SKIP_EXISTING and auto_txt.exists() and parse_stats(auto_txt):
        rc_auto = 0
    else:
        rc_auto, _ = run_match(case_dir, "auto", auto_txt)

    # Run behavioral
    if SKIP_EXISTING and beh_txt.exists() and parse_stats(beh_txt):
        rc_beh = 0
    else:
        rc_beh, _ = run_match(case_dir, "behavioral", beh_txt)

    auto_stats = parse_stats(auto_txt) if rc_auto == 0 else None
    beh_stats = parse_stats(beh_txt) if rc_beh == 0 else None

    return {
        "case": case_dir.name,
        "rc_auto": rc_auto,
        "rc_beh": rc_beh,
        "auto_stats": auto_stats,
        "beh_stats": beh_stats,
    }


def main() -> int:
    cases = sorted([d for d in ROOT_CASES.iterdir() if d.is_dir()], key=lambda p: p.name)
    if MAX_CASES is not None:
        cases = cases[:MAX_CASES]

    summary_rows: list[dict] = []

    with ThreadPoolExecutor(max_workers=PARALLEL) as ex:
        futs = {ex.submit(process_case, case_dir): case_dir for case_dir in cases}
        for fut in as_completed(futs):
            row = fut.result()
            summary_rows.append(row)
            # Lightweight progress feedback
            print(f"done: {row['case']} rc_auto={row['rc_auto']} rc_beh={row['rc_beh']}")

    # Write CSV summary
    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    csv_path = OUT_ROOT / "summary.csv"
    with csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "case", "rc_auto", "rc_beh",
            "auto_total1", "auto_total2", "auto_matched", "auto_rate1(%)", "auto_rate2(%)", "auto_avg",
            "beh_total1", "beh_total2", "beh_matched", "beh_rate1(%)", "beh_rate2(%)", "beh_avg",
            "delta_matched(beh-auto)", "delta_avg(beh-auto)",
        ])
        for r in sorted(summary_rows, key=lambda x: x["case"]):
            a = r.get("auto_stats") or {}
            b = r.get("beh_stats") or {}
            w.writerow([
                r["case"], r["rc_auto"], r["rc_beh"],
                a.get("total1"), a.get("total2"), a.get("matched"), a.get("rate1"), a.get("rate2"), a.get("avg"),
                b.get("total1"), b.get("total2"), b.get("matched"), b.get("rate1"), b.get("rate2"), b.get("avg"),
                (b.get("matched") or 0) - (a.get("matched") or 0),
                (b.get("avg") or 0.0) - (a.get("avg") or 0.0),
            ])

    print(f"Wrote summary to {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
