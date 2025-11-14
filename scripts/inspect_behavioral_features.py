#!/usr/bin/env python3
"""Inspect behavioral features of matched connections to guide tuning."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

def parse_behavioral_evidence(evidence: str) -> dict[str, float]:
    """Parse behavioral evidence string like 'BEHAV(overlap=0.67 dur=0.67 iat=0.74 bytes=0.95)'"""
    pattern = r"BEHAV\(overlap=([0-9.]+) dur=([0-9.]+) iat=([0-9.]+) bytes=([0-9.]+)\)"
    m = re.search(pattern, evidence)
    if not m:
        return {}
    return {
        "overlap": float(m.group(1)),
        "duration": float(m.group(2)),
        "iat": float(m.group(3)),
        "bytes": float(m.group(4)),
    }

def parse_match_line(line: str) -> dict[str, Any] | None:
    """Parse a match result line from behavioral.txt"""
    # Format: No. Stream_A Client_A Server_A Stream_B Client_B Server_B Conf Evidence
    # Example: 1      12         17.17.17.45:56950      10.30.50.101:6096      236        17.17.17.45:38723      10.0.6.33:6096         0.67   BEHAV(overlap=0.67 dur=0.67 iat=0.74 bytes=0.95)
    # Note: Evidence may be truncated with "..." in display, but we can still extract what's visible
    if not line.strip() or line.startswith("-") or "Stream A" in line:
        return None

    parts = line.split()
    if len(parts) < 9:
        return None
    try:
        no = int(parts[0])
        conf = float(parts[7])
        evidence = " ".join(parts[8:])

        # Try to parse features from evidence
        features = parse_behavioral_evidence(evidence)
        if not features:
            # If evidence is truncated, try to extract what we can
            # Look for individual feature values
            overlap_m = re.search(r"overlap=([0-9.]+)", evidence)
            dur_m = re.search(r"dur=([0-9.]+)", evidence)
            iat_m = re.search(r"iat=([0-9.]+)", evidence)
            bytes_m = re.search(r"bytes=([0-9.]+)", evidence)

            if overlap_m and dur_m and iat_m:  # At least have first 3 features
                features = {
                    "overlap": float(overlap_m.group(1)),
                    "duration": float(dur_m.group(1)),
                    "iat": float(iat_m.group(1)),
                    "bytes": float(bytes_m.group(1)) if bytes_m else 0.0,
                }
            else:
                return None

        return {
            "no": no,
            "conf": conf,
            **features
        }
    except (ValueError, IndexError):
        return None

def analyze_case(case_dir: Path) -> dict[str, Any]:
    """Analyze behavioral features for a single case."""
    beh_txt = case_dir / "behavioral.txt"
    if not beh_txt.exists():
        return {"case": case_dir.name, "error": "behavioral.txt not found"}
    
    text = beh_txt.read_text(errors="ignore")
    lines = text.split("\n")
    
    # Find matched connections section
    in_matches = False
    matches = []
    for line in lines:
        if "Matched Connections:" in line:
            in_matches = True
            continue
        if in_matches and line.strip().startswith("Total:"):
            break
        if in_matches and line.strip() and not line.startswith("-"):
            match = parse_match_line(line)
            if match:
                matches.append(match)
    
    if not matches:
        return {"case": case_dir.name, "matches": 0}
    
    # Compute statistics
    overlaps = [m["overlap"] for m in matches]
    durations = [m["duration"] for m in matches]
    iats = [m["iat"] for m in matches]
    bytes_sims = [m["bytes"] for m in matches]
    confs = [m["conf"] for m in matches]
    
    return {
        "case": case_dir.name,
        "matches": len(matches),
        "conf_avg": sum(confs) / len(confs),
        "conf_min": min(confs),
        "conf_max": max(confs),
        "overlap_avg": sum(overlaps) / len(overlaps),
        "overlap_min": min(overlaps),
        "duration_avg": sum(durations) / len(durations),
        "duration_min": min(durations),
        "iat_avg": sum(iats) / len(iats),
        "iat_min": min(iats),
        "bytes_avg": sum(bytes_sims) / len(bytes_sims),
        "bytes_min": min(bytes_sims),
        # Count how many matches have low feature values
        "low_overlap": sum(1 for o in overlaps if o < 0.1),
        "low_duration": sum(1 for d in durations if d < 0.5),
        "low_iat": sum(1 for i in iats if i < 0.5),
        "low_bytes": sum(1 for b in bytes_sims if b < 0.5),
    }

def main() -> int:
    out_root = Path("eval_results/2hops")
    if not out_root.exists():
        print(f"Error: {out_root} not found", file=sys.stderr)
        return 1
    
    cases = sorted([d for d in out_root.iterdir() if d.is_dir()], key=lambda p: p.name)
    
    print("=" * 100)
    print("行为特征分布分析（用于调校权重和阈值）")
    print("=" * 100)
    print()
    
    results = []
    for case_dir in cases:
        result = analyze_case(case_dir)
        if "error" not in result and result.get("matches", 0) > 0:
            results.append(result)
    
    if not results:
        print("无有效数据")
        return 0
    
    print(f"分析用例数: {len(results)}")
    print()
    
    # Overall statistics
    print("## 1. 各特征的平均值分布")
    print(f"{'用例':30s} {'匹配数':>8s} {'平均分':>8s} {'overlap':>8s} {'duration':>8s} {'iat':>8s} {'bytes':>8s}")
    print("-" * 100)
    for r in results:
        print(f"{r['case']:30s} {r['matches']:8d} {r['conf_avg']:8.2f} {r['overlap_avg']:8.2f} {r['duration_avg']:8.2f} {r['iat_avg']:8.2f} {r['bytes_avg']:8.2f}")
    print()
    
    # Feature contribution analysis
    print("## 2. 低值特征统计（可能影响匹配质量）")
    print(f"{'用例':30s} {'匹配数':>8s} {'低overlap':>10s} {'低duration':>12s} {'低iat':>8s} {'低bytes':>10s}")
    print("-" * 100)
    for r in results:
        print(f"{r['case']:30s} {r['matches']:8d} {r['low_overlap']:10d} {r['low_duration']:12d} {r['low_iat']:8d} {r['low_bytes']:10d}")
    print()
    
    # Aggregate insights
    total_matches = sum(r["matches"] for r in results)
    total_low_overlap = sum(r["low_overlap"] for r in results)
    total_low_duration = sum(r["low_duration"] for r in results)
    total_low_iat = sum(r["low_iat"] for r in results)
    total_low_bytes = sum(r["low_bytes"] for r in results)
    
    print("## 3. 总体特征质量")
    print(f"  总匹配对数: {total_matches}")
    print(f"  低 overlap (<0.1):   {total_low_overlap:5d} ({100*total_low_overlap/total_matches:.1f}%)")
    print(f"  低 duration (<0.5):  {total_low_duration:5d} ({100*total_low_duration/total_matches:.1f}%)")
    print(f"  低 iat (<0.5):       {total_low_iat:5d} ({100*total_low_iat/total_matches:.1f}%)")
    print(f"  低 bytes (<0.5):     {total_low_bytes:5d} ({100*total_low_bytes/total_matches:.1f}%)")
    print()
    
    avg_overlap = sum(r["overlap_avg"] for r in results) / len(results)
    avg_duration = sum(r["duration_avg"] for r in results) / len(results)
    avg_iat = sum(r["iat_avg"] for r in results) / len(results)
    avg_bytes = sum(r["bytes_avg"] for r in results) / len(results)
    
    print("## 4. 各特征的平均贡献度")
    print(f"  overlap:  {avg_overlap:.3f}")
    print(f"  duration: {avg_duration:.3f}")
    print(f"  iat:      {avg_iat:.3f}")
    print(f"  bytes:    {avg_bytes:.3f}")
    print()
    
    print("=" * 100)
    print("调优建议")
    print("=" * 100)
    print()
    print("当前权重: overlap=35%, duration=25%, iat=20%, bytes=20%")
    print()
    
    if total_low_overlap / total_matches > 0.3:
        print("⚠️  超过30%的匹配 overlap<0.1，说明时间重叠不是强约束")
        print("   建议: 降低 overlap 权重，或改为软约束（仅在>0时加分）")
    
    if avg_duration > 0.9:
        print("✓  duration 平均值很高，说明该特征区分度好")
        print("   建议: 可以适当提高 duration 权重")
    
    if avg_iat > 0.9:
        print("✓  iat 平均值很高，说明该特征区分度好")
        print("   建议: 可以适当提高 iat 权重")
    
    if avg_bytes < 0.7:
        print("⚠️  bytes 平均值偏低，可能区分度不足")
        print("   建议: 降低 bytes 权重，或考虑用其他特征替代")
    
    print()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

