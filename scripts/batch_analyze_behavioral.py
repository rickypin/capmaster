#!/usr/bin/env python3
"""Batch analyze behavioral matching features across multiple cases."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from capmaster.core.connection.extractor import TcpFieldExtractor
from capmaster.core.connection.models import ConnectionBuilder
from capmaster.core.connection.behavioral_matcher import BehavioralMatcher
from capmaster.core.connection.matcher import BucketStrategy, MatchMode

def analyze_case(case_dir: Path) -> dict[str, Any] | None:
    """Analyze a single case and return feature statistics."""
    pcaps = sorted(case_dir.glob("*.pcap"))
    if len(pcaps) != 2:
        return None
    
    # Extract connections
    extractor1 = TcpFieldExtractor()
    builder1 = ConnectionBuilder()
    for packet in extractor1.extract(pcaps[0]):
        builder1.add_packet(packet)
    connections1 = list(builder1.build_connections())
    
    extractor2 = TcpFieldExtractor()
    builder2 = ConnectionBuilder()
    for packet in extractor2.extract(pcaps[1]):
        builder2.add_packet(packet)
    connections2 = list(builder2.build_connections())
    
    # Run behavioral matching
    matcher = BehavioralMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
        match_mode=MatchMode.ONE_TO_ONE,
    )
    matches = matcher.match(connections1, connections2)
    
    if not matches:
        return {
            "case": case_dir.name,
            "matches": 0,
        }
    
    # Parse features
    pattern = r"BEHAV\(overlap=([0-9.]+) dur=([0-9.]+) iat=([0-9.]+) bytes=([0-9.]+)\)"
    features = []
    for m in matches:
        match_obj = re.search(pattern, m.score.evidence)
        if match_obj:
            features.append({
                "overlap": float(match_obj.group(1)),
                "duration": float(match_obj.group(2)),
                "iat": float(match_obj.group(3)),
                "bytes": float(match_obj.group(4)),
                "score": m.score.normalized_score,
            })
    
    if not features:
        return {"case": case_dir.name, "matches": len(matches), "parse_error": True}
    
    # Compute statistics
    overlaps = [f["overlap"] for f in features]
    durations = [f["duration"] for f in features]
    iats = [f["iat"] for f in features]
    bytes_sims = [f["bytes"] for f in features]
    scores = [f["score"] for f in features]
    
    return {
        "case": case_dir.name,
        "matches": len(features),
        "overlap_avg": sum(overlaps) / len(overlaps),
        "overlap_min": min(overlaps),
        "duration_avg": sum(durations) / len(durations),
        "duration_min": min(durations),
        "iat_avg": sum(iats) / len(iats),
        "iat_min": min(iats),
        "bytes_avg": sum(bytes_sims) / len(bytes_sims),
        "bytes_min": min(bytes_sims),
        "score_avg": sum(scores) / len(scores),
        "low_overlap": sum(1 for o in overlaps if o < 0.1),
        "low_duration": sum(1 for d in durations if d < 0.5),
        "low_iat": sum(1 for i in iats if i < 0.5),
        "low_bytes": sum(1 for b in bytes_sims if b < 0.5),
    }

def main() -> int:
    root_cases = Path("data/2hops")
    if not root_cases.exists():
        print(f"Error: {root_cases} not found", file=sys.stderr)
        return 1
    
    cases = sorted([d for d in root_cases.iterdir() if d.is_dir()], key=lambda p: p.name)
    
    # Limit to first N cases for quick analysis
    max_cases = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    cases = cases[:max_cases]
    
    print(f"Analyzing {len(cases)} cases...")
    print()
    
    results = []
    for i, case_dir in enumerate(cases, 1):
        print(f"[{i}/{len(cases)}] {case_dir.name}...", end=" ", flush=True)
        result = analyze_case(case_dir)
        if result:
            results.append(result)
            print(f"✓ {result.get('matches', 0)} matches")
        else:
            print("✗ skipped")
    
    print()
    print("=" * 120)
    print("Behavioral Feature Analysis Summary")
    print("=" * 120)
    print()
    
    valid = [r for r in results if r.get("matches", 0) > 0 and "parse_error" not in r]
    if not valid:
        print("No valid results")
        return 0
    
    print(f"Valid cases: {len(valid)}")
    print()
    
    # Per-case table
    print(f"{'Case':30s} {'Matches':>8s} {'Overlap':>8s} {'Duration':>9s} {'IAT':>8s} {'Bytes':>8s} {'Score':>8s}")
    print("-" * 120)
    for r in valid:
        print(f"{r['case']:30s} {r['matches']:8d} {r['overlap_avg']:8.3f} {r['duration_avg']:9.3f} {r['iat_avg']:8.3f} {r['bytes_avg']:8.3f} {r['score_avg']:8.3f}")
    print()
    
    # Aggregate statistics
    total_matches = sum(r["matches"] for r in valid)
    avg_overlap = sum(r["overlap_avg"] * r["matches"] for r in valid) / total_matches
    avg_duration = sum(r["duration_avg"] * r["matches"] for r in valid) / total_matches
    avg_iat = sum(r["iat_avg"] * r["matches"] for r in valid) / total_matches
    avg_bytes = sum(r["bytes_avg"] * r["matches"] for r in valid) / total_matches
    
    total_low_overlap = sum(r["low_overlap"] for r in valid)
    total_low_duration = sum(r["low_duration"] for r in valid)
    total_low_iat = sum(r["low_iat"] for r in valid)
    total_low_bytes = sum(r["low_bytes"] for r in valid)
    
    print("Weighted Averages (across all matches):")
    print(f"  overlap:  {avg_overlap:.3f}")
    print(f"  duration: {avg_duration:.3f}")
    print(f"  iat:      {avg_iat:.3f}")
    print(f"  bytes:    {avg_bytes:.3f}")
    print()
    
    print("Low-value Feature Counts:")
    print(f"  overlap < 0.1:   {total_low_overlap:5d} / {total_matches:5d} ({100*total_low_overlap/total_matches:.1f}%)")
    print(f"  duration < 0.5:  {total_low_duration:5d} / {total_matches:5d} ({100*total_low_duration/total_matches:.1f}%)")
    print(f"  iat < 0.5:       {total_low_iat:5d} / {total_matches:5d} ({100*total_low_iat/total_matches:.1f}%)")
    print(f"  bytes < 0.5:     {total_low_bytes:5d} / {total_matches:5d} ({100*total_low_bytes/total_matches:.1f}%)")
    print()
    
    print("=" * 120)
    print("Tuning Recommendations")
    print("=" * 120)
    print()
    print("Current weights: overlap=35%, duration=25%, iat=20%, bytes=20%")
    print()
    
    if avg_overlap < 0.2:
        print(f"⚠️  overlap 平均值={avg_overlap:.3f}，{100*total_low_overlap/total_matches:.0f}%的匹配<0.1")
        print("   → 建议: 降低 overlap 权重到 5-10%，或改为可选加分项")
    
    if avg_duration > 0.85:
        print(f"✓  duration 平均值={avg_duration:.3f}，区分度很好")
        print("   → 建议: 提高 duration 权重到 30-40%")
    
    if avg_iat > 0.85:
        print(f"✓  iat 平均值={avg_iat:.3f}，区分度很好")
        print("   → 建议: 提高 iat 权重到 25-35%")
    
    if avg_bytes > 0.85:
        print(f"✓  bytes 平均值={avg_bytes:.3f}，区分度很好")
        print("   → 建议: 保持或提高 bytes 权重到 25-30%")
    elif avg_bytes < 0.6:
        print(f"⚠️  bytes 平均值={avg_bytes:.3f}，区分度一般")
        print("   → 建议: 降低 bytes 权重到 10-15%")
    
    print()
    print("建议的新权重配置（基于以上分析）:")
    if avg_overlap < 0.2:
        w_overlap = 0.05
    else:
        w_overlap = 0.20
    
    if avg_duration > 0.85:
        w_duration = 0.35
    else:
        w_duration = 0.25
    
    if avg_iat > 0.85:
        w_iat = 0.30
    else:
        w_iat = 0.20
    
    if avg_bytes > 0.85:
        w_bytes = 0.30
    elif avg_bytes < 0.6:
        w_bytes = 0.10
    else:
        w_bytes = 0.20
    
    # Normalize
    total_w = w_overlap + w_duration + w_iat + w_bytes
    w_overlap /= total_w
    w_duration /= total_w
    w_iat /= total_w
    w_bytes /= total_w
    
    print(f"  overlap:  {w_overlap:.0%}")
    print(f"  duration: {w_duration:.0%}")
    print(f"  iat:      {w_iat:.0%}")
    print(f"  bytes:    {w_bytes:.0%}")
    print()
    
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

