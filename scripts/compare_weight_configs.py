#!/usr/bin/env python3
"""Compare different weight configurations for behavioral matching."""
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

def test_config(
    connections1: list,
    connections2: list,
    w_overlap: float,
    w_duration: float,
    w_iat: float,
    w_bytes: float,
) -> dict[str, Any]:
    """Test a specific weight configuration."""
    matcher = BehavioralMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
        match_mode=MatchMode.ONE_TO_ONE,
        weight_overlap=w_overlap,
        weight_duration=w_duration,
        weight_iat=w_iat,
        weight_bytes=w_bytes,
    )
    matches = matcher.match(connections1, connections2)
    
    if not matches:
        return {"matches": 0, "avg_score": 0.0}
    
    scores = [m.score.normalized_score for m in matches]
    return {
        "matches": len(matches),
        "avg_score": sum(scores) / len(scores),
        "min_score": min(scores),
        "max_score": max(scores),
    }

def main() -> int:
    case_dir = Path("data/2hops/TC-001-1-20160407")
    pcaps = sorted(case_dir.glob("*.pcap"))
    
    if len(pcaps) < 2:
        print(f"Error: Need at least 2 PCAP files in {case_dir}")
        return 1
    
    print(f"Loading case: {case_dir.name}")
    print()
    
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
    
    print(f"Connections: {len(connections1)} vs {len(connections2)}")
    print()
    
    # Define weight configurations to test
    configs = [
        ("Current (default)", 0.35, 0.25, 0.20, 0.20),
        ("Recommended", 0.24, 0.41, 0.24, 0.12),
        ("Duration-focused", 0.10, 0.50, 0.25, 0.15),
        ("No overlap", 0.00, 0.40, 0.30, 0.30),
        ("Equal weights", 0.25, 0.25, 0.25, 0.25),
    ]
    
    print("=" * 100)
    print("Weight Configuration Comparison")
    print("=" * 100)
    print()
    print(f"{'Configuration':20s} {'Overlap':>8s} {'Duration':>9s} {'IAT':>8s} {'Bytes':>8s} {'Matches':>8s} {'Avg Score':>10s}")
    print("-" * 100)
    
    results = []
    for name, w_o, w_d, w_i, w_b in configs:
        result = test_config(connections1, connections2, w_o, w_d, w_i, w_b)
        results.append((name, w_o, w_d, w_i, w_b, result))
        print(f"{name:20s} {w_o:8.2f} {w_d:9.2f} {w_i:8.2f} {w_b:8.2f} {result['matches']:8d} {result['avg_score']:10.3f}")
    
    print()
    print("=" * 100)
    print("Analysis")
    print("=" * 100)
    print()
    
    # Find best configuration by match count
    best_by_count = max(results, key=lambda x: x[5]["matches"])
    print(f"Most matches: {best_by_count[0]} ({best_by_count[5]['matches']} matches)")
    
    # Find best configuration by average score
    best_by_score = max(results, key=lambda x: x[5]["avg_score"])
    print(f"Highest avg score: {best_by_score[0]} (score={best_by_score[5]['avg_score']:.3f})")
    
    # Compare recommended vs current
    current = next(r for r in results if r[0] == "Current (default)")
    recommended = next(r for r in results if r[0] == "Recommended")
    
    print()
    print("Recommended vs Current:")
    print(f"  Match count: {recommended[5]['matches']} vs {current[5]['matches']} (delta: {recommended[5]['matches'] - current[5]['matches']:+d})")
    print(f"  Avg score:   {recommended[5]['avg_score']:.3f} vs {current[5]['avg_score']:.3f} (delta: {recommended[5]['avg_score'] - current[5]['avg_score']:+.3f})")
    
    print()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

