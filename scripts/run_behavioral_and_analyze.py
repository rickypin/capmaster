#!/usr/bin/env python3
"""Run behavioral matching on a case and analyze feature distributions directly."""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from capmaster.core.connection.extractor import TcpFieldExtractor
from capmaster.core.connection.models import ConnectionBuilder
from capmaster.core.connection.behavioral_matcher import BehavioralMatcher
from capmaster.core.connection.matcher import BucketStrategy, MatchMode

def main() -> int:
    case_dir = Path("data/2hops/TC-001-1-20160407")
    pcaps = sorted(case_dir.glob("*.pcap"))
    
    if len(pcaps) < 2:
        print(f"Error: Need at least 2 PCAP files in {case_dir}")
        return 1
    
    print(f"Case: {case_dir.name}")
    print(f"File 1: {pcaps[0].name}")
    print(f"File 2: {pcaps[1].name}")
    print()
    
    # Extract connections
    print("Extracting connections from file 1...")
    extractor1 = TcpFieldExtractor()
    builder1 = ConnectionBuilder()
    for packet in extractor1.extract(pcaps[0]):
        builder1.add_packet(packet)
    connections1 = list(builder1.build_connections())
    print(f"  Total: {len(connections1)}")
    
    print("Extracting connections from file 2...")
    extractor2 = TcpFieldExtractor()
    builder2 = ConnectionBuilder()
    for packet in extractor2.extract(pcaps[1]):
        builder2.add_packet(packet)
    connections2 = list(builder2.build_connections())
    print(f"  Total: {len(connections2)}")
    print()
    
    # Run behavioral matching
    print("Running behavioral matching...")
    matcher = BehavioralMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
        match_mode=MatchMode.ONE_TO_ONE,
    )
    matches = matcher.match(connections1, connections2)
    print(f"  Matched pairs: {len(matches)}")
    print()
    
    # Analyze features
    print("=" * 80)
    print("Feature Distribution Analysis")
    print("=" * 80)
    print()
    
    if not matches:
        print("No matches found")
        return 0
    
    # Parse evidence from each match
    import re
    features = []
    for m in matches:
        pattern = r"BEHAV\(overlap=([0-9.]+) dur=([0-9.]+) iat=([0-9.]+) bytes=([0-9.]+)\)"
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
        print("Failed to parse features from evidence")
        return 1
    
    # Statistics
    overlaps = [f["overlap"] for f in features]
    durations = [f["duration"] for f in features]
    iats = [f["iat"] for f in features]
    bytes_sims = [f["bytes"] for f in features]
    scores = [f["score"] for f in features]
    
    print(f"Total matches analyzed: {len(features)}")
    print()
    
    print("Feature Averages:")
    print(f"  overlap:  {sum(overlaps)/len(overlaps):.3f}")
    print(f"  duration: {sum(durations)/len(durations):.3f}")
    print(f"  iat:      {sum(iats)/len(iats):.3f}")
    print(f"  bytes:    {sum(bytes_sims)/len(bytes_sims):.3f}")
    print(f"  score:    {sum(scores)/len(scores):.3f}")
    print()
    
    print("Feature Ranges:")
    print(f"  overlap:  [{min(overlaps):.2f}, {max(overlaps):.2f}]")
    print(f"  duration: [{min(durations):.2f}, {max(durations):.2f}]")
    print(f"  iat:      [{min(iats):.2f}, {max(iats):.2f}]")
    print(f"  bytes:    [{min(bytes_sims):.2f}, {max(bytes_sims):.2f}]")
    print(f"  score:    [{min(scores):.2f}, {max(scores):.2f}]")
    print()
    
    print("Low-value Feature Counts (potential issues):")
    print(f"  overlap < 0.1:   {sum(1 for o in overlaps if o < 0.1):4d} ({100*sum(1 for o in overlaps if o < 0.1)/len(overlaps):.1f}%)")
    print(f"  duration < 0.5:  {sum(1 for d in durations if d < 0.5):4d} ({100*sum(1 for d in durations if d < 0.5)/len(durations):.1f}%)")
    print(f"  iat < 0.5:       {sum(1 for i in iats if i < 0.5):4d} ({100*sum(1 for i in iats if i < 0.5)/len(iats):.1f}%)")
    print(f"  bytes < 0.5:     {sum(1 for b in bytes_sims if b < 0.5):4d} ({100*sum(1 for b in bytes_sims if b < 0.5)/len(bytes_sims):.1f}%)")
    print()
    
    print("=" * 80)
    print("Tuning Recommendations")
    print("=" * 80)
    print()
    print("Current weights: overlap=35%, duration=25%, iat=20%, bytes=20%")
    print()
    
    avg_overlap = sum(overlaps) / len(overlaps)
    avg_duration = sum(durations) / len(durations)
    avg_iat = sum(iats) / len(iats)
    avg_bytes = sum(bytes_sims) / len(bytes_sims)
    
    if avg_overlap < 0.3:
        print("⚠️  overlap 平均值很低，说明时间重叠不是强约束")
        print("   建议: 降低 overlap 权重到 10-15%")
    elif avg_overlap > 0.8:
        print("✓  overlap 平均值很高，说明该特征区分度好")
        print("   建议: 可以保持或提高 overlap 权重")
    
    if avg_duration > 0.9:
        print("✓  duration 平均值很高，说明该特征区分度好")
        print("   建议: 可以提高 duration 权重到 30-35%")
    
    if avg_iat > 0.9:
        print("✓  iat 平均值很高，说明该特征区分度好")
        print("   建议: 可以提高 iat 权重到 25-30%")
    
    if avg_bytes < 0.5:
        print("⚠️  bytes 平均值偏低，可能区分度不足")
        print("   建议: 降低 bytes 权重到 5-10%，或考虑用其他特征替代")
    elif avg_bytes > 0.8:
        print("✓  bytes 平均值很高，说明该特征区分度好")
        print("   建议: 可以保持或提高 bytes 权重")
    
    print()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

