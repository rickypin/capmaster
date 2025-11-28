#!/usr/bin/env python3
"""Analyze score distribution to understand why Behavioral has low precision.

This script analyzes:
1. Score distribution of True Positives (matches found by both Auto and Behavioral)
2. Score distribution of False Positives (matches found only by Behavioral)
3. Optimal threshold to separate TP from FP
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.core.connection.behavioral_matcher import BehavioralMatcher
from capmaster.core.connection.matcher import BucketStrategy, ConnectionMatcher, MatchMode


def analyze_case(case_dir: Path):
    """Analyze score distribution for a single case."""
    pcap_files = sorted(case_dir.glob("*.pcap"))
    if len(pcap_files) < 2:
        return None
    
    file1, file2 = pcap_files[0], pcap_files[1]
    
    print(f"\n{'=' * 80}")
    print(f"📁 Case: {case_dir.name}")
    print(f"{'=' * 80}")
    
    # Extract connections
    print("Extracting connections...")
    conns1 = list(extract_connections_from_pcap(file1))
    conns2 = list(extract_connections_from_pcap(file2))
    print(f"  File 1: {len(conns1)} connections")
    print(f"  File 2: {len(conns2)} connections")
    
    # Auto mode (Ground Truth)
    print("\n🎯 Auto Mode (Ground Truth)...")
    auto_matcher = ConnectionMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
        match_mode=MatchMode.ONE_TO_ONE,
    )
    auto_matches = auto_matcher.match(conns1, conns2)
    auto_pairs = {(m.conn1.stream_id, m.conn2.stream_id) for m in auto_matches}
    print(f"  Matches: {len(auto_matches)}")
    
    # Behavioral mode (Old Recommended)
    print("\n🔍 Behavioral (Old Recommended, threshold=0.60)...")
    behavioral_matcher = BehavioralMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
        match_mode=MatchMode.ONE_TO_ONE,
        weight_overlap=0.0,
        weight_duration=0.4,
        weight_iat=0.3,
        weight_bytes=0.3,
    )
    behavioral_matches = behavioral_matcher.match(conns1, conns2)
    
    # Categorize matches
    tp_scores = []  # True Positives
    fp_scores = []  # False Positives
    
    for match in behavioral_matches:
        pair = (match.conn1.stream_id, match.conn2.stream_id)
        score = match.score.normalized_score
        
        if pair in auto_pairs:
            tp_scores.append(score)
        else:
            fp_scores.append(score)
    
    print(f"  Total Matches: {len(behavioral_matches)}")
    print(f"  True Positives: {len(tp_scores)}")
    print(f"  False Positives: {len(fp_scores)}")
    
    # Analyze score distribution
    print(f"\n📊 Score Distribution Analysis:")
    
    if tp_scores:
        tp_scores.sort(reverse=True)
        print(f"\n  True Positives (correct matches):")
        print(f"    Count: {len(tp_scores)}")
        print(f"    Min:   {min(tp_scores):.3f}")
        print(f"    Max:   {max(tp_scores):.3f}")
        print(f"    Avg:   {sum(tp_scores)/len(tp_scores):.3f}")
        print(f"    Median: {tp_scores[len(tp_scores)//2]:.3f}")
        
        # Show percentiles
        print(f"    Percentiles:")
        for p in [10, 25, 50, 75, 90]:
            idx = int(len(tp_scores) * p / 100)
            print(f"      {p}th: {tp_scores[idx]:.3f}")
    
    if fp_scores:
        fp_scores.sort(reverse=True)
        print(f"\n  False Positives (incorrect matches):")
        print(f"    Count: {len(fp_scores)}")
        print(f"    Min:   {min(fp_scores):.3f}")
        print(f"    Max:   {max(fp_scores):.3f}")
        print(f"    Avg:   {sum(fp_scores)/len(fp_scores):.3f}")
        print(f"    Median: {fp_scores[len(fp_scores)//2]:.3f}")
        
        # Show percentiles
        print(f"    Percentiles:")
        for p in [10, 25, 50, 75, 90]:
            idx = int(len(fp_scores) * p / 100)
            print(f"      {p}th: {fp_scores[idx]:.3f}")
    
    # Find optimal threshold
    print(f"\n🎯 Threshold Analysis:")
    print(f"  {'Threshold':<12} {'TP':<6} {'FP':<6} {'Precision':<12} {'Recall':<12} {'F1':<12}")
    print(f"  {'-'*70}")
    
    for threshold in [0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95, 0.98]:
        tp_count = sum(1 for s in tp_scores if s >= threshold)
        fp_count = sum(1 for s in fp_scores if s >= threshold)
        
        precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0
        recall = tp_count / len(auto_pairs) if auto_pairs else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"  {threshold:<12.2f} {tp_count:<6} {fp_count:<6} {precision:<12.1%} {recall:<12.1%} {f1:<12.1%}")
    
    return {
        "case": case_dir.name,
        "tp_scores": tp_scores,
        "fp_scores": fp_scores,
    }


def main():
    """Analyze score distribution on multiple cases."""
    base_dir = Path("data/2hops")
    
    # Test cases
    test_cases = [
        "TC-034-3-20210604-O",  # auto=504
        "TC-034-4-20210901",    # auto=95
    ]
    
    print("=" * 80)
    print("🔬 Analyzing Score Distribution")
    print("   (Understanding why Behavioral has low precision)")
    print("=" * 80)
    
    for case_name in test_cases:
        case_dir = base_dir / case_name
        if not case_dir.exists():
            print(f"\n⚠️  Skipping {case_name}: directory not found")
            continue
        
        analyze_case(case_dir)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

