#!/usr/bin/env python3
"""Optimize Behavioral matching precision by testing different configurations.

This script tests various combinations of:
1. Score thresholds (0.60, 0.70, 0.80, 0.90, 0.95)
2. Weight configurations
3. Bucket strategies

Goal: Maximize precision while maintaining reasonable recall.
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.core.connection.behavioral_matcher import BehavioralMatcher
from capmaster.core.connection.matcher import BucketStrategy, ConnectionMatcher, MatchMode


def get_match_pairs(matches):
    """Extract (stream_id_1, stream_id_2) pairs from matches."""
    return {(m.conn1.stream_id, m.conn2.stream_id) for m in matches}


def test_configuration(conns1, conns2, auto_pairs, config_name, threshold, weights, bucket_strategy):
    """Test a single configuration."""
    matcher = BehavioralMatcher(
        bucket_strategy=bucket_strategy,
        score_threshold=threshold,
        match_mode=MatchMode.ONE_TO_ONE,
        **weights,
    )
    matches = matcher.match(conns1, conns2)
    behavioral_pairs = get_match_pairs(matches)
    
    # Calculate metrics
    tp = len(auto_pairs & behavioral_pairs)
    fp = len(behavioral_pairs - auto_pairs)
    fn = len(auto_pairs - behavioral_pairs)
    
    precision = tp / len(behavioral_pairs) if behavioral_pairs else 0
    recall = tp / len(auto_pairs) if auto_pairs else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "config": config_name,
        "threshold": threshold,
        "bucket": bucket_strategy.value,
        "total": len(matches),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def analyze_case(case_dir: Path):
    """Analyze a single case with multiple configurations."""
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
    auto_pairs = get_match_pairs(auto_matches)
    print(f"  Matches: {len(auto_matches)}")
    
    # Test configurations
    print("\n🔍 Testing configurations...")
    
    # Weight configurations to test
    weight_configs = {
        "Old Rec": {"weight_overlap": 0.0, "weight_duration": 0.4, "weight_iat": 0.3, "weight_bytes": 0.3},
        "IAT+Duration": {"weight_overlap": 0.0, "weight_duration": 0.5, "weight_iat": 0.5, "weight_bytes": 0.0},
    }

    # Thresholds to test
    thresholds = [0.95, 0.98, 0.99]

    # Bucket strategies to test
    bucket_strategies = [BucketStrategy.PORT, BucketStrategy.SERVER]
    
    results = []
    
    for config_name, weights in weight_configs.items():
        for threshold in thresholds:
            for bucket_strategy in bucket_strategies:
                result = test_configuration(
                    conns1, conns2, auto_pairs,
                    config_name, threshold, weights, bucket_strategy
                )
                results.append(result)
    
    # Sort by F1 score (best balance of precision and recall)
    results.sort(key=lambda r: r["f1"], reverse=True)
    
    # Show top 10 configurations
    print(f"\n{'Config':<15} {'Threshold':<10} {'Bucket':<10} {'Total':<7} {'TP':<5} {'FP':<5} {'Precision':<10} {'Recall':<10} {'F1':<10}")
    print("-" * 100)
    
    for r in results[:10]:
        print(f"{r['config']:<15} {r['threshold']:<10.2f} {r['bucket']:<10} "
              f"{r['total']:<7} {r['tp']:<5} {r['fp']:<5} "
              f"{r['precision']:<10.1%} {r['recall']:<10.1%} {r['f1']:<10.1%}")
    
    return {
        "case": case_dir.name,
        "auto_matches": len(auto_matches),
        "results": results[:10],  # Keep top 10
    }


def main():
    """Optimize Behavioral precision on multiple cases."""
    base_dir = Path("/Users/ricky/Downloads/2hops")
    
    # Test cases
    test_cases = [
        "TC-034-3-20210604-O",  # auto=504
        "TC-034-4-20210901",    # auto=95
    ]
    
    print("=" * 80)
    print("🔬 Optimizing Behavioral Matching Precision")
    print("   (Testing thresholds, weights, and bucket strategies)")
    print("=" * 80)
    
    all_results = []
    for case_name in test_cases:
        case_dir = base_dir / case_name
        if not case_dir.exists():
            print(f"\n⚠️  Skipping {case_name}: directory not found")
            continue
        
        result = analyze_case(case_dir)
        if result:
            all_results.append(result)
    
    # Overall best configurations
    print(f"\n\n{'=' * 80}")
    print("📊 BEST CONFIGURATIONS ACROSS ALL CASES")
    print(f"{'=' * 80}\n")
    
    # Aggregate results
    from collections import defaultdict
    config_scores = defaultdict(list)
    
    for case_result in all_results:
        for r in case_result["results"]:
            key = (r["config"], r["threshold"], r["bucket"])
            config_scores[key].append(r["f1"])
    
    # Calculate average F1 for each configuration
    avg_scores = []
    for key, f1_scores in config_scores.items():
        avg_f1 = sum(f1_scores) / len(f1_scores)
        avg_scores.append({
            "config": key[0],
            "threshold": key[1],
            "bucket": key[2],
            "avg_f1": avg_f1,
            "cases": len(f1_scores),
        })
    
    avg_scores.sort(key=lambda r: r["avg_f1"], reverse=True)
    
    print(f"{'Config':<15} {'Threshold':<10} {'Bucket':<10} {'Avg F1':<10} {'Cases':<10}")
    print("-" * 60)
    
    for r in avg_scores[:10]:
        print(f"{r['config']:<15} {r['threshold']:<10.2f} {r['bucket']:<10} "
              f"{r['avg_f1']:<10.1%} {r['cases']:<10}")
    
    print("\n💡 建议：")
    best = avg_scores[0]
    print(f"  最佳配置: {best['config']}, threshold={best['threshold']:.2f}, bucket={best['bucket']}")
    print(f"  平均 F1: {best['avg_f1']:.1%}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

