#!/usr/bin/env python3
"""Analyze Behavioral matching accuracy against Auto (Ground Truth).

This script compares Behavioral matches with Auto matches to understand:
1. How many Behavioral matches are also found by Auto (True Positives)
2. How many Behavioral matches are NOT found by Auto (False Positives)
3. Precision = TP / (TP + FP)
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


def analyze_case(case_dir: Path):
    """Analyze a single case."""
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
    
    # Behavioral modes
    configs = {
        "Old Recommended": {"weight_overlap": 0.0, "weight_duration": 0.4, "weight_iat": 0.3, "weight_bytes": 0.3},
        "Pure IAT": {"weight_overlap": 0.0, "weight_duration": 0.0, "weight_iat": 1.0, "weight_bytes": 0.0},
    }

    results = []

    for config_name, weights in configs.items():
        print(f"\n🔍 Behavioral ({config_name})...")
        matcher = BehavioralMatcher(
            bucket_strategy=BucketStrategy.AUTO,
            score_threshold=0.60,
            match_mode=MatchMode.ONE_TO_ONE,
            **weights,
        )
        matches = matcher.match(conns1, conns2)
        behavioral_pairs = get_match_pairs(matches)
        
        # Calculate accuracy metrics
        true_positives = len(auto_pairs & behavioral_pairs)  # Both found
        false_positives = len(behavioral_pairs - auto_pairs)  # Behavioral only
        false_negatives = len(auto_pairs - behavioral_pairs)  # Auto only
        
        precision = true_positives / len(behavioral_pairs) if behavioral_pairs else 0
        recall = true_positives / len(auto_pairs) if auto_pairs else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"  Total Matches: {len(matches)}")
        print(f"  True Positives (TP):  {true_positives:>4} (also found by Auto)")
        print(f"  False Positives (FP): {false_positives:>4} (NOT found by Auto - 可能误匹配)")
        print(f"  False Negatives (FN): {false_negatives:>4} (Auto found but Behavioral missed)")
        print(f"  Precision: {precision:.1%} (TP / (TP + FP))")
        print(f"  Recall:    {recall:.1%} (TP / (TP + FN))")
        print(f"  F1 Score:  {f1:.1%}")
        
        results.append({
            "config": config_name,
            "total": len(matches),
            "tp": true_positives,
            "fp": false_positives,
            "fn": false_negatives,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        })
    
    return {
        "case": case_dir.name,
        "auto_matches": len(auto_matches),
        "results": results,
    }


def main():
    """Analyze multiple cases."""
    base_dir = Path("/Users/ricky/Downloads/2hops")
    
    # Test cases with Auto matches
    test_cases = [
        "TC-034-3-20210604-O",  # auto=504
        "TC-035-04-20240104",   # auto=1169
        "TC-034-4-20210901",    # auto=95
    ]
    
    print("=" * 80)
    print("🔬 Behavioral Matching Accuracy Analysis")
    print("   (Using Auto mode as Ground Truth)")
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
    
    # Summary
    print(f"\n\n{'=' * 80}")
    print("📊 SUMMARY")
    print(f"{'=' * 80}\n")
    
    print(f"{'Case':<25} {'Auto':<8} {'Config':<20} {'Total':<8} {'TP':<6} {'FP':<6} {'Precision':<10} {'Recall':<10}")
    print("-" * 80)
    
    for case_result in all_results:
        case = case_result["case"]
        auto = case_result["auto_matches"]
        
        for i, r in enumerate(case_result["results"]):
            case_col = case if i == 0 else ""
            auto_col = auto if i == 0 else ""
            print(f"{case_col:<25} {auto_col:<8} {r['config']:<20} "
                  f"{r['total']:<8} {r['tp']:<6} {r['fp']:<6} "
                  f"{r['precision']:<10.1%} {r['recall']:<10.1%}")
    
    print("\n💡 解读：")
    print("  - Precision (精确度): Behavioral 匹配中有多少是正确的")
    print("  - Recall (召回率): Auto 匹配中有多少被 Behavioral 找到")
    print("  - FP (False Positives): 可能的误匹配")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

