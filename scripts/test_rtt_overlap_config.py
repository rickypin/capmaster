#!/usr/bin/env python3
"""Test the RTT + Overlap configuration for behavioral matching.

This script tests the recommended configuration for two-hop scenarios:
- Time overlap: 50% (connections should have some time overlap)
- IAT (RTT approximation): 50% (request-response timing pattern)
- Duration: 0% (unreliable in two-hop)
- Bytes: 0% (unreliable with TLS)
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.core.connection.behavioral_matcher import BehavioralMatcher
from capmaster.core.connection.matcher import BucketStrategy, MatchMode


def test_case(case_dir: Path, config_name: str, weights: dict) -> dict:
    """Test a single case with given weight configuration."""
    # Find PCAP files
    pcap_files = sorted(case_dir.glob("*.pcap"))
    if len(pcap_files) < 2:
        return {"error": "Not enough PCAP files"}
    
    file1, file2 = pcap_files[0], pcap_files[1]
    
    # Extract connections
    print(f"  Extracting from {file1.name}...", end=" ", flush=True)
    conns1 = list(extract_connections_from_pcap(file1))
    print(f"{len(conns1)} connections")
    
    print(f"  Extracting from {file2.name}...", end=" ", flush=True)
    conns2 = list(extract_connections_from_pcap(file2))
    print(f"{len(conns2)} connections")
    
    # Match with given configuration
    matcher = BehavioralMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
        match_mode=MatchMode.ONE_TO_ONE,
        weight_overlap=weights["overlap"],
        weight_duration=weights["duration"],
        weight_iat=weights["iat"],
        weight_bytes=weights["bytes"],
    )
    
    matches = matcher.match(conns1, conns2)
    
    # Calculate statistics
    if matches:
        scores = [m.score.normalized_score for m in matches]
        avg_score = sum(scores) / len(scores)
        min_score = min(scores)
        max_score = max(scores)
    else:
        avg_score = min_score = max_score = 0.0
    
    return {
        "config": config_name,
        "matches": len(matches),
        "avg_score": avg_score,
        "min_score": min_score,
        "max_score": max_score,
    }


def main():
    """Test different configurations on sample cases."""
    # Test configurations
    configs = {
        "Current Default": {
            "overlap": 0.35,
            "duration": 0.25,
            "iat": 0.20,
            "bytes": 0.20,
        },
        "Recommended (no overlap/duration/bytes)": {
            "overlap": 0.0,
            "duration": 0.4,
            "iat": 0.3,
            "bytes": 0.3,
        },
        "RTT + Overlap (50/50)": {
            "overlap": 0.5,
            "duration": 0.0,
            "iat": 0.5,
            "bytes": 0.0,
        },
        "RTT + Overlap (40/60)": {
            "overlap": 0.4,
            "duration": 0.0,
            "iat": 0.6,
            "bytes": 0.0,
        },
        "RTT + Overlap (30/70)": {
            "overlap": 0.3,
            "duration": 0.0,
            "iat": 0.7,
            "bytes": 0.0,
        },
        "RTT Only (100%)": {
            "overlap": 0.0,
            "duration": 0.0,
            "iat": 1.0,
            "bytes": 0.0,
        },
    }
    
    # Find test cases
    test_cases_dir = Path("/Users/ricky/Downloads/2hops")
    if not test_cases_dir.exists():
        print(f"Error: Test cases directory not found: {test_cases_dir}")
        return 1
    
    # Get a few sample cases
    sample_cases = [
        "dbs_1112",
        "dbs_1113",
        "dbs_1110",
    ]
    
    print("Testing RTT + Overlap configurations on sample cases\n")
    print("=" * 80)
    
    for case_name in sample_cases:
        case_dir = test_cases_dir / case_name
        if not case_dir.exists():
            print(f"\nSkipping {case_name}: directory not found")
            continue
        
        print(f"\n📁 Case: {case_name}")
        print("-" * 80)
        
        results = []
        for config_name, weights in configs.items():
            print(f"\n  Testing: {config_name}")
            print(f"    Weights: overlap={weights['overlap']:.0%}, "
                  f"duration={weights['duration']:.0%}, "
                  f"iat={weights['iat']:.0%}, "
                  f"bytes={weights['bytes']:.0%}")
            
            result = test_case(case_dir, config_name, weights)
            if "error" in result:
                print(f"    ❌ {result['error']}")
                continue
            
            results.append(result)
            print(f"    ✓ Matches: {result['matches']}, "
                  f"Avg Score: {result['avg_score']:.3f}, "
                  f"Range: [{result['min_score']:.3f}, {result['max_score']:.3f}]")
        
        # Summary for this case
        if results:
            print(f"\n  📊 Summary for {case_name}:")
            best = max(results, key=lambda r: r["matches"])
            print(f"    Best config: {best['config']} with {best['matches']} matches")
    
    print("\n" + "=" * 80)
    print("✅ Testing complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())

