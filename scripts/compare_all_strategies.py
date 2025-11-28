#!/usr/bin/env python3
"""Compare all matching strategies: auto, F5, TLS, behavioral.

This script tests all available matching strategies on sample cases
to understand their effectiveness in different scenarios.
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.core.connection.behavioral_matcher import BehavioralMatcher
from capmaster.core.connection.matcher import BucketStrategy, ConnectionMatcher, MatchMode
from capmaster.core.connection.f5_matcher import F5Matcher
from capmaster.core.connection.tls_matcher import TlsMatcher


def test_auto_mode(file1: Path, file2: Path, conns1, conns2) -> dict:
    """Test auto mode (feature-based matching)."""
    matcher = ConnectionMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
        match_mode=MatchMode.ONE_TO_ONE,
    )
    matches = matcher.match(conns1, conns2)
    return {
        "strategy": "auto",
        "matches": len(matches),
        "avg_score": sum(m.score.normalized_score for m in matches) / len(matches) if matches else 0.0,
    }


def test_f5_mode(file1: Path, file2: Path) -> dict:
    """Test F5 trailer-based matching."""
    matcher = F5Matcher()
    
    # Detect F5 trailer
    has_f5_1 = matcher.detect_f5_trailer(file1)
    has_f5_2 = matcher.detect_f5_trailer(file2)
    
    if not (has_f5_1 and has_f5_2):
        return {
            "strategy": "f5",
            "matches": 0,
            "avg_score": 0.0,
            "note": f"F5 trailer not found (file1={has_f5_1}, file2={has_f5_2})",
        }
    
    matches = matcher.match(file1, file2)
    return {
        "strategy": "f5",
        "matches": len(matches),
        "avg_score": 1.0 if matches else 0.0,  # F5 matching is 100% accurate
        "note": "F5 trailer detected",
    }


def test_tls_mode(file1: Path, file2: Path) -> dict:
    """Test TLS Client Hello-based matching."""
    matcher = TlsMatcher()
    
    # Detect TLS Client Hello
    has_tls_1 = matcher.detect_tls_client_hello(file1)
    has_tls_2 = matcher.detect_tls_client_hello(file2)
    
    if not (has_tls_1 and has_tls_2):
        return {
            "strategy": "tls",
            "matches": 0,
            "avg_score": 0.0,
            "note": f"TLS Client Hello not found (file1={has_tls_1}, file2={has_tls_2})",
        }
    
    matches = matcher.match(file1, file2)
    return {
        "strategy": "tls",
        "matches": len(matches),
        "avg_score": 1.0 if matches else 0.0,  # TLS random matching is highly accurate
        "note": "TLS Client Hello detected",
    }


def test_behavioral_mode(conns1, conns2, config_name: str, weights: dict) -> dict:
    """Test behavioral matching with given configuration."""
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
    return {
        "strategy": f"behavioral ({config_name})",
        "matches": len(matches),
        "avg_score": sum(m.score.normalized_score for m in matches) / len(matches) if matches else 0.0,
    }


def test_single_case(case_dir: Path) -> dict:
    """Test all strategies on a single case."""
    pcap_files = sorted(case_dir.glob("*.pcap"))
    if len(pcap_files) < 2:
        return {"error": "Not enough PCAP files"}

    file1, file2 = pcap_files[0], pcap_files[1]

    print(f"\n{'=' * 80}")
    print(f"📁 Case: {case_dir.name}")
    print(f"  File 1: {file1.name}")
    print(f"  File 2: {file2.name}")
    print(f"{'=' * 80}")

    # Extract connections (needed for auto and behavioral modes)
    print("\n📦 Extracting connections...")
    conns1 = list(extract_connections_from_pcap(file1))
    conns2 = list(extract_connections_from_pcap(file2))
    print(f"  File 1: {len(conns1)} connections")
    print(f"  File 2: {len(conns2)} connections")

    results = []

    # Test all strategies
    print("\n🔍 Testing strategies...")

    # 1. Auto mode
    result = test_auto_mode(file1, file2, conns1, conns2)
    results.append(result)
    print(f"  Auto:            {result['matches']:>4} matches")

    # 2. F5 mode
    result = test_f5_mode(file1, file2)
    results.append(result)
    print(f"  F5:              {result['matches']:>4} matches")

    # 3. TLS mode
    result = test_tls_mode(file1, file2)
    results.append(result)
    print(f"  TLS:             {result['matches']:>4} matches")

    # 4. Behavioral modes
    behavioral_configs = {
        "Pure IAT": {"overlap": 0.0, "duration": 0.0, "iat": 1.0, "bytes": 0.0},
        "Old Recommended": {"overlap": 0.0, "duration": 0.4, "iat": 0.3, "bytes": 0.3},
    }

    for config_name, weights in behavioral_configs.items():
        result = test_behavioral_mode(conns1, conns2, config_name, weights)
        results.append(result)
        print(f"  Behavioral ({config_name}): {result['matches']:>4} matches")

    # Find best
    best = max(results, key=lambda r: r["matches"])

    return {
        "case": case_dir.name,
        "results": results,
        "best": best,
        "conns1": len(conns1),
        "conns2": len(conns2),
    }


def main():
    """Compare all strategies on multiple representative cases."""
    # Test cases directory
    base_dir = Path("data/2hops")
    if not base_dir.exists():
        print(f"Error: Base directory not found: {base_dir}")
        return 1

    # Representative test cases
    test_cases = [
        "TC-034-3-20210604-O",  # auto=504, behavioral=1041
        "TC-035-04-20240104",   # auto=1169, behavioral=2230
        "TC-034-4-20210901",    # auto=95, behavioral=358
        "dbs_1113_2",           # auto=11, behavioral=662
    ]

    print("=" * 80)
    print("🔬 Comparing All Matching Strategies on Representative Cases")
    print("=" * 80)

    all_results = []
    for case_name in test_cases:
        case_dir = base_dir / case_name
        if not case_dir.exists():
            print(f"\n⚠️  Skipping {case_name}: directory not found")
            continue

        result = test_single_case(case_dir)
        if "error" in result:
            print(f"  ❌ {result['error']}")
            continue

        all_results.append(result)

    # Overall summary
    print(f"\n\n{'=' * 80}")
    print("📊 OVERALL SUMMARY")
    print(f"{'=' * 80}\n")

    print(f"{'Case':<30} {'Auto':<8} {'F5':<8} {'TLS':<8} {'Pure IAT':<10} {'Old Rec':<10} {'Best':<15}")
    print("-" * 80)

    for case_result in all_results:
        case = case_result["case"]
        results = {r["strategy"]: r["matches"] for r in case_result["results"]}
        best = case_result["best"]

        print(f"{case:<30} "
              f"{results.get('auto', 0):<8} "
              f"{results.get('f5', 0):<8} "
              f"{results.get('tls', 0):<8} "
              f"{results.get('behavioral (Pure IAT)', 0):<10} "
              f"{results.get('behavioral (Old Recommended)', 0):<10} "
              f"{best['strategy']:<15}")

    print("\n✅ Testing complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())

