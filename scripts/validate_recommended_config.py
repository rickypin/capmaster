#!/usr/bin/env python3
"""Validate recommended behavioral config vs auto mode on all cases."""
from __future__ import annotations

import csv
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from capmaster.core.connection.extractor import TcpFieldExtractor
from capmaster.core.connection.models import ConnectionBuilder
from capmaster.core.connection.behavioral_matcher import BehavioralMatcher
from capmaster.core.connection.matcher import (
    BucketStrategy,
    ConnectionMatcher,
    MatchMode,
)

def run_auto_mode(pcap1: Path, pcap2: Path) -> dict:
    """Run auto mode matching."""
    # Extract connections
    extractor1 = TcpFieldExtractor()
    builder1 = ConnectionBuilder()
    for packet in extractor1.extract(pcap1):
        builder1.add_packet(packet)
    connections1 = list(builder1.build_connections())

    extractor2 = TcpFieldExtractor()
    builder2 = ConnectionBuilder()
    for packet in extractor2.extract(pcap2):
        builder2.add_packet(packet)
    connections2 = list(builder2.build_connections())

    # Auto mode matching (feature-based)
    matcher = ConnectionMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
        match_mode=MatchMode.ONE_TO_ONE,
    )
    matches = matcher.match(connections1, connections2)

    scores = [m.score.normalized_score for m in matches] if matches else []
    return {
        "total1": len(connections1),
        "total2": len(connections2),
        "matched": len(matches),
        "avg_score": sum(scores) / len(scores) if scores else 0.0,
    }

def run_behavioral_recommended(pcap1: Path, pcap2: Path) -> dict:
    """Run behavioral mode with recommended config (no overlap)."""
    # Extract connections
    extractor1 = TcpFieldExtractor()
    builder1 = ConnectionBuilder()
    for packet in extractor1.extract(pcap1):
        builder1.add_packet(packet)
    connections1 = list(builder1.build_connections())

    extractor2 = TcpFieldExtractor()
    builder2 = ConnectionBuilder()
    for packet in extractor2.extract(pcap2):
        builder2.add_packet(packet)
    connections2 = list(builder2.build_connections())

    # Behavioral matching with recommended config
    matcher = BehavioralMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
        match_mode=MatchMode.ONE_TO_ONE,
        weight_overlap=0.0,
        weight_duration=0.4,
        weight_iat=0.3,
        weight_bytes=0.3,
    )
    matches = matcher.match(connections1, connections2)

    scores = [m.score.normalized_score for m in matches] if matches else []
    return {
        "total1": len(connections1),
        "total2": len(connections2),
        "matched": len(matches),
        "avg_score": sum(scores) / len(scores) if scores else 0.0,
    }

def process_case(case_dir: Path) -> dict | None:
    """Process a single case."""
    pcaps = sorted(case_dir.glob("*.pcap"))
    if len(pcaps) != 2:
        return None
    
    try:
        auto_result = run_auto_mode(pcaps[0], pcaps[1])
        behavioral_result = run_behavioral_recommended(pcaps[0], pcaps[1])
        
        return {
            "case": case_dir.name,
            "auto": auto_result,
            "behavioral": behavioral_result,
        }
    except Exception as e:
        print(f"Error processing {case_dir.name}: {e}", file=sys.stderr)
        return None

def main() -> int:
    root_cases = Path("/Users/ricky/Downloads/2hops")
    if not root_cases.exists():
        print(f"Error: {root_cases} not found", file=sys.stderr)
        return 1
    
    cases = sorted([d for d in root_cases.iterdir() if d.is_dir()], key=lambda p: p.name)
    
    # Limit cases if specified
    max_cases = int(os.environ.get("MAX_CASES", "0"))
    if max_cases > 0:
        cases = cases[:max_cases]
    
    print(f"Validating recommended config on {len(cases)} cases...")
    print(f"Config: overlap=0%, duration=40%, iat=30%, bytes=30%")
    print()
    
    # Process cases in parallel
    max_workers = int(os.environ.get("PARALLEL", "4"))
    results = []
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_case, case_dir): case_dir for case_dir in cases}
        
        for i, future in enumerate(as_completed(futures), 1):
            case_dir = futures[future]
            print(f"[{i}/{len(cases)}] {case_dir.name}...", end=" ", flush=True)
            try:
                result = future.result()
                if result:
                    results.append(result)
                    print(f"✓ auto={result['auto']['matched']}, behavioral={result['behavioral']['matched']}")
                else:
                    print("✗ skipped")
            except Exception as e:
                print(f"✗ error: {e}")
    
    if not results:
        print("No valid results")
        return 0
    
    # Save detailed CSV
    output_dir = Path("eval_results/validation")
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "recommended_vs_auto.csv"
    
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "case",
            "auto_total1", "auto_total2", "auto_matched", "auto_rate1(%)", "auto_rate2(%)", "auto_avg_score",
            "behav_total1", "behav_total2", "behav_matched", "behav_rate1(%)", "behav_rate2(%)", "behav_avg_score",
            "delta_matched", "delta_rate1(%)", "delta_avg_score",
        ])

        for r in results:
            auto = r["auto"]
            behav = r["behavioral"]

            auto_rate1 = 100 * auto["matched"] / auto["total1"] if auto["total1"] > 0 else 0
            auto_rate2 = 100 * auto["matched"] / auto["total2"] if auto["total2"] > 0 else 0
            behav_rate1 = 100 * behav["matched"] / behav["total1"] if behav["total1"] > 0 else 0
            behav_rate2 = 100 * behav["matched"] / behav["total2"] if behav["total2"] > 0 else 0

            delta_matched = behav["matched"] - auto["matched"]
            delta_rate1 = behav_rate1 - auto_rate1
            delta_avg_score = behav["avg_score"] - auto["avg_score"]

            writer.writerow([
                r["case"],
                auto["total1"], auto["total2"], auto["matched"], f"{auto_rate1:.1f}", f"{auto_rate2:.1f}", f"{auto['avg_score']:.3f}",
                behav["total1"], behav["total2"], behav["matched"], f"{behav_rate1:.1f}", f"{behav_rate2:.1f}", f"{behav['avg_score']:.3f}",
                delta_matched, f"{delta_rate1:+.1f}", f"{delta_avg_score:+.3f}",
            ])

    print()
    print(f"Detailed results saved to: {csv_path}")
    print()

    # Print summary
    print("=" * 120)
    print("Summary: Recommended Behavioral Config vs Auto Mode")
    print("=" * 120)
    print()

    total_auto_matched = sum(r["auto"]["matched"] for r in results)
    total_behav_matched = sum(r["behavioral"]["matched"] for r in results)

    auto_scores = [r["auto"]["avg_score"] for r in results if r["auto"]["matched"] > 0]
    behav_scores = [r["behavioral"]["avg_score"] for r in results if r["behavioral"]["matched"] > 0]

    avg_auto_score = sum(auto_scores) / len(auto_scores) if auto_scores else 0.0
    avg_behav_score = sum(behav_scores) / len(behav_scores) if behav_scores else 0.0

    print(f"Total cases analyzed: {len(results)}")
    print()
    print(f"Total matches:")
    print(f"  Auto mode:        {total_auto_matched:6d}")
    print(f"  Behavioral (rec): {total_behav_matched:6d}")
    print(f"  Delta:            {total_behav_matched - total_auto_matched:+6d} ({100*(total_behav_matched - total_auto_matched)/total_auto_matched:+.1f}%)")
    print()
    print(f"Average score (across cases with matches):")
    print(f"  Auto mode:        {avg_auto_score:.3f}")
    print(f"  Behavioral (rec): {avg_behav_score:.3f}")
    print(f"  Delta:            {avg_behav_score - avg_auto_score:+.3f}")
    print()

    # Win/loss analysis
    behav_wins = sum(1 for r in results if r["behavioral"]["matched"] > r["auto"]["matched"])
    auto_wins = sum(1 for r in results if r["auto"]["matched"] > r["behavioral"]["matched"])
    ties = sum(1 for r in results if r["behavioral"]["matched"] == r["auto"]["matched"])

    print(f"Match count comparison:")
    print(f"  Behavioral wins:  {behav_wins:3d} ({100*behav_wins/len(results):.1f}%)")
    print(f"  Auto wins:        {auto_wins:3d} ({100*auto_wins/len(results):.1f}%)")
    print(f"  Ties:             {ties:3d} ({100*ties/len(results):.1f}%)")
    print()

    # Top improvements
    improvements = sorted(
        [(r["case"], r["behavioral"]["matched"] - r["auto"]["matched"]) for r in results],
        key=lambda x: x[1],
        reverse=True,
    )

    print("Top 10 improvements (behavioral - auto):")
    for i, (case, delta) in enumerate(improvements[:10], 1):
        print(f"  {i:2d}. {case:30s} {delta:+5d}")
    print()

    print("Top 10 regressions (behavioral - auto):")
    for i, (case, delta) in enumerate(reversed(improvements[-10:]), 1):
        print(f"  {i:2d}. {case:30s} {delta:+5d}")
    print()

    # Recommendation
    print("=" * 120)
    print("Recommendation")
    print("=" * 120)
    print()

    if total_behav_matched > total_auto_matched * 1.1:
        print("✓ 推荐配置显著优于 auto 模式（匹配数 >10% 提升）")
        print("  建议：将推荐配置设为 behavioral 模式的默认配置")
    elif total_behav_matched > total_auto_matched:
        print("✓ 推荐配置略优于 auto 模式")
        print("  建议：可作为 behavioral 模式的默认配置")
    else:
        print("⚠️  推荐配置未显著优于 auto 模式")
        print("  建议：需要进一步调优或针对特定场景使用")

    print()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())


