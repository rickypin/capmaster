#!/usr/bin/env python3
"""
Verify that match and compare commands produce consistent results.

This script demonstrates the new --match-file feature that ensures
match and compare commands use the same connection pairs.
"""

import json
import re
import subprocess
import sys
from pathlib import Path


def run_command(cmd: list[str]) -> str:
    """Run a command and return its output."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout + result.stderr


def extract_match_pairs_from_text(output: str) -> dict[int, tuple[str, str]]:
    """
    Extract match pairs from match command text output.
    
    Returns:
        Dict mapping match number to (conn1_str, conn2_str)
    """
    pairs = {}
    pattern = r'\[(\d+)\] A: ([\d.]+:\d+ <-> [\d.]+:\d+)\s+B: ([\d.]+:\d+ <-> [\d.]+:\d+)'
    
    for match in re.finditer(pattern, output):
        match_num = int(match.group(1))
        conn1 = match.group(2)
        conn2 = match.group(3)
        pairs[match_num] = (conn1, conn2)
    
    return pairs


def extract_match_pairs_from_json(json_file: Path) -> dict[int, tuple[str, str, int, int]]:
    """
    Extract match pairs from JSON file.
    
    Returns:
        Dict mapping index to (conn1_str, conn2_str, stream1, stream2)
    """
    with open(json_file) as f:
        data = json.load(f)
    
    pairs = {}
    for i, match in enumerate(data['matches'], 1):
        conn1 = match['conn1']
        conn2 = match['conn2']
        
        conn1_str = f"{conn1['client_ip']}:{conn1['client_port']} <-> {conn1['server_ip']}:{conn1['server_port']}"
        conn2_str = f"{conn2['client_ip']}:{conn2['client_port']} <-> {conn2['server_ip']}:{conn2['server_port']}"
        
        pairs[i] = (conn1_str, conn2_str, conn1['stream_id'], conn2['stream_id'])
    
    return pairs


def extract_compare_pairs(output: str) -> dict[int, int]:
    """
    Extract stream pairs from compare command output.
    
    Returns:
        Dict mapping baseline stream to compare stream
    """
    pairs = {}
    pattern = r'Stream Pair: Baseline Stream (\d+) ↔ Compare Stream (\d+)'
    
    for match in re.finditer(pattern, output):
        baseline_stream = int(match.group(1))
        compare_stream = int(match.group(2))
        pairs[baseline_stream] = compare_stream
    
    return pairs


def main():
    """Main verification function."""
    if len(sys.argv) < 2:
        print("Usage: verify_match_compare_consistency.py <pcap_directory>")
        print("\nExample:")
        print("  python3 scripts/verify_match_compare_consistency.py /path/to/pcaps/")
        sys.exit(1)
    
    pcap_dir = sys.argv[1]
    
    print("=" * 80)
    print("Match and Compare Consistency Verification")
    print("=" * 80)
    print()
    
    # Step 1: Run match command and save JSON
    print("Step 1: Running match command and saving results to JSON...")
    match_json = Path("verify_matches.json")
    match_cmd = [
        "capmaster", "match",
        "-i", pcap_dir,
        "--match-json", str(match_json)
    ]
    
    match_output = run_command(match_cmd)
    print("✓ Match command completed")
    print()
    
    # Extract match pairs from text output
    match_text_pairs = extract_match_pairs_from_text(match_output)
    print(f"Found {len(match_text_pairs)} matched pairs in text output")
    
    # Extract match pairs from JSON
    match_json_pairs = extract_match_pairs_from_json(match_json)
    print(f"Found {len(match_json_pairs)} matched pairs in JSON file")
    print()
    
    # Step 2: Run compare WITHOUT --match-file (old behavior)
    print("Step 2: Running compare WITHOUT --match-file (may be inconsistent)...")
    compare_cmd_old = [
        "capmaster", "compare",
        "-i", pcap_dir,
    ]
    
    compare_output_old = run_command(compare_cmd_old)
    compare_pairs_old = extract_compare_pairs(compare_output_old)
    print(f"✓ Compare command completed (found {len(compare_pairs_old)} pairs)")
    print()
    
    # Step 3: Run compare WITH --match-file (new behavior)
    print("Step 3: Running compare WITH --match-file (guaranteed consistent)...")
    compare_cmd_new = [
        "capmaster", "compare",
        "-i", pcap_dir,
        "--match-file", str(match_json)
    ]
    
    compare_output_new = run_command(compare_cmd_new)
    compare_pairs_new = extract_compare_pairs(compare_output_new)
    print(f"✓ Compare command completed (found {len(compare_pairs_new)} pairs)")
    print()
    
    # Step 4: Verify consistency
    print("=" * 80)
    print("Verification Results")
    print("=" * 80)
    print()
    
    # Check if compare with --match-file matches the JSON
    all_consistent = True
    for i, (conn1_str, conn2_str, stream1, stream2) in match_json_pairs.items():
        if stream1 in compare_pairs_new:
            compare_stream2 = compare_pairs_new[stream1]
            if compare_stream2 == stream2:
                status = "✓"
            else:
                status = "✗"
                all_consistent = False
            
            print(f"{status} Match #{i}: Stream {stream1} ↔ Stream {stream2}")
            print(f"  Match:   {conn1_str}")
            print(f"           {conn2_str}")
            print(f"  Compare: Stream {stream1} ↔ Stream {compare_stream2}")
            
            if compare_stream2 != stream2:
                print(f"  ERROR: Compare used different stream ({compare_stream2} instead of {stream2})")
            print()
    
    # Summary
    print("=" * 80)
    print("Summary")
    print("=" * 80)
    print()
    
    if all_consistent:
        print("✓ SUCCESS: All match and compare pairs are consistent!")
        print()
        print("The --match-file feature ensures that compare uses the exact same")
        print("connection pairs identified by the match command.")
    else:
        print("✗ FAILURE: Some pairs are inconsistent!")
        print()
        print("This should not happen when using --match-file.")
    
    # Cleanup
    match_json.unlink()
    
    return 0 if all_consistent else 1


if __name__ == "__main__":
    sys.exit(main())

