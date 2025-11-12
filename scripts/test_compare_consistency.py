#!/usr/bin/env python3
"""
Test that compare plugin produces consistent results with both methods:
1. Using --match-file (reading from file)
2. Using in-memory matching (calling match plugin's match_connections_in_memory)

This script verifies that the refactoring to use match plugin's logic
produces the same results as before.
"""

import json
import subprocess
import sys
from pathlib import Path


def run_command(cmd: list[str]) -> tuple[str, int]:
    """Run a command and return its output and exit code."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout + result.stderr, result.returncode


def extract_stream_pairs_from_output(output: str) -> set[tuple[int, int]]:
    """
    Extract stream pairs from compare command output.
    
    Returns:
        Set of (baseline_stream, compare_stream) tuples
    """
    import re
    pairs = set()
    pattern = r'Stream Pair: Baseline Stream (\d+) ↔ Compare Stream (\d+)'
    
    for match in re.finditer(pattern, output):
        baseline_stream = int(match.group(1))
        compare_stream = int(match.group(2))
        pairs.add((baseline_stream, compare_stream))
    
    return pairs


def main():
    """Main test function."""
    if len(sys.argv) < 2:
        print("Usage: test_compare_consistency.py <pcap_directory>")
        print("\nExample:")
        print("  python3 scripts/test_compare_consistency.py /Users/ricky/Downloads/2hops/aomenjinguanju/")
        sys.exit(1)
    
    pcap_dir = sys.argv[1]
    
    print("=" * 80)
    print("Compare Plugin Consistency Test")
    print("=" * 80)
    print()
    print(f"Testing with: {pcap_dir}")
    print()
    
    # Step 1: Run match command and save JSON
    print("Step 1: Running match command and saving results to JSON...")
    match_json = Path("test_matches.json")
    match_cmd = [
        "capmaster", "match",
        "-i", pcap_dir,
        "--match-mode", "one-to-many",
        "--match-json", str(match_json)
    ]
    
    match_output, match_exit = run_command(match_cmd)
    if match_exit != 0:
        print(f"✗ Match command failed with exit code {match_exit}")
        print(match_output)
        return 1
    
    print("✓ Match command completed")
    
    # Count matches in JSON
    with open(match_json) as f:
        match_data = json.load(f)
    match_count = len(match_data['matches'])
    print(f"  Found {match_count} matched pairs")
    print()
    
    # Step 2: Run compare WITH --match-file (method 1: reading from file)
    print("Step 2: Running compare WITH --match-file (method 1)...")
    compare_cmd_file = [
        "capmaster", "compare",
        "-i", pcap_dir,
        "--show-flow-hash",
        "--matched-only",
        "--match-mode", "one-to-many",
        "--match-file", str(match_json)
    ]
    
    compare_output_file, compare_exit_file = run_command(compare_cmd_file)
    if compare_exit_file != 0:
        print(f"✗ Compare command (with --match-file) failed with exit code {compare_exit_file}")
        print(compare_output_file)
        return 1
    
    pairs_from_file = extract_stream_pairs_from_output(compare_output_file)
    print(f"✓ Compare command completed (method 1)")
    print(f"  Found {len(pairs_from_file)} stream pairs")
    print()
    
    # Step 3: Run compare WITHOUT --match-file (method 2: in-memory matching)
    print("Step 3: Running compare WITHOUT --match-file (method 2)...")
    compare_cmd_memory = [
        "capmaster", "compare",
        "-i", pcap_dir,
        "--show-flow-hash",
        "--matched-only",
        "--match-mode", "one-to-many"
    ]
    
    compare_output_memory, compare_exit_memory = run_command(compare_cmd_memory)
    if compare_exit_memory != 0:
        print(f"✗ Compare command (without --match-file) failed with exit code {compare_exit_memory}")
        print(compare_output_memory)
        return 1
    
    pairs_from_memory = extract_stream_pairs_from_output(compare_output_memory)
    print(f"✓ Compare command completed (method 2)")
    print(f"  Found {len(pairs_from_memory)} stream pairs")
    print()
    
    # Step 4: Compare results
    print("=" * 80)
    print("Verification Results")
    print("=" * 80)
    print()
    
    print(f"Method 1 (--match-file):     {len(pairs_from_file)} pairs")
    print(f"Method 2 (in-memory):        {len(pairs_from_memory)} pairs")
    print(f"Match command:               {match_count} pairs")
    print()
    
    # Check if counts match
    if len(pairs_from_file) == len(pairs_from_memory) == match_count:
        print("✓ Pair counts are consistent!")
    else:
        print("✗ Pair counts are INCONSISTENT!")
        print()
        print("This indicates that the two methods are producing different results.")
        return 1
    
    # Check if the actual pairs match
    if pairs_from_file == pairs_from_memory:
        print("✓ Stream pairs are IDENTICAL!")
        print()
        print("SUCCESS: Both methods produce the same results!")
        print("The refactoring is working correctly.")
    else:
        print("✗ Stream pairs are DIFFERENT!")
        print()
        
        # Show differences
        only_in_file = pairs_from_file - pairs_from_memory
        only_in_memory = pairs_from_memory - pairs_from_file
        
        if only_in_file:
            print(f"Pairs only in method 1 (--match-file): {len(only_in_file)}")
            for baseline, compare in sorted(only_in_file)[:5]:
                print(f"  Stream {baseline} ↔ Stream {compare}")
            if len(only_in_file) > 5:
                print(f"  ... and {len(only_in_file) - 5} more")
            print()
        
        if only_in_memory:
            print(f"Pairs only in method 2 (in-memory): {len(only_in_memory)}")
            for baseline, compare in sorted(only_in_memory)[:5]:
                print(f"  Stream {baseline} ↔ Stream {compare}")
            if len(only_in_memory) > 5:
                print(f"  ... and {len(only_in_memory) - 5} more")
            print()
        
        print("FAILURE: The two methods produce different results!")
        return 1
    
    # Cleanup
    match_json.unlink()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

