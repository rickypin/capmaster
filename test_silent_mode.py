#!/usr/bin/env python3
"""Test script for the --silent parameter in compare plugin."""

import subprocess
import sys
from pathlib import Path


def run_command(cmd: list[str], description: str) -> tuple[int, str, str]:
    """Run a command and return exit code, stdout, and stderr."""
    print(f"\n{'='*80}")
    print(f"Test: {description}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'='*80}")
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )
    
    print(f"Exit code: {result.returncode}")
    print(f"Stdout length: {len(result.stdout)} chars")
    print(f"Stderr length: {len(result.stderr)} chars")
    
    if result.stdout:
        print(f"\nStdout preview (first 500 chars):")
        print(result.stdout[:500])
    
    if result.stderr:
        print(f"\nStderr preview (first 500 chars):")
        print(result.stderr[:500])
    
    return result.returncode, result.stdout, result.stderr


def main():
    """Run tests for silent mode."""
    
    # Check if test PCAP files exist
    test_dir = Path("test_data")
    if not test_dir.exists():
        print(f"Error: Test directory {test_dir} does not exist")
        print("Please create test PCAP files first")
        return 1
    
    pcap_files = list(test_dir.glob("*.pcap"))
    if len(pcap_files) < 2:
        print(f"Error: Need at least 2 PCAP files in {test_dir}")
        print(f"Found: {pcap_files}")
        return 1
    
    file1 = pcap_files[0]
    file2 = pcap_files[1]
    
    print(f"Using test files:")
    print(f"  File 1: {file1}")
    print(f"  File 2: {file2}")
    
    # Test 1: Normal mode (with output)
    exit_code, stdout, stderr = run_command(
        [
            "capmaster", "compare",
            "--file1", str(file1),
            "--file1-pcapid", "0",
            "--file2", str(file2),
            "--file2-pcapid", "1",
        ],
        "Normal mode - should show progress bars and output"
    )
    
    if exit_code != 0:
        print(f"❌ Test 1 failed with exit code {exit_code}")
    else:
        if len(stdout) > 0:
            print("✅ Test 1 passed - output generated")
        else:
            print("⚠️  Test 1 warning - no stdout (might be expected)")
    
    # Test 2: Silent mode (no screen output)
    exit_code, stdout, stderr = run_command(
        [
            "capmaster", "compare",
            "--file1", str(file1),
            "--file1-pcapid", "0",
            "--file2", str(file2),
            "--file2-pcapid", "1",
            "--silent",
        ],
        "Silent mode - should suppress progress bars and screen output"
    )
    
    if exit_code != 0:
        print(f"❌ Test 2 failed with exit code {exit_code}")
    else:
        if len(stdout) == 0:
            print("✅ Test 2 passed - no stdout in silent mode")
        else:
            print(f"❌ Test 2 failed - stdout should be empty but got {len(stdout)} chars")
    
    # Test 3: Silent mode with output file
    output_file = Path("test_output.txt")
    if output_file.exists():
        output_file.unlink()
    
    exit_code, stdout, stderr = run_command(
        [
            "capmaster", "compare",
            "--file1", str(file1),
            "--file1-pcapid", "0",
            "--file2", str(file2),
            "--file2-pcapid", "1",
            "--silent",
            "-o", str(output_file),
        ],
        "Silent mode with output file - should write to file, no screen output"
    )
    
    if exit_code != 0:
        print(f"❌ Test 3 failed with exit code {exit_code}")
    else:
        if output_file.exists():
            file_size = output_file.stat().st_size
            print(f"✅ Test 3 passed - output file created ({file_size} bytes)")
            if len(stdout) == 0:
                print("✅ Test 3 passed - no stdout in silent mode with file output")
            else:
                print(f"❌ Test 3 failed - stdout should be empty but got {len(stdout)} chars")
        else:
            print("❌ Test 3 failed - output file not created")
    
    # Cleanup
    if output_file.exists():
        output_file.unlink()
        print(f"\nCleaned up: {output_file}")
    
    print("\n" + "="*80)
    print("Test Summary:")
    print("  Test 1: Normal mode with output")
    print("  Test 2: Silent mode (no output)")
    print("  Test 3: Silent mode with file output")
    print("="*80)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

