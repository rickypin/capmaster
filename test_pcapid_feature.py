#!/usr/bin/env python3
"""
Test script for the new pcap_id feature in compare plugin.

This script tests the new --file1/--file2 with --file1-pcapid/--file2-pcapid parameters.
"""

import subprocess
import sys
from pathlib import Path


def test_new_pcapid_parameters():
    """Test the new pcap_id parameters."""
    print("=" * 80)
    print("Testing new pcap_id feature for compare plugin")
    print("=" * 80)
    
    # Test files
    file1 = Path("cases/TC-001-1-20160407/TC-001-1-20160407-A.pcap")
    file2 = Path("cases/TC-001-1-20160407/TC-001-1-20160407-B.pcap")
    
    if not file1.exists():
        print(f"❌ Test file not found: {file1}")
        return False
    
    if not file2.exists():
        print(f"❌ Test file not found: {file2}")
        return False
    
    print(f"\n✓ Test files found:")
    print(f"  - file1: {file1}")
    print(f"  - file2: {file2}")
    
    # Test 1: file1 with pcap_id=0, file2 with pcap_id=1
    print("\n" + "=" * 80)
    print("Test 1: --file1 A.pcap --file1-pcapid 0 --file2 B.pcap --file2-pcapid 1")
    print("=" * 80)
    
    cmd1 = [
        "python", "-m", "capmaster",
        "compare",
        "--file1", str(file1),
        "--file1-pcapid", "0",
        "--file2", str(file2),
        "--file2-pcapid", "1",
        "--show-flow-hash",
    ]
    
    print(f"\nCommand: {' '.join(cmd1)}")
    result1 = subprocess.run(cmd1, capture_output=True, text=True)
    
    if result1.returncode == 0:
        print("✓ Test 1 passed - command executed successfully")
        print("\nOutput preview (first 20 lines):")
        lines = result1.stdout.split('\n')[:20]
        for line in lines:
            print(f"  {line}")
    else:
        print(f"❌ Test 1 failed - exit code: {result1.returncode}")
        print(f"Error: {result1.stderr}")
        return False
    
    # Test 2: file1 with pcap_id=1, file2 with pcap_id=0 (reversed)
    print("\n" + "=" * 80)
    print("Test 2: --file1 B.pcap --file1-pcapid 1 --file2 A.pcap --file2-pcapid 0")
    print("=" * 80)
    
    cmd2 = [
        "python", "-m", "capmaster",
        "compare",
        "--file1", str(file2),
        "--file1-pcapid", "1",
        "--file2", str(file1),
        "--file2-pcapid", "0",
        "--show-flow-hash",
    ]
    
    print(f"\nCommand: {' '.join(cmd2)}")
    result2 = subprocess.run(cmd2, capture_output=True, text=True)
    
    if result2.returncode == 0:
        print("✓ Test 2 passed - command executed successfully")
        print("\nOutput preview (first 20 lines):")
        lines = result2.stdout.split('\n')[:20]
        for line in lines:
            print(f"  {line}")
    else:
        print(f"❌ Test 2 failed - exit code: {result2.returncode}")
        print(f"Error: {result2.stderr}")
        return False
    
    # Test 3: Verify that legacy -i parameter still works
    print("\n" + "=" * 80)
    print("Test 3: Legacy -i parameter (backward compatibility)")
    print("=" * 80)
    
    cmd3 = [
        "python", "-m", "capmaster",
        "compare",
        "-i", f"{file1},{file2}",
        "--show-flow-hash",
    ]
    
    print(f"\nCommand: {' '.join(cmd3)}")
    result3 = subprocess.run(cmd3, capture_output=True, text=True)
    
    if result3.returncode == 0:
        print("✓ Test 3 passed - legacy parameter still works")
        print("\nOutput preview (first 20 lines):")
        lines = result3.stdout.split('\n')[:20]
        for line in lines:
            print(f"  {line}")
    else:
        print(f"❌ Test 3 failed - exit code: {result3.returncode}")
        print(f"Error: {result3.stderr}")
        return False
    
    # Test 4: Verify parameter validation (should fail)
    print("\n" + "=" * 80)
    print("Test 4: Parameter validation (should fail - missing pcapid)")
    print("=" * 80)
    
    cmd4 = [
        "python", "-m", "capmaster",
        "compare",
        "--file1", str(file1),
        "--file2", str(file2),
        "--show-flow-hash",
    ]
    
    print(f"\nCommand: {' '.join(cmd4)}")
    result4 = subprocess.run(cmd4, capture_output=True, text=True)
    
    if result4.returncode != 0:
        print("✓ Test 4 passed - validation correctly rejected missing pcapid")
        print(f"Expected error: {result4.stderr.strip()}")
    else:
        print("❌ Test 4 failed - should have rejected missing pcapid")
        return False
    
    # Test 5: Verify parameter validation (should fail - invalid pcapid)
    print("\n" + "=" * 80)
    print("Test 5: Parameter validation (should fail - invalid pcapid value)")
    print("=" * 80)
    
    cmd5 = [
        "python", "-m", "capmaster",
        "compare",
        "--file1", str(file1),
        "--file1-pcapid", "2",  # Invalid: must be 0 or 1
        "--file2", str(file2),
        "--file2-pcapid", "0",
        "--show-flow-hash",
    ]
    
    print(f"\nCommand: {' '.join(cmd5)}")
    result5 = subprocess.run(cmd5, capture_output=True, text=True)
    
    if result5.returncode != 0:
        print("✓ Test 5 passed - validation correctly rejected invalid pcapid")
        print(f"Expected error: {result5.stderr.strip()}")
    else:
        print("❌ Test 5 failed - should have rejected invalid pcapid")
        return False
    
    print("\n" + "=" * 80)
    print("All tests passed! ✓")
    print("=" * 80)
    return True


def test_database_integration():
    """Test database integration with pcap_id (requires database access)."""
    print("\n" + "=" * 80)
    print("Database Integration Test (Optional)")
    print("=" * 80)
    print("\nTo test database integration, run:")
    print("\npython -m capmaster compare \\")
    print("  --file1 cases/TC-001-1-20160407/TC-001-1-20160407-A.pcap \\")
    print("  --file1-pcapid 0 \\")
    print("  --file2 cases/TC-001-1-20160407/TC-001-1-20160407-B.pcap \\")
    print("  --file2-pcapid 1 \\")
    print("  --show-flow-hash \\")
    print("  --db-connection 'postgresql://user:pass@host:port/db' \\")
    print("  --kase-id 133")
    print("\nThen verify in database:")
    print("SELECT pcap_id, flow_hash, first_time, last_time, tcp_flags_different_cnt FROM public.kase_133_tcp_stream_extra ORDER BY id DESC LIMIT 5;")
    print("\nExpected output:")
    print("- pcap_id should be 0 (from file1)")
    print("- first_time and last_time should be nanosecond timestamps (e.g., 1459996923372072960)")
    print("- flow_hash should be a signed 64-bit integer")
    print("- tcp_flags_different_cnt should be the count of TCP flags differences")


if __name__ == "__main__":
    success = test_new_pcapid_parameters()
    test_database_integration()
    
    sys.exit(0 if success else 1)

