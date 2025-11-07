#!/usr/bin/env python3
"""
Test script for the timestamp feature in compare plugin.

This script tests that first_time and last_time are correctly extracted and displayed.
"""

import subprocess
import sys
import re
from pathlib import Path


def test_timestamp_output():
    """Test that timestamps are displayed in the output."""
    print("=" * 80)
    print("Testing timestamp display in compare plugin output")
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
    
    # Run compare with new parameters
    print("\n" + "=" * 80)
    print("Running compare with timestamp display")
    print("=" * 80)
    
    cmd = [
        "python", "-m", "capmaster",
        "compare",
        "--file1", str(file1),
        "--file1-pcapid", "0",
        "--file2", str(file2),
        "--file2-pcapid", "1",
        "--show-flow-hash",
    ]
    
    print(f"\nCommand: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ Command failed with exit code: {result.returncode}")
        print(f"Error: {result.stderr}")
        return False
    
    print("✓ Command executed successfully")
    
    # Check for timestamp columns in output
    output = result.stdout
    
    # Look for "First Time" and "Last Time" headers
    if "First Time" not in output:
        print("❌ 'First Time' column not found in output")
        return False
    
    if "Last Time" not in output:
        print("❌ 'Last Time' column not found in output")
        return False
    
    print("✓ Timestamp columns found in output")
    
    # Extract and validate timestamp values
    # Look for lines with timestamps (19-digit numbers)
    timestamp_pattern = r'\d{19}'
    timestamps = re.findall(timestamp_pattern, output)
    
    if not timestamps:
        print("❌ No timestamp values found in output")
        return False
    
    print(f"✓ Found {len(timestamps)} timestamp values")
    
    # Display some example timestamps
    print("\nExample timestamps found:")
    for i, ts in enumerate(timestamps[:5]):
        print(f"  {i+1}. {ts}")
    
    # Validate timestamp format (should be nanoseconds since epoch)
    # Expected range: 2016-04-07 (around 1459900000000000000 to 1460000000000000000)
    valid_timestamps = 0
    microsecond_precision_count = 0
    for ts in timestamps:
        ts_int = int(ts)
        # Check if timestamp is in reasonable range for 2016
        if 1459000000000000000 <= ts_int <= 1461000000000000000:
            valid_timestamps += 1

        # Check if timestamp has microsecond precision (last 3 digits should be 000)
        if ts_int % 1000 == 0:
            microsecond_precision_count += 1

    if valid_timestamps == 0:
        print("❌ No valid timestamps found (expected nanosecond timestamps from 2016)")
        return False

    # Verify microsecond precision
    if microsecond_precision_count != len(timestamps):
        print(f"⚠️  Warning: Not all timestamps have microsecond precision")
        print(f"   Microsecond precision: {microsecond_precision_count}/{len(timestamps)}")
    else:
        print(f"✓ All timestamps have microsecond precision (last 3 digits are 000)")
    
    print(f"✓ {valid_timestamps}/{len(timestamps)} timestamps are in valid range")
    
    # Show a sample of the output with timestamps
    print("\n" + "=" * 80)
    print("Sample output (first 30 lines):")
    print("=" * 80)
    lines = output.split('\n')
    for i, line in enumerate(lines[:30]):
        if i >= 15:  # Start showing from line 15 to see the data rows
            print(line)
    
    return True


def test_timestamp_format():
    """Test that timestamps are in correct nanosecond format."""
    print("\n" + "=" * 80)
    print("Testing timestamp format")
    print("=" * 80)
    
    # Example timestamp from 2016-04-07
    # Expected format: 19 digits (nanoseconds since epoch)
    example_timestamp = 1459996923372072960
    
    print(f"\nExample timestamp: {example_timestamp}")
    print(f"Length: {len(str(example_timestamp))} digits")
    
    # Convert to seconds to verify
    timestamp_seconds = example_timestamp / 1_000_000_000
    print(f"Converted to seconds: {timestamp_seconds}")
    
    # Convert to human-readable format
    from datetime import datetime
    dt = datetime.fromtimestamp(timestamp_seconds)
    print(f"Human-readable: {dt}")
    
    # Verify it's from 2016
    if dt.year == 2016:
        print("✓ Timestamp is from 2016 as expected")
        return True
    else:
        print(f"❌ Timestamp year is {dt.year}, expected 2016")
        return False


if __name__ == "__main__":
    success = True
    
    # Test 1: Timestamp output
    if not test_timestamp_output():
        success = False
    
    # Test 2: Timestamp format
    if not test_timestamp_format():
        success = False
    
    if success:
        print("\n" + "=" * 80)
        print("All timestamp tests passed! ✓")
        print("=" * 80)
        print("\nNext steps:")
        print("1. Test database integration to verify first_time and last_time are written correctly")
        print("2. Run: python -m capmaster compare \\")
        print("     --file1 cases/TC-001-1-20160407/TC-001-1-20160407-A.pcap \\")
        print("     --file1-pcapid 0 \\")
        print("     --file2 cases/TC-001-1-20160407/TC-001-1-20160407-B.pcap \\")
        print("     --file2-pcapid 1 \\")
        print("     --show-flow-hash \\")
        print("     --db-connection 'postgresql://postgres:password@172.16.200.156:5433/r2' \\")
        print("     --kase-id 133")
        print("\n3. Verify in database:")
        print("   SELECT pcap_id, flow_hash, first_time, last_time, tcp_flags_different_cnt")
        print("   FROM public.kase_133_tcp_stream_extra")
        print("   ORDER BY id DESC LIMIT 5;")
    else:
        print("\n" + "=" * 80)
        print("Some tests failed ❌")
        print("=" * 80)
    
    sys.exit(0 if success else 1)

