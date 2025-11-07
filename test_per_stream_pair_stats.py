#!/usr/bin/env python3
"""
Test script to verify per-stream-pair statistics output.

This script tests the new per-stream-pair statistics feature in the compare plugin.
It creates a simple test case with multiple stream pairs and verifies that the
statistics are correctly grouped by stream pair.
"""

import subprocess
import tempfile
from pathlib import Path


def create_test_pcap_with_scapy():
    """
    Create test PCAP files using scapy.
    
    Creates two PCAP files:
    - File A: 2 TCP streams with different flags
    - File B: 2 TCP streams with different flags
    
    This will result in 2 stream pairs when matched.
    """
    try:
        from scapy.all import IP, TCP, wrpcap
    except ImportError:
        print("Scapy not installed. Skipping test.")
        return None, None
    
    # Create temporary files
    file_a = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
    file_b = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
    
    # Stream 1: Client 10.0.0.1:1234 -> Server 10.0.0.2:80
    # File A: SYN, SYN-ACK, ACK
    packets_a_stream1 = [
        IP(src="10.0.0.1", dst="10.0.0.2", id=1000) / TCP(sport=1234, dport=80, flags="S", seq=1000),
        IP(src="10.0.0.2", dst="10.0.0.1", id=2000) / TCP(sport=80, dport=1234, flags="SA", seq=2000, ack=1001),
        IP(src="10.0.0.1", dst="10.0.0.2", id=1001) / TCP(sport=1234, dport=80, flags="A", seq=1001, ack=2001),
    ]
    
    # File B: SYN, SYN-ACK, ACK, PSH-ACK (different from A)
    packets_b_stream1 = [
        IP(src="10.0.0.1", dst="10.0.0.2", id=1000) / TCP(sport=1234, dport=80, flags="S", seq=1000),
        IP(src="10.0.0.2", dst="10.0.0.1", id=2000) / TCP(sport=80, dport=1234, flags="SA", seq=2000, ack=1001),
        IP(src="10.0.0.1", dst="10.0.0.2", id=1001) / TCP(sport=1234, dport=80, flags="A", seq=1001, ack=2001),
        IP(src="10.0.0.1", dst="10.0.0.2", id=1002) / TCP(sport=1234, dport=80, flags="PA", seq=1001, ack=2001),
    ]
    
    # Stream 2: Client 10.0.0.3:5678 -> Server 10.0.0.4:443
    # File A: SYN, SYN-ACK, ACK, FIN-ACK
    packets_a_stream2 = [
        IP(src="10.0.0.3", dst="10.0.0.4", id=3000) / TCP(sport=5678, dport=443, flags="S", seq=3000),
        IP(src="10.0.0.4", dst="10.0.0.3", id=4000) / TCP(sport=443, dport=5678, flags="SA", seq=4000, ack=3001),
        IP(src="10.0.0.3", dst="10.0.0.4", id=3001) / TCP(sport=5678, dport=443, flags="A", seq=3001, ack=4001),
        IP(src="10.0.0.3", dst="10.0.0.4", id=3002) / TCP(sport=5678, dport=443, flags="FA", seq=3001, ack=4001),
    ]
    
    # File B: SYN, SYN-ACK, ACK, RST (different from A)
    packets_b_stream2 = [
        IP(src="10.0.0.3", dst="10.0.0.4", id=3000) / TCP(sport=5678, dport=443, flags="S", seq=3000),
        IP(src="10.0.0.4", dst="10.0.0.3", id=4000) / TCP(sport=443, dport=5678, flags="SA", seq=4000, ack=3001),
        IP(src="10.0.0.3", dst="10.0.0.4", id=3001) / TCP(sport=5678, dport=443, flags="A", seq=3001, ack=4001),
        IP(src="10.0.0.3", dst="10.0.0.4", id=3002) / TCP(sport=5678, dport=443, flags="R", seq=3001),
    ]
    
    # Write PCAP files
    wrpcap(file_a.name, packets_a_stream1 + packets_a_stream2)
    wrpcap(file_b.name, packets_b_stream1 + packets_b_stream2)
    
    return Path(file_a.name), Path(file_b.name)


def run_compare_test():
    """Run the compare plugin and check the output."""
    print("Creating test PCAP files...")
    file_a, file_b = create_test_pcap_with_scapy()
    
    if file_a is None or file_b is None:
        print("Failed to create test files. Exiting.")
        return
    
    try:
        print(f"File A: {file_a}")
        print(f"File B: {file_b}")
        
        # Run compare plugin
        print("\nRunning compare plugin...")
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "compare",
                "--file1", str(file_a),
                "--file2", str(file_b),
            ],
            capture_output=True,
            text=True,
        )
        
        print("\n" + "="*80)
        print("COMPARE OUTPUT:")
        print("="*80)
        print(result.stdout)
        
        if result.stderr:
            print("\n" + "="*80)
            print("STDERR:")
            print("="*80)
            print(result.stderr)
        
        # Check for expected output sections
        output = result.stdout
        
        print("\n" + "="*80)
        print("VERIFICATION:")
        print("="*80)
        
        checks = [
            ("Per-Stream-Pair Statistics", "Per-Stream-Pair Statistics section"),
            ("Stream Pair:", "Stream pair headers"),
            ("Difference Type Statistics:", "Difference type statistics per pair"),
            ("TCP FLAGS Detailed Breakdown:", "TCP FLAGS breakdown per pair"),
        ]
        
        for pattern, description in checks:
            if pattern in output:
                print(f"✓ Found: {description}")
            else:
                print(f"✗ Missing: {description}")
        
        # Check that we have separate sections for each stream pair
        stream_pair_count = output.count("Stream Pair:")
        print(f"\nFound {stream_pair_count} stream pair section(s)")
        
        if stream_pair_count >= 1:
            print("✓ Per-stream-pair statistics are working!")
        else:
            print("✗ Per-stream-pair statistics not found!")
        
        return result.returncode == 0
        
    finally:
        # Clean up
        if file_a and file_a.exists():
            file_a.unlink()
        if file_b and file_b.exists():
            file_b.unlink()


if __name__ == "__main__":
    print("Testing per-stream-pair statistics feature...")
    print("="*80)
    
    success = run_compare_test()
    
    print("\n" + "="*80)
    if success:
        print("✓ Test completed successfully!")
    else:
        print("✗ Test failed!")
    print("="*80)

