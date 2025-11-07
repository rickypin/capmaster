#!/usr/bin/env python3
"""Final test of the flow hash implementation."""

import sys
sys.path.insert(0, '/Users/ricky/Downloads/code/capmaster')

from capmaster.plugins.compare.flow_hash import (
    calculate_flow_hash,
    calculate_connection_flow_hash,
    format_flow_hash,
)


def test_reference_case():
    """Test against the reference implementation."""
    print("=" * 60)
    print("Test 1: Reference case from provided Python code")
    print("=" * 60)
    
    # Reference case
    ip1 = "8.67.2.125"
    ip2 = "8.42.96.45"
    port1 = 26302
    port2 = 35101
    
    hash_val, flow_side = calculate_flow_hash(ip1, ip2, port1, port2, 6)
    
    print(f"Input: {ip1}:{port1} -> {ip2}:{port2}")
    print(f"Flow hash: {hash_val}")
    print(f"Flow side: {flow_side}")
    print(f"Formatted: {format_flow_hash(hash_val, flow_side)}")
    print(f"Expected:  -1173584886679544929")
    print(f"Match: {'✓' if hash_val == -1173584886679544929 else '✗'}")
    print()


def test_connection_wrapper():
    """Test the connection wrapper function."""
    print("=" * 60)
    print("Test 2: Connection wrapper function")
    print("=" * 60)
    
    client_ip = "8.67.2.125"
    server_ip = "8.42.96.45"
    client_port = 26302
    server_port = 35101
    
    hash_val, flow_side = calculate_connection_flow_hash(
        client_ip, server_ip, client_port, server_port
    )
    
    print(f"Client: {client_ip}:{client_port}")
    print(f"Server: {server_ip}:{server_port}")
    print(f"Flow hash: {hash_val}")
    print(f"Flow side: {flow_side}")
    print(f"Formatted: {format_flow_hash(hash_val, flow_side)}")
    print()


def test_directionality():
    """Test that the hash is directional (not bidirectional)."""
    print("=" * 60)
    print("Test 3: Directionality (hash should differ for reverse)")
    print("=" * 60)
    
    test_cases = [
        ("8.67.2.125", "8.42.96.45", 26302, 35101),
        ("192.168.1.1", "10.0.0.1", 12345, 80),
        ("8.8.8.8", "1.1.1.1", 443, 54321),
    ]
    
    for ip1, ip2, port1, port2 in test_cases:
        hash_fwd, side_fwd = calculate_flow_hash(ip1, ip2, port1, port2, 6)
        hash_rev, side_rev = calculate_flow_hash(ip2, ip1, port2, port1, 6)
        
        print(f"{ip1}:{port1} -> {ip2}:{port2}")
        print(f"  Forward:  {hash_fwd:20d} (side={side_fwd})")
        print(f"  Reverse:  {hash_rev:20d} (side={side_rev})")
        print(f"  Different: {'✓' if hash_fwd != hash_rev else '✗ (should be different!)'}")
        print()


def test_multiple_cases():
    """Test multiple cases to ensure consistency."""
    print("=" * 60)
    print("Test 4: Multiple test cases")
    print("=" * 60)
    
    test_cases = [
        ("192.168.1.1", "10.0.0.1", 12345, 80, 6),
        ("10.0.0.1", "192.168.1.1", 80, 12345, 6),
        ("172.16.0.1", "172.16.0.2", 5000, 5001, 6),
        ("1.2.3.4", "5.6.7.8", 1234, 5678, 6),
    ]
    
    for ip1, ip2, port1, port2, proto in test_cases:
        hash_val, flow_side = calculate_flow_hash(ip1, ip2, port1, port2, proto)
        print(f"{ip1}:{port1} -> {ip2}:{port2}")
        print(f"  Hash: {hash_val}")
        print(f"  Side: {flow_side}")
        print()


if __name__ == "__main__":
    test_reference_case()
    test_connection_wrapper()
    test_directionality()
    test_multiple_cases()
    
    print("=" * 60)
    print("All tests completed!")
    print("=" * 60)

