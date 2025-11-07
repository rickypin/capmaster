#!/usr/bin/env python3
"""Test the integrated flow hash implementation."""

import sys
sys.path.insert(0, '/Users/ricky/Downloads/code/capmaster')

from capmaster.plugins.compare.flow_hash import calculate_flow_hash, format_flow_hash


def test_flow_hash():
    """Test flow hash calculation with the example from the reference code."""
    
    # Test case from the provided Python code
    port1 = 26302
    port2 = 35101
    ip1 = "8.67.2.125"
    ip2 = "8.42.96.45"
    proto = 6

    hash_val, flow_side = calculate_flow_hash(ip1, ip2, port1, port2, proto)
    
    print(f"Test case: {ip1}:{port1} <-> {ip2}:{port2}")
    print(f"Flow hash: {hash_val}")
    print(f"Flow side: {flow_side}")
    print(f"Formatted: {format_flow_hash(hash_val, flow_side)}")
    print(f"Expected: -1173584886679544929")
    print(f"Match: {hash_val == -1173584886679544929}")
    print()

    # Test bidirectional consistency
    hash_val2, flow_side2 = calculate_flow_hash(ip2, ip1, port2, port1, proto)
    print(f"Reverse: {ip2}:{port2} <-> {ip1}:{port1}")
    print(f"Flow hash: {hash_val2}")
    print(f"Flow side: {flow_side2}")
    print(f"Bidirectional match: {hash_val == hash_val2}")
    print()

    # Additional test cases
    test_cases = [
        ("192.168.1.1", "10.0.0.1", 12345, 80, 6),
        ("10.0.0.1", "192.168.1.1", 80, 12345, 6),
        ("8.8.8.8", "1.1.1.1", 443, 54321, 6),
    ]
    
    print("Additional test cases:")
    for ip1, ip2, port1, port2, proto in test_cases:
        hash_val, flow_side = calculate_flow_hash(ip1, ip2, port1, port2, proto)
        hash_val_rev, flow_side_rev = calculate_flow_hash(ip2, ip1, port2, port1, proto)
        
        print(f"{ip1}:{port1} <-> {ip2}:{port2}")
        print(f"  Hash: {hash_val}, Side: {flow_side}")
        print(f"  Reverse hash: {hash_val_rev}, Side: {flow_side_rev}")
        print(f"  Bidirectional: {hash_val == hash_val_rev}")
        print()


if __name__ == "__main__":
    test_flow_hash()

