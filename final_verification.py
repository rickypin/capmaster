#!/usr/bin/env python3
"""
Final comprehensive verification of the flow hash implementation.

This script verifies:
1. Correctness against the reference value
2. Bidirectional consistency
3. Multiple test cases
"""

import sys
sys.path.insert(0, '/Users/ricky/Downloads/code/capmaster')

from capmaster.plugins.compare.flow_hash import calculate_flow_hash, format_flow_hash


def test_reference_value():
    """Test against the reference value from the original Python code."""
    print("=" * 70)
    print("TEST 1: Reference Value Verification")
    print("=" * 70)
    
    ip1 = "8.67.2.125"
    ip2 = "8.42.96.45"
    port1 = 26302
    port2 = 35101
    expected = -1173584886679544929
    
    hash_val, flow_side = calculate_flow_hash(ip1, ip2, port1, port2, 6)
    
    print(f"Input: {ip1}:{port1} -> {ip2}:{port2}")
    print(f"Expected: {expected}")
    print(f"Actual:   {hash_val}")
    print(f"Flow side: {flow_side}")
    
    if hash_val == expected:
        print("✓ PASS: Hash value matches reference")
        return True
    else:
        print("✗ FAIL: Hash value does not match reference")
        return False


def test_bidirectional_consistency():
    """Test bidirectional consistency."""
    print("\n" + "=" * 70)
    print("TEST 2: Bidirectional Consistency")
    print("=" * 70)
    
    test_cases = [
        ("8.67.2.125", "8.42.96.45", 26302, 35101),
        ("192.168.1.1", "10.0.0.1", 12345, 80),
        ("8.8.8.8", "1.1.1.1", 443, 54321),
        ("172.16.0.1", "172.16.0.2", 5000, 5001),
    ]
    
    all_passed = True
    
    for ip1, ip2, port1, port2 in test_cases:
        hash_fwd, side_fwd = calculate_flow_hash(ip1, ip2, port1, port2, 6)
        hash_rev, side_rev = calculate_flow_hash(ip2, ip1, port2, port1, 6)
        
        match = hash_fwd == hash_rev
        status = "✓" if match else "✗"
        
        print(f"\n{status} {ip1}:{port1} <-> {ip2}:{port2}")
        print(f"  Forward:  {hash_fwd:20d} (side={side_fwd})")
        print(f"  Reverse:  {hash_rev:20d} (side={side_rev})")
        print(f"  Match: {match}")
        
        if not match:
            all_passed = False
    
    if all_passed:
        print("\n✓ PASS: All test cases show bidirectional consistency")
    else:
        print("\n✗ FAIL: Some test cases failed bidirectional consistency")
    
    return all_passed


def test_pcap_case():
    """Test the actual PCAP file case."""
    print("\n" + "=" * 70)
    print("TEST 3: PCAP File Case")
    print("=" * 70)
    
    # Connection from the actual PCAP files
    client_ip = "8.42.96.45"
    server_ip = "8.67.2.125"
    client_port = 35101
    server_port = 26302
    expected = -1173584886679544929
    
    hash1, side1 = calculate_flow_hash(client_ip, server_ip, client_port, server_port, 6)
    hash2, side2 = calculate_flow_hash(server_ip, client_ip, server_port, client_port, 6)
    
    print(f"Connection: {client_ip}:{client_port} <-> {server_ip}:{server_port}")
    print(f"Direction 1: {hash1} (side={side1})")
    print(f"Direction 2: {hash2} (side={side2})")
    print(f"Expected:    {expected}")
    
    match1 = hash1 == expected
    match2 = hash2 == expected
    bidirectional = hash1 == hash2
    
    print(f"\nDirection 1 matches expected: {match1} {'✓' if match1 else '✗'}")
    print(f"Direction 2 matches expected: {match2} {'✓' if match2 else '✗'}")
    print(f"Bidirectional consistency: {bidirectional} {'✓' if bidirectional else '✗'}")
    
    if match1 and match2 and bidirectional:
        print("\n✓ PASS: PCAP case verified")
        return True
    else:
        print("\n✗ FAIL: PCAP case failed")
        return False


def test_format_output():
    """Test the format_flow_hash function."""
    print("\n" + "=" * 70)
    print("TEST 4: Format Output")
    print("=" * 70)
    
    hash_val, flow_side = calculate_flow_hash("8.67.2.125", "8.42.96.45", 26302, 35101, 6)
    formatted = format_flow_hash(hash_val, flow_side)
    
    print(f"Hash value: {hash_val}")
    print(f"Flow side: {flow_side}")
    print(f"Formatted: {formatted}")
    
    expected_format = f"{hash_val} (LHS>=RHS)"
    if formatted == expected_format:
        print(f"✓ PASS: Format matches expected: {expected_format}")
        return True
    else:
        print(f"✗ FAIL: Format does not match expected")
        print(f"  Expected: {expected_format}")
        print(f"  Actual:   {formatted}")
        return False


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("FLOW HASH IMPLEMENTATION - FINAL VERIFICATION")
    print("=" * 70)
    
    results = []
    
    results.append(("Reference Value", test_reference_value()))
    results.append(("Bidirectional Consistency", test_bidirectional_consistency()))
    results.append(("PCAP File Case", test_pcap_case()))
    results.append(("Format Output", test_format_output()))
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {name}")
    
    all_passed = all(passed for _, passed in results)
    
    print("\n" + "=" * 70)
    if all_passed:
        print("✓✓✓ ALL TESTS PASSED ✓✓✓")
        print("=" * 70)
        return 0
    else:
        print("✗✗✗ SOME TESTS FAILED ✗✗✗")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())

