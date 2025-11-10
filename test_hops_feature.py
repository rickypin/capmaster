#!/usr/bin/env python3
"""Test script for network hops calculation feature."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from capmaster.plugins.match.ttl_utils import (
    TtlDelta,
    calculate_hops,
    most_common_hops,
    analyze_ttl_info,
)
from capmaster.plugins.match.endpoint_stats import EndpointPairStats, EndpointTuple
from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.matcher import ConnectionMatch, MatchScore


def test_ttl_delta():
    """Test TTL delta calculation."""
    print("=" * 80)
    print("Test 1: TTL Delta Calculation")
    print("=" * 80)
    
    # Test Linux system (initial TTL = 64)
    delta1 = TtlDelta(64)
    print(f"TTL=64 (Linux, direct): {delta1} -> hops={delta1.hops}")
    assert delta1.hops == 0, "Direct connection should have 0 hops"
    assert not delta1.has_intermediate_device(), "Direct connection should have no intermediate device"
    
    delta2 = TtlDelta(60)
    print(f"TTL=60 (Linux, 4 hops): {delta2} -> hops={delta2.hops}")
    assert delta2.hops == 4, "Should have 4 hops"
    assert delta2.has_intermediate_device(), "Should have intermediate device"
    
    # Test Windows system (initial TTL = 128)
    delta3 = TtlDelta(128)
    print(f"TTL=128 (Windows, direct): {delta3} -> hops={delta3.hops}")
    assert delta3.hops == 0, "Direct connection should have 0 hops"
    
    delta4 = TtlDelta(120)
    print(f"TTL=120 (Windows, 8 hops): {delta4} -> hops={delta4.hops}")
    assert delta4.hops == 8, "Should have 8 hops"
    
    # Test network device (initial TTL = 255)
    delta5 = TtlDelta(255)
    print(f"TTL=255 (Device, direct): {delta5} -> hops={delta5.hops}")
    assert delta5.hops == 0, "Direct connection should have 0 hops"
    
    delta6 = TtlDelta(240)
    print(f"TTL=240 (Device, 15 hops): {delta6} -> hops={delta6.hops}")
    assert delta6.hops == 15, "Should have 15 hops"
    
    print("✓ TTL delta calculation test passed!\n")


def test_calculate_hops():
    """Test calculate_hops convenience function."""
    print("=" * 80)
    print("Test 2: Calculate Hops Function")
    print("=" * 80)
    
    test_cases = [
        (64, 0, "Linux direct"),
        (60, 4, "Linux 4 hops"),
        (128, 0, "Windows direct"),
        (120, 8, "Windows 8 hops"),
        (255, 0, "Device direct"),
        (240, 15, "Device 15 hops"),
        (0, 0, "Invalid TTL"),
    ]
    
    for ttl, expected_hops, description in test_cases:
        hops = calculate_hops(ttl)
        print(f"TTL={ttl:3d} -> hops={hops:2d} ({description})")
        assert hops == expected_hops, f"Expected {expected_hops} hops for {description}"
    
    print("✓ Calculate hops function test passed!\n")


def test_most_common_hops():
    """Test most_common_hops function."""
    print("=" * 80)
    print("Test 3: Most Common Hops")
    print("=" * 80)
    
    # Test case 1: Mostly direct connections
    ttls1 = [64, 64, 64, 63]
    hops1 = most_common_hops(ttls1)
    print(f"TTLs {ttls1} -> most common hops: {hops1}")
    assert hops1 == 0, "Most common should be 0 hops"
    
    # Test case 2: Mostly 4 hops
    ttls2 = [60, 60, 61, 64]
    hops2 = most_common_hops(ttls2)
    print(f"TTLs {ttls2} -> most common hops: {hops2}")
    assert hops2 == 4, "Most common should be 4 hops"
    
    # Test case 3: Empty list
    ttls3 = []
    hops3 = most_common_hops(ttls3)
    print(f"TTLs {ttls3} -> most common hops: {hops3}")
    assert hops3 == 0, "Empty list should return 0"
    
    # Test case 4: Mixed Windows and Linux
    ttls4 = [120, 120, 120, 60, 60]
    hops4 = most_common_hops(ttls4)
    print(f"TTLs {ttls4} -> most common hops: {hops4}")
    assert hops4 == 8, "Most common should be 8 hops (Windows)"
    
    print("✓ Most common hops test passed!\n")


def test_analyze_ttl_info():
    """Test analyze_ttl_info function."""
    print("=" * 80)
    print("Test 4: Analyze TTL Info")
    print("=" * 80)
    
    client_ttls = [64, 64, 64]
    server_ttls = [60, 60, 61]
    
    info = analyze_ttl_info(client_ttls, server_ttls)
    print(f"Client TTLs: {client_ttls}")
    print(f"Server TTLs: {server_ttls}")
    print(f"Analysis result: {info}")
    
    assert info['client_hops'] == 0, "Client should have 0 hops"
    assert info['server_hops'] == 4, "Server should have 4 hops"
    assert info['client_has_device'] == 0, "Client should have no intermediate device"
    assert info['server_has_device'] == 1, "Server should have intermediate device"
    
    print("✓ Analyze TTL info test passed!\n")


def test_endpoint_stats_with_hops():
    """Test endpoint statistics with hops information."""
    print("=" * 80)
    print("Test 5: Endpoint Statistics with Hops")
    print("=" * 80)
    
    # Create test endpoint pair stats
    stats = EndpointPairStats(
        tuple_a=EndpointTuple(
            client_ip="192.168.1.100",
            server_ip="10.0.0.50",
            server_port=80,
            protocol=6,
        ),
        tuple_b=EndpointTuple(
            client_ip="172.16.0.200",
            server_ip="10.0.0.51",
            server_port=80,
            protocol=6,
        ),
        count=5,
        confidence="HIGH",
        client_ttl_a=64,
        server_ttl_a=60,
        client_ttl_b=128,
        server_ttl_b=120,
        client_hops_a=0,
        server_hops_a=4,
        client_hops_b=0,
        server_hops_b=8,
    )
    
    print(f"Endpoint Pair Stats:")
    print(f"  File A: Client TTL={stats.client_ttl_a} (hops={stats.client_hops_a}), "
          f"Server TTL={stats.server_ttl_a} (hops={stats.server_hops_a})")
    print(f"  File B: Client TTL={stats.client_ttl_b} (hops={stats.client_hops_b}), "
          f"Server TTL={stats.server_ttl_b} (hops={stats.server_hops_b})")
    
    # Test string representation
    str_repr = str(stats)
    print(f"\nString representation:\n{str_repr}")
    
    assert "hops=0" in str_repr, "Should contain client hops info"
    assert "hops=4" in str_repr, "Should contain server hops info"
    assert "hops=8" in str_repr, "Should contain server B hops info"
    
    print("\n✓ Endpoint statistics with hops test passed!\n")


def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("Testing Network Hops Calculation Feature")
    print("=" * 80 + "\n")
    
    try:
        # Test 1: TTL delta calculation
        test_ttl_delta()
        
        # Test 2: Calculate hops function
        test_calculate_hops()
        
        # Test 3: Most common hops
        test_most_common_hops()
        
        # Test 4: Analyze TTL info
        test_analyze_ttl_info()
        
        # Test 5: Endpoint stats with hops
        test_endpoint_stats_with_hops()
        
        print("=" * 80)
        print("✓ All tests passed successfully!")
        print("=" * 80)
        return 0
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

