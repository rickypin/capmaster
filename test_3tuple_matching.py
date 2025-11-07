#!/usr/bin/env python3
"""
Test script to verify 3-tuple (port pair) matching logic.

This script tests the new matching requirements:
1. 3-tuple matching (port pair only, direction-independent) - REQUIRED
2. IPID matching (flexible) - REQUIRED
3. Time overlap - REMOVED (no longer required)
"""

from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.scorer import ConnectionScorer

def create_test_connection(
    client_ip: str,
    client_port: int,
    server_ip: str,
    server_port: int,
    ipid_set: set[int],
    first_time: float = 0.0,
    last_time: float = 100.0,
) -> TcpConnection:
    """Create a test connection with minimal required fields."""
    return TcpConnection(
        stream_id=0,
        client_ip=client_ip,
        client_port=client_port,
        server_ip=server_ip,
        server_port=server_port,
        syn_timestamp=first_time,
        client_isn=0,
        server_isn=0,
        syn_options="",
        tcp_timestamp_tsval="",
        tcp_timestamp_tsecr="",
        client_payload_md5="",
        server_payload_md5="",
        length_signature="",
        ipid_set=ipid_set,
        ipid_first=list(ipid_set)[0] if ipid_set else 0,
        first_packet_time=first_time,
        last_packet_time=last_time,
        packet_count=10,
        is_header_only=True,
    )

def test_3tuple_matching():
    """Test 3-tuple (port pair) matching."""
    print("=" * 80)
    print("Test 1: 3-tuple matching (port pair only)")
    print("=" * 80)
    
    scorer = ConnectionScorer()
    
    # Test case 1: Same port pair, different IPs (NAT scenario) - should match
    print("\nTest 1.1: Same port pair, different IPs (NAT scenario)")
    conn1 = create_test_connection(
        "10.0.0.1", 8080, "192.168.1.1", 443,
        ipid_set={1000, 1001}
    )
    conn2 = create_test_connection(
        "172.16.0.1", 443, "10.10.10.1", 8080,  # Different IPs, same ports
        ipid_set={1000, 1002}  # Share IPID 1000
    )
    
    print(f"  conn1: {conn1.client_ip}:{conn1.client_port} <-> {conn1.server_ip}:{conn1.server_port}")
    print(f"  conn2: {conn2.client_ip}:{conn2.client_port} <-> {conn2.server_ip}:{conn2.server_port}")
    print(f"  conn1 3-tuple: {conn1.get_normalized_3tuple()}")
    print(f"  conn2 3-tuple: {conn2.get_normalized_3tuple()}")
    print(f"  conn1 IPID: {conn1.ipid_set}")
    print(f"  conn2 IPID: {conn2.ipid_set}")
    
    score = scorer.score(conn1, conn2)
    print(f"  Result: score={score.normalized_score:.3f}, ipid_match={score.ipid_match}, evidence={score.evidence}")
    print(f"  Expected: Should MATCH (same port pair + shared IPID)")
    print(f"  Status: {'✅ PASS' if score.normalized_score > 0 else '❌ FAIL'}")
    
    # Test case 2: Different port pair - should NOT match
    print("\nTest 1.2: Different port pair")
    conn3 = create_test_connection(
        "10.0.0.1", 8080, "192.168.1.1", 443,
        ipid_set={1000, 1001}
    )
    conn4 = create_test_connection(
        "172.16.0.1", 9000, "10.10.10.1", 8080,  # Different port (9000 vs 443)
        ipid_set={1000, 1002}  # Share IPID 1000
    )
    
    print(f"  conn3: {conn3.client_ip}:{conn3.client_port} <-> {conn3.server_ip}:{conn3.server_port}")
    print(f"  conn4: {conn4.client_ip}:{conn4.client_port} <-> {conn4.server_ip}:{conn4.server_port}")
    print(f"  conn3 3-tuple: {conn3.get_normalized_3tuple()}")
    print(f"  conn4 3-tuple: {conn4.get_normalized_3tuple()}")
    
    score = scorer.score(conn3, conn4)
    print(f"  Result: score={score.normalized_score:.3f}, evidence={score.evidence}")
    print(f"  Expected: Should NOT match (different port pair)")
    print(f"  Status: {'✅ PASS' if score.normalized_score == 0 and score.evidence == 'no-3tuple' else '❌ FAIL'}")
    
    # Test case 3: Same port pair but no shared IPID - should NOT match
    print("\nTest 1.3: Same port pair but no shared IPID")
    conn5 = create_test_connection(
        "10.0.0.1", 8080, "192.168.1.1", 443,
        ipid_set={1000, 1001}
    )
    conn6 = create_test_connection(
        "172.16.0.1", 443, "10.10.10.1", 8080,  # Same ports
        ipid_set={2000, 2001}  # No shared IPID
    )
    
    print(f"  conn5: {conn5.client_ip}:{conn5.client_port} <-> {conn5.server_ip}:{conn5.server_port}")
    print(f"  conn6: {conn6.client_ip}:{conn6.client_port} <-> {conn6.server_ip}:{conn6.server_port}")
    print(f"  conn5 IPID: {conn5.ipid_set}")
    print(f"  conn6 IPID: {conn6.ipid_set}")
    
    score = scorer.score(conn5, conn6)
    print(f"  Result: score={score.normalized_score:.3f}, evidence={score.evidence}")
    print(f"  Expected: Should NOT match (no shared IPID)")
    print(f"  Status: {'✅ PASS' if score.normalized_score == 0 and score.evidence == 'no-ipid' else '❌ FAIL'}")

def test_time_overlap_removed():
    """Test that time overlap is no longer a requirement."""
    print("\n" + "=" * 80)
    print("Test 2: Time overlap no longer required")
    print("=" * 80)
    
    scorer = ConnectionScorer()
    
    # Test case: Same port pair, shared IPID, but NO time overlap
    print("\nTest 2.1: Same port pair, shared IPID, NO time overlap")
    conn1 = create_test_connection(
        "10.0.0.1", 8080, "192.168.1.1", 443,
        ipid_set={1000, 1001},
        first_time=0.0,
        last_time=100.0
    )
    conn2 = create_test_connection(
        "172.16.0.1", 443, "10.10.10.1", 8080,
        ipid_set={1000, 1002},
        first_time=200.0,  # No overlap with conn1
        last_time=300.0
    )
    
    print(f"  conn1: {conn1.client_ip}:{conn1.client_port} <-> {conn1.server_ip}:{conn1.server_port}")
    print(f"  conn1 time: [{conn1.first_packet_time}, {conn1.last_packet_time}]")
    print(f"  conn2: {conn2.client_ip}:{conn2.client_port} <-> {conn2.server_ip}:{conn2.server_port}")
    print(f"  conn2 time: [{conn2.first_packet_time}, {conn2.last_packet_time}]")
    print(f"  Time overlap: NO")
    print(f"  conn1 IPID: {conn1.ipid_set}")
    print(f"  conn2 IPID: {conn2.ipid_set}")
    
    score = scorer.score(conn1, conn2)
    print(f"  Result: score={score.normalized_score:.3f}, ipid_match={score.ipid_match}, evidence={score.evidence}")
    print(f"  Expected: Should MATCH (time overlap no longer required)")
    print(f"  Status: {'✅ PASS' if score.normalized_score > 0 else '❌ FAIL'}")

def test_direction_independence():
    """Test that port matching is direction-independent."""
    print("\n" + "=" * 80)
    print("Test 3: Direction independence")
    print("=" * 80)
    
    scorer = ConnectionScorer()
    
    # Test case: Same port pair but reversed direction
    print("\nTest 3.1: Same port pair, reversed direction")
    conn1 = create_test_connection(
        "10.0.0.1", 8080, "192.168.1.1", 443,
        ipid_set={1000, 1001}
    )
    conn2 = create_test_connection(
        "172.16.0.1", 8080, "10.10.10.1", 443,  # Reversed: 8080 is now client port
        ipid_set={1000, 1002}
    )
    
    print(f"  conn1: {conn1.client_ip}:{conn1.client_port} <-> {conn1.server_ip}:{conn1.server_port}")
    print(f"  conn1 3-tuple: {conn1.get_normalized_3tuple()}")
    print(f"  conn2: {conn2.client_ip}:{conn2.client_port} <-> {conn2.server_ip}:{conn2.server_port}")
    print(f"  conn2 3-tuple: {conn2.get_normalized_3tuple()}")
    
    score = scorer.score(conn1, conn2)
    print(f"  Result: score={score.normalized_score:.3f}, ipid_match={score.ipid_match}, evidence={score.evidence}")
    print(f"  Expected: Should MATCH (same port pair, direction-independent)")
    print(f"  Status: {'✅ PASS' if score.normalized_score > 0 else '❌ FAIL'}")

def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("Testing 3-tuple (Port Pair) Matching Logic")
    print("=" * 80)
    print("\nNew matching requirements:")
    print("  1. ✅ 3-tuple matching (port pair only, direction-independent) - REQUIRED")
    print("  2. ✅ IPID matching (flexible) - REQUIRED")
    print("  3. ❌ Time overlap - REMOVED (no longer required)")
    print()
    
    test_3tuple_matching()
    test_time_overlap_removed()
    test_direction_independence()
    
    print("\n" + "=" * 80)
    print("All tests completed!")
    print("=" * 80)

if __name__ == "__main__":
    main()

