#!/usr/bin/env python3
"""Test script to verify one-to-many matching functionality."""

from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.matcher import ConnectionMatcher, MatchMode

def main():
    print("=" * 80)
    print("One-to-Many Matching Test")
    print("=" * 80)
    print()
    
    # Simulate the real case:
    # File B: 1 long stream covering time [0, 1000]
    # File A: 4 shorter streams covering different time segments
    
    # File B: Long stream
    conn_b = TcpConnection(
        stream_id=0,
        client_ip="8.42.96.45",
        client_port=35101,
        server_ip="8.67.2.125",
        server_port=26302,
        syn_timestamp=0.0,
        syn_options="020405b40402080a8a3c283c0000000001030307",
        client_isn=100,
        server_isn=200,
        tcp_timestamp_tsval="2327256484",
        tcp_timestamp_tsecr="2049763571",
        client_payload_md5="abc123",
        server_payload_md5="def456",
        length_signature="C:54 S:57 C:54 S:57",
        is_header_only=False,
        ipid_first=61507,
        first_packet_time=0.0,
        last_packet_time=1000.0,
        packet_count=1000,
    )
    
    # File A: Stream 0 - Time [0, 100]
    conn_a0 = TcpConnection(
        stream_id=0,
        client_ip="8.42.96.45",
        client_port=35101,
        server_ip="8.67.2.125",
        server_port=26302,
        syn_timestamp=0.0,
        syn_options="020405b40402080a8a3c283c0000000001030307",
        client_isn=100,
        server_isn=200,
        tcp_timestamp_tsval="2327256484",
        tcp_timestamp_tsecr="2049763571",
        client_payload_md5="abc123",
        server_payload_md5="def456",
        length_signature="C:54 S:57 C:54 S:57",
        is_header_only=False,
        ipid_first=61507,
        first_packet_time=0.0,
        last_packet_time=100.0,
        packet_count=100,
    )
    
    # File A: Stream 1 - Time [100, 200]
    conn_a1 = TcpConnection(
        stream_id=1,
        client_ip="8.42.96.45",
        client_port=35101,
        server_ip="8.67.2.125",
        server_port=26302,
        syn_timestamp=100.0,
        syn_options="020405b40402080a8a3c283c0000000001030307",
        client_isn=100,
        server_isn=200,
        tcp_timestamp_tsval="2327256484",
        tcp_timestamp_tsecr="2049763571",
        client_payload_md5="abc123",
        server_payload_md5="def456",
        length_signature="C:54 S:57 C:54 S:57",
        is_header_only=False,
        ipid_first=61507,
        first_packet_time=100.0,
        last_packet_time=200.0,
        packet_count=100,
    )
    
    # File A: Stream 2 - Time [200, 300]
    conn_a2 = TcpConnection(
        stream_id=2,
        client_ip="8.42.96.45",
        client_port=35101,
        server_ip="8.67.2.125",
        server_port=26302,
        syn_timestamp=200.0,
        syn_options="020405b40402080a8a3c283c0000000001030307",
        client_isn=100,
        server_isn=200,
        tcp_timestamp_tsval="2327256484",
        tcp_timestamp_tsecr="2049763571",
        client_payload_md5="abc123",
        server_payload_md5="def456",
        length_signature="C:54 S:57 C:54 S:57",
        is_header_only=False,
        ipid_first=61507,
        first_packet_time=200.0,
        last_packet_time=300.0,
        packet_count=100,
    )
    
    # File A: Stream 3 - Time [2000, 3000], NO overlap with B
    conn_a3 = TcpConnection(
        stream_id=3,
        client_ip="8.42.96.45",
        client_port=35101,
        server_ip="8.67.2.125",
        server_port=26302,
        syn_timestamp=2000.0,
        syn_options="020405b40402080a8a3c283c0000000001030307",
        client_isn=100,
        server_isn=200,
        tcp_timestamp_tsval="2327256484",
        tcp_timestamp_tsecr="2049763571",
        client_payload_md5="abc123",
        server_payload_md5="def456",
        length_signature="C:54 S:57 C:54 S:57",
        is_header_only=False,
        ipid_first=61507,
        first_packet_time=2000.0,
        last_packet_time=3000.0,
        packet_count=100,
    )
    
    connections_b = [conn_b]
    connections_a = [conn_a0, conn_a1, conn_a2, conn_a3]
    
    print("Test Setup:")
    print("-" * 80)
    print(f"File B: 1 stream")
    print(f"  {conn_b}")
    print()
    print(f"File A: 4 streams")
    for conn in connections_a:
        print(f"  {conn}")
    print()
    
    # Test 1: One-to-One Matching (default)
    print("=" * 80)
    print("Test 1: One-to-One Matching (default)")
    print("=" * 80)
    print()
    
    matcher_one_to_one = ConnectionMatcher(match_mode=MatchMode.ONE_TO_ONE)
    matches_one_to_one = matcher_one_to_one.match(connections_b, connections_a)
    stats_one_to_one = matcher_one_to_one.get_match_stats(connections_b, connections_a, matches_one_to_one)
    
    print(f"Found {len(matches_one_to_one)} matches")
    print()
    for i, match in enumerate(matches_one_to_one, 1):
        print(f"Match {i}:")
        print(f"  File B: {match.conn1}")
        print(f"  File A: {match.conn2}")
        print(f"  Score: {match.score.normalized_score:.4f}")
        print(f"  Evidence: {match.score.evidence}")
        print()
    
    print("Statistics:")
    for key, value in stats_one_to_one.items():
        print(f"  {key}: {value}")
    print()
    
    # Test 2: One-to-Many Matching
    print("=" * 80)
    print("Test 2: One-to-Many Matching")
    print("=" * 80)
    print()
    
    matcher_one_to_many = ConnectionMatcher(match_mode=MatchMode.ONE_TO_MANY)
    matches_one_to_many = matcher_one_to_many.match(connections_b, connections_a)
    stats_one_to_many = matcher_one_to_many.get_match_stats(connections_b, connections_a, matches_one_to_many)
    
    print(f"Found {len(matches_one_to_many)} matches")
    print()
    for i, match in enumerate(matches_one_to_many, 1):
        print(f"Match {i}:")
        print(f"  File B: {match.conn1}")
        print(f"  File A: {match.conn2}")
        print(f"  Score: {match.score.normalized_score:.4f}")
        print(f"  Evidence: {match.score.evidence}")
        print()
    
    print("Statistics:")
    for key, value in stats_one_to_many.items():
        print(f"  {key}: {value}")
    print()
    
    # Verification
    print("=" * 80)
    print("Verification:")
    print("=" * 80)
    print()
    
    expected_one_to_one = 1
    expected_one_to_many = 3  # A0, A1, A2 should match B, A3 should not (no time overlap)
    
    if len(matches_one_to_one) == expected_one_to_one:
        print(f"✅ PASS: One-to-one matching found {expected_one_to_one} match (as expected)")
    else:
        print(f"❌ FAIL: One-to-one matching found {len(matches_one_to_one)} matches (expected {expected_one_to_one})")
    
    if len(matches_one_to_many) == expected_one_to_many:
        print(f"✅ PASS: One-to-many matching found {expected_one_to_many} matches (as expected)")
    else:
        print(f"❌ FAIL: One-to-many matching found {len(matches_one_to_many)} matches (expected {expected_one_to_many})")
    
    # Verify that A3 is NOT matched (no time overlap)
    a3_matched = any(m.conn2.stream_id == 3 for m in matches_one_to_many)
    if not a3_matched:
        print(f"✅ PASS: Stream A3 correctly rejected (no time overlap with B)")
    else:
        print(f"❌ FAIL: Stream A3 should be rejected (no time overlap with B)")
    
    # Verify that B Stream 0 matched multiple A streams
    b0_match_count = sum(1 for m in matches_one_to_many if m.conn1.stream_id == 0)
    if b0_match_count == expected_one_to_many:
        print(f"✅ PASS: B Stream 0 matched {b0_match_count} A streams (as expected)")
    else:
        print(f"❌ FAIL: B Stream 0 matched {b0_match_count} A streams (expected {expected_one_to_many})")
    
    print()
    print("=" * 80)
    print("Summary:")
    print("=" * 80)
    print()
    print("One-to-Many matching allows:")
    print("  - B Stream 0 to match multiple A streams (A0, A1, A2)")
    print("  - Based on time overlap and IPID match")
    print("  - A3 is correctly rejected due to no time overlap")
    print()
    print("This solves the problem where one long stream should match")
    print("multiple shorter streams with the same 5-tuple but different time ranges.")
    print()

if __name__ == "__main__":
    main()

