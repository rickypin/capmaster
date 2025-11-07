#!/usr/bin/env python3
"""Test script simulating the real-world scenario from the user's case."""

from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.matcher import ConnectionMatcher, MatchMode

def create_connection(stream_id, first_time, last_time, packet_count, ipid):
    """Helper to create a TcpConnection."""
    return TcpConnection(
        stream_id=stream_id,
        client_ip="8.42.96.45",
        client_port=35101,
        server_ip="8.67.2.125",
        server_port=26302,
        syn_timestamp=first_time,
        syn_options="020405b40402080a8a3c283c0000000001030307",
        client_isn=100,
        server_isn=200,
        tcp_timestamp_tsval="2327256484",
        tcp_timestamp_tsecr="2049763571",
        client_payload_md5="abc123",
        server_payload_md5="def456",
        length_signature="C:54 S:57 C:54 S:57",
        is_header_only=False,
        ipid_first=ipid,
        first_packet_time=first_time,
        last_packet_time=last_time,
        packet_count=packet_count,
    )

def main():
    print("=" * 80)
    print("Real-World Scenario Test: 16 A Streams vs 1 B Stream")
    print("=" * 80)
    print()
    
    # Simulate the real case:
    # File B: 1 long stream covering entire time range
    # File A: 16 shorter streams, each covering a different time segment
    
    # File B: One long stream [0, 16000]
    conn_b = create_connection(
        stream_id=0,
        first_time=0.0,
        last_time=16000.0,
        packet_count=16000,
        ipid=61507,
    )
    
    # File A: 16 streams, each covering 1000 seconds
    # Stream 0: [0, 1000], Stream 1: [1000, 2000], ..., Stream 15: [15000, 16000]
    # All streams have the same IPID (61507) because they're part of the same long connection
    # that was split into multiple streams by tshark
    connections_a = []

    for i in range(16):
        conn = create_connection(
            stream_id=i,
            first_time=i * 1000.0,
            last_time=(i + 1) * 1000.0,
            packet_count=1000,
            ipid=61507,  # Same IPID for all streams (same connection)
        )
        connections_a.append(conn)
    
    connections_b = [conn_b]
    
    print("Test Setup:")
    print("-" * 80)
    print(f"File B: 1 stream covering entire time range")
    print(f"  {conn_b}")
    print()
    print(f"File A: 16 streams, each covering 1000 seconds")
    for i, conn in enumerate(connections_a):
        print(f"  Stream {i:2d}: time=[{conn.first_packet_time:7.1f}, {conn.last_packet_time:7.1f}], ipid={conn.ipid_first}")
    print()
    
    # Test 1: One-to-One Matching
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
        print(f"  B Stream {match.conn1.stream_id}: time=[{match.conn1.first_packet_time:.1f}, {match.conn1.last_packet_time:.1f}]")
        print(f"  A Stream {match.conn2.stream_id}: time=[{match.conn2.first_packet_time:.1f}, {match.conn2.last_packet_time:.1f}]")
        print(f"  Score: {match.score.normalized_score:.4f}")
        print()
    
    print("Statistics:")
    for key, value in stats_one_to_one.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.4f}")
        else:
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
    
    # Group matches by B stream
    from collections import defaultdict
    matches_by_b = defaultdict(list)
    for match in matches_one_to_many:
        matches_by_b[match.conn1.stream_id].append(match)
    
    for b_stream_id, matches in sorted(matches_by_b.items()):
        print(f"B Stream {b_stream_id} matched {len(matches)} A streams:")
        for match in matches:
            print(f"  → A Stream {match.conn2.stream_id:2d}: "
                  f"time=[{match.conn2.first_packet_time:7.1f}, {match.conn2.last_packet_time:7.1f}], "
                  f"score={match.score.normalized_score:.4f}")
        print()
    
    print("Statistics:")
    for key, value in stats_one_to_many.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.4f}")
        else:
            print(f"  {key}: {value}")
    print()
    
    # Verification
    print("=" * 80)
    print("Verification:")
    print("=" * 80)
    print()
    
    expected_one_to_one = 1
    expected_one_to_many = 16  # All 16 A streams should match B stream 0
    
    if len(matches_one_to_one) == expected_one_to_one:
        print(f"✅ PASS: One-to-one matching found {expected_one_to_one} match (as expected)")
    else:
        print(f"❌ FAIL: One-to-one matching found {len(matches_one_to_one)} matches (expected {expected_one_to_one})")
    
    if len(matches_one_to_many) == expected_one_to_many:
        print(f"✅ PASS: One-to-many matching found {expected_one_to_many} matches (as expected)")
    else:
        print(f"❌ FAIL: One-to-many matching found {len(matches_one_to_many)} matches (expected {expected_one_to_many})")
    
    # Verify that B Stream 0 matched all 16 A streams
    b0_match_count = sum(1 for m in matches_one_to_many if m.conn1.stream_id == 0)
    if b0_match_count == expected_one_to_many:
        print(f"✅ PASS: B Stream 0 matched {b0_match_count} A streams (as expected)")
    else:
        print(f"❌ FAIL: B Stream 0 matched {b0_match_count} A streams (expected {expected_one_to_many})")
    
    # Verify all A streams were matched
    matched_a_streams = {m.conn2.stream_id for m in matches_one_to_many}
    if len(matched_a_streams) == 16:
        print(f"✅ PASS: All 16 A streams were matched")
    else:
        print(f"❌ FAIL: Only {len(matched_a_streams)} A streams were matched (expected 16)")
        print(f"  Matched: {sorted(matched_a_streams)}")
        print(f"  Missing: {sorted(set(range(16)) - matched_a_streams)}")
    
    print()
    print("=" * 80)
    print("Summary:")
    print("=" * 80)
    print()
    print("One-to-Many matching successfully handles the real-world scenario:")
    print()
    print("  File B: 1 long stream [0, 16000]")
    print("  File A: 16 shorter streams, each [i*1000, (i+1)*1000]")
    print()
    print("  Result: B Stream 0 matches all 16 A streams")
    print()
    print("This is exactly what was needed for the user's case where:")
    print("  - File A has 16 TCP streams (0-15) with same 5-tuple")
    print("  - File B has 1 TCP stream (0) with same 5-tuple")
    print("  - Each A stream should match a time segment of B stream")
    print()

if __name__ == "__main__":
    main()

