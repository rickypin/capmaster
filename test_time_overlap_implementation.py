#!/usr/bin/env python3
"""Test script to verify time overlap implementation."""

from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.matcher import ConnectionMatcher, BucketStrategy

def main():
    print("=" * 80)
    print("Time Overlap Implementation Test")
    print("=" * 80)
    print()
    
    # File B: One long stream covering time 0-1000
    connections_b = [
        TcpConnection(
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
            first_packet_time=0.0,      # NEW: Time range [0, 1000]
            last_packet_time=1000.0,    # NEW
            packet_count=1000,          # NEW
        ),
    ]
    
    # File A: Multiple streams with same 5-tuple and IPID but different time ranges
    connections_a = [
        # Stream 0: Time [0, 100], overlaps with B
        TcpConnection(
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
            first_packet_time=0.0,      # NEW: Time range [0, 100]
            last_packet_time=100.0,     # NEW
            packet_count=100,           # NEW
        ),
        # Stream 1: Time [100, 200], overlaps with B
        TcpConnection(
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
            client_payload_md5="xyz789",
            server_payload_md5="uvw012",
            length_signature="C:100 S:200",
            is_header_only=False,
            ipid_first=61507,
            first_packet_time=100.0,    # NEW: Time range [100, 200]
            last_packet_time=200.0,     # NEW
            packet_count=100,           # NEW
        ),
        # Stream 2: Time [200, 300], overlaps with B
        TcpConnection(
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
            client_payload_md5="pqr345",
            server_payload_md5="stu678",
            length_signature="C:150 S:250",
            is_header_only=False,
            ipid_first=61507,
            first_packet_time=200.0,    # NEW: Time range [200, 300]
            last_packet_time=300.0,     # NEW
            packet_count=100,           # NEW
        ),
        # Stream 3: Time [2000, 3000], NO overlap with B (B ends at 1000)
        TcpConnection(
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
            client_payload_md5="mno901",
            server_payload_md5="jkl234",
            length_signature="C:200 S:300",
            is_header_only=False,
            ipid_first=61507,           # Same IPID!
            first_packet_time=2000.0,   # NEW: Time range [2000, 3000]
            last_packet_time=3000.0,    # NEW
            packet_count=100,           # NEW
        ),
    ]
    
    print("File B (Baseline):")
    print("-" * 80)
    for conn in connections_b:
        print(f"  {conn}")
    print()
    
    print("File A (Compare):")
    print("-" * 80)
    for conn in connections_a:
        print(f"  {conn}")
    print()
    
    print("Matching with Time Overlap Check:")
    print("-" * 80)
    matcher = ConnectionMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
    )
    
    matches = matcher.match(connections_b, connections_a)
    
    print(f"Found {len(matches)} matches")
    print()
    
    for i, match in enumerate(matches, 1):
        print(f"Match {i}:")
        print(f"  File B: Stream {match.conn1.stream_id} - Time [{match.conn1.first_packet_time:.1f}, {match.conn1.last_packet_time:.1f}]")
        print(f"  File A: Stream {match.conn2.stream_id} - Time [{match.conn2.first_packet_time:.1f}, {match.conn2.last_packet_time:.1f}]")
        print(f"  Score: {match.score.normalized_score:.4f}")
        print(f"  Evidence: {match.score.evidence}")
        print()
    
    print("=" * 80)
    print("Test Results:")
    print("=" * 80)
    print()
    
    # Expected: 3 matches (A streams 0, 1, 2 should match B stream 0)
    # A stream 3 should NOT match (no time overlap)
    expected_matches = 3
    
    if len(matches) == expected_matches:
        print(f"✅ PASS: Found {len(matches)} matches (expected {expected_matches})")
        print()
        print("Matched streams:")
        for match in matches:
            print(f"  ✅ A Stream {match.conn2.stream_id} ↔ B Stream {match.conn1.stream_id}")
        print()
        
        # Check that stream 3 is NOT matched
        matched_stream_ids = {match.conn2.stream_id for match in matches}
        if 3 not in matched_stream_ids:
            print(f"✅ PASS: A Stream 3 correctly NOT matched (no time overlap)")
        else:
            print(f"❌ FAIL: A Stream 3 should NOT be matched (no time overlap)")
    else:
        print(f"❌ FAIL: Found {len(matches)} matches (expected {expected_matches})")
        print()
        print("Note: Current matcher uses greedy one-to-one matching.")
        print("B Stream 0 can only match ONE A stream (highest score).")
        print("To match all overlapping streams, need to implement one-to-many matching.")
    
    print()
    print("=" * 80)
    print("Summary:")
    print("=" * 80)
    print()
    print("✅ Time range fields added to TcpConnection:")
    print("   - first_packet_time")
    print("   - last_packet_time")
    print("   - packet_count")
    print()
    print("✅ Time overlap check added to ConnectionScorer:")
    print("   - _check_time_overlap() method")
    print("   - Checks if time ranges [first, last] overlap")
    print("   - Returns 'no-time-overlap' evidence if no overlap")
    print()
    print("⚠️  Current limitation:")
    print("   - Greedy one-to-one matching still applies")
    print("   - B Stream 0 can only match ONE A stream")
    print("   - To match all overlapping streams, need one-to-many matching")
    print()

if __name__ == "__main__":
    main()

