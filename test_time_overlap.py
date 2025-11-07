#!/usr/bin/env python3
"""
Test script to demonstrate the time overlap problem.

Scenario:
- File A has multiple streams (0-15) with same 5-tuple but different time ranges
- File B has one long stream (0) that spans the entire time range
- Current logic: Only matches based on features, ignores time overlap
- Expected: Each A stream should match a subset of B stream based on time overlap
"""

from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.matcher import ConnectionMatcher, BucketStrategy

def main():
    print("=" * 80)
    print("Time Overlap Problem Demonstration")
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
            syn_timestamp=0.0,  # Start time: 0
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
            # Note: No end_timestamp field in current implementation!
        ),
    ]
    
    # File A: Multiple streams with same 5-tuple but different time ranges
    connections_a = [
        # Stream 0: Time 0-100, IPID 61507 (overlaps with B stream 0)
        TcpConnection(
            stream_id=0,
            client_ip="8.42.96.45",
            client_port=35101,
            server_ip="8.67.2.125",
            server_port=26302,
            syn_timestamp=0.0,  # Time range: 0-100
            syn_options="020405b40402080a8a3c283c0000000001030307",
            client_isn=100,
            server_isn=200,
            tcp_timestamp_tsval="2327256484",
            tcp_timestamp_tsecr="2049763571",
            client_payload_md5="abc123",
            server_payload_md5="def456",
            length_signature="C:54 S:57 C:54 S:57",
            is_header_only=False,
            ipid_first=61507,  # Same IPID as B
        ),
        # Stream 1: Time 100-200, IPID 61507 (also overlaps with B stream 0)
        TcpConnection(
            stream_id=1,
            client_ip="8.42.96.45",
            client_port=35101,
            server_ip="8.67.2.125",
            server_port=26302,
            syn_timestamp=100.0,  # Time range: 100-200
            syn_options="020405b40402080a8a3c283c0000000001030307",
            client_isn=100,
            server_isn=200,
            tcp_timestamp_tsval="2327256484",
            tcp_timestamp_tsecr="2049763571",
            client_payload_md5="xyz789",  # Different payload
            server_payload_md5="uvw012",  # Different payload
            length_signature="C:100 S:200",  # Different signature
            is_header_only=False,
            ipid_first=61507,  # Same IPID as B!
        ),
        # Stream 2: Time 200-300, IPID 61507 (also overlaps with B stream 0)
        TcpConnection(
            stream_id=2,
            client_ip="8.42.96.45",
            client_port=35101,
            server_ip="8.67.2.125",
            server_port=26302,
            syn_timestamp=200.0,  # Time range: 200-300
            syn_options="020405b40402080a8a3c283c0000000001030307",
            client_isn=100,
            server_isn=200,
            tcp_timestamp_tsval="2327256484",
            tcp_timestamp_tsecr="2049763571",
            client_payload_md5="pqr345",  # Different payload
            server_payload_md5="stu678",  # Different payload
            length_signature="C:150 S:250",  # Different signature
            is_header_only=False,
            ipid_first=61507,  # Same IPID as B!
        ),
    ]
    
    print("File B (Baseline):")
    print("-" * 80)
    for conn in connections_b:
        print(f"  Stream {conn.stream_id}: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
        print(f"    Time: {conn.syn_timestamp} - ??? (no end_timestamp)")
        print(f"    IPID: {conn.ipid_first}")
        print(f"    Payload: C={conn.client_payload_md5}, S={conn.server_payload_md5}")
    print()
    
    print("File A (Compare):")
    print("-" * 80)
    for conn in connections_a:
        print(f"  Stream {conn.stream_id}: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
        print(f"    Time: {conn.syn_timestamp} - ??? (no end_timestamp)")
        print(f"    IPID: {conn.ipid_first}")
        print(f"    Payload: C={conn.client_payload_md5}, S={conn.server_payload_md5}")
    print()
    
    print("Current Matching Logic:")
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
        print(f"  File B: Stream {match.conn1.stream_id}")
        print(f"  File A: Stream {match.conn2.stream_id}")
        print(f"  Score: {match.score.normalized_score:.4f}")
        print(f"  Evidence: {match.score.evidence}")
        print()
    
    print("=" * 80)
    print("Problem Analysis:")
    print("=" * 80)
    print()
    print("❌ Current Behavior:")
    print("  - Greedy one-to-one matching")
    print("  - B Stream 0 can only match ONE A stream (highest score)")
    print("  - Other A streams (1, 2) are left unmatched")
    print("  - Even though they all have the same IPID and overlap in time!")
    print()
    print("✅ Expected Behavior:")
    print("  - B Stream 0 should match ALL A streams (0, 1, 2)")
    print("  - Each match represents a time-overlapping subset")
    print("  - One-to-many matching based on time overlap")
    print()
    print("Root Cause:")
    print("  1. TcpConnection lacks time range information (only syn_timestamp)")
    print("  2. Matcher uses greedy one-to-one matching (line 226-229)")
    print("  3. No time overlap check in scoring logic")
    print()
    print("Proposed Solution:")
    print("  1. Add first_packet_time and last_packet_time to TcpConnection")
    print("  2. Add time overlap check in ConnectionScorer")
    print("  3. Consider changing to one-to-many matching for time-overlapping streams")
    print()
    print("Example:")
    print("  B Stream 0: Time [0, 1000], IPID 61507")
    print("  A Stream 0: Time [0, 100], IPID 61507 → Match (overlap: [0, 100])")
    print("  A Stream 1: Time [100, 200], IPID 61507 → Match (overlap: [100, 200])")
    print("  A Stream 2: Time [200, 300], IPID 61507 → Match (overlap: [200, 300])")
    print()

if __name__ == "__main__":
    main()

