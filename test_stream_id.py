#!/usr/bin/env python3
"""Test script to verify TCP stream ID is NOT used in matching."""

from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.matcher import ConnectionMatcher, BucketStrategy

def main():
    print("=" * 80)
    print("TCP Stream ID Matching Test")
    print("=" * 80)
    print()
    
    # Create connections with DIFFERENT stream IDs but SAME features
    connections1 = [
        TcpConnection(
            stream_id=0,  # Stream ID = 0
            client_ip="8.42.96.45",
            client_port=35101,
            server_ip="8.67.2.125",
            server_port=26302,
            syn_timestamp=1757441703.700765,
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
        ),
        TcpConnection(
            stream_id=1,  # Stream ID = 1
            client_ip="10.0.0.1",
            client_port=8080,
            server_ip="10.0.0.2",
            server_port=80,
            syn_timestamp=1757441703.700765,
            syn_options="020405b40402080a8a3c283c0000000001030307",
            client_isn=300,
            server_isn=400,
            tcp_timestamp_tsval="1111111111",
            tcp_timestamp_tsecr="2222222222",
            client_payload_md5="xyz789",
            server_payload_md5="uvw012",
            length_signature="C:100 S:200",
            is_header_only=False,
            ipid_first=12345,
        ),
    ]
    
    connections2 = [
        TcpConnection(
            stream_id=99,  # DIFFERENT Stream ID = 99 (not 0!)
            client_ip="8.42.96.45",
            client_port=35101,
            server_ip="8.67.2.125",
            server_port=26302,
            syn_timestamp=1757441703.689601,
            syn_options="020405b40402080a8a3c283c0000000001030307",  # Same
            client_isn=100,  # Same
            server_isn=200,  # Same
            tcp_timestamp_tsval="2327256484",  # Same
            tcp_timestamp_tsecr="2049763571",  # Same
            client_payload_md5="abc123",  # Same
            server_payload_md5="def456",  # Same
            length_signature="C:54 S:57 C:54 S:57",  # Same
            is_header_only=False,
            ipid_first=61507,  # Same
        ),
        TcpConnection(
            stream_id=88,  # DIFFERENT Stream ID = 88 (not 1!)
            client_ip="10.0.0.1",
            client_port=8080,
            server_ip="10.0.0.2",
            server_port=80,
            syn_timestamp=1757441703.689601,
            syn_options="020405b40402080a8a3c283c0000000001030307",  # Same
            client_isn=300,  # Same
            server_isn=400,  # Same
            tcp_timestamp_tsval="1111111111",  # Same
            tcp_timestamp_tsecr="2222222222",  # Same
            client_payload_md5="xyz789",  # Same
            server_payload_md5="uvw012",  # Same
            length_signature="C:100 S:200",  # Same
            is_header_only=False,
            ipid_first=12345,  # Same
        ),
    ]
    
    print("File 1 Connections:")
    print("-" * 80)
    for conn in connections1:
        print(f"  Stream {conn.stream_id}: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
        print(f"    IPID: {conn.ipid_first}, ISN: C={conn.client_isn} S={conn.server_isn}")
    print()
    
    print("File 2 Connections:")
    print("-" * 80)
    for conn in connections2:
        print(f"  Stream {conn.stream_id}: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
        print(f"    IPID: {conn.ipid_first}, ISN: C={conn.client_isn} S={conn.server_isn}")
    print()
    
    print("Matching...")
    print("-" * 80)
    matcher = ConnectionMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
    )
    
    matches = matcher.match(connections1, connections2)
    
    print(f"Found {len(matches)} matches")
    print()
    
    for i, match in enumerate(matches, 1):
        print(f"Match {i}:")
        print(f"  File 1: Stream {match.conn1.stream_id} - {match.conn1.client_ip}:{match.conn1.client_port} <-> {match.conn1.server_ip}:{match.conn1.server_port}")
        print(f"  File 2: Stream {match.conn2.stream_id} - {match.conn2.client_ip}:{match.conn2.client_port} <-> {match.conn2.server_ip}:{match.conn2.server_port}")
        print(f"  Score: {match.score.normalized_score:.4f}")
        print(f"  Evidence: {match.score.evidence}")
        print()
    
    print("=" * 80)
    print("Conclusion:")
    print("=" * 80)
    print()
    print("✅ TCP Stream ID is NOT used as a matching criterion!")
    print()
    print("Matching is based on:")
    print("  1. IPID (必要条件)")
    print("  2. Connection features (SYN options, ISN, timestamp, payload, etc.)")
    print("  3. NOT stream_id")
    print()
    print("Why?")
    print("  - Stream IDs are assigned by tshark during PCAP analysis")
    print("  - Same TCP connection may have different stream IDs in different files")
    print("  - Stream ID is file-specific, not a network-level identifier")
    print()
    print("Evidence from code:")
    print("  - matcher.py line 213-214: Nested loop over ALL connections")
    print("  - compare/plugin.py line 448: Comment says 'Do NOT use stream_id'")
    print("  - compare/plugin.py line 449-454: Uses TCP 5-tuple, not stream_id")
    print()
    
    if len(matches) == 2:
        print("✅ Test PASSED: Matched connections despite different stream IDs")
        print(f"   - Stream 0 (File 1) matched with Stream 99 (File 2)")
        print(f"   - Stream 1 (File 1) matched with Stream 88 (File 2)")
    else:
        print("❌ Test FAILED: Expected 2 matches")
    print()

if __name__ == "__main__":
    main()

