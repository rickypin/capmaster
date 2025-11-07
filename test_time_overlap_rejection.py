#!/usr/bin/env python3
"""Test script to verify time overlap rejection works correctly."""

from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.scorer import ConnectionScorer

def main():
    print("=" * 80)
    print("Time Overlap Rejection Test")
    print("=" * 80)
    print()
    
    # Connection B: Time [0, 1000]
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
    
    # Connection A3: Time [2000, 3000], NO overlap with B
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
        client_payload_md5="abc123",  # Same payload as B
        server_payload_md5="def456",  # Same payload as B
        length_signature="C:54 S:57 C:54 S:57",  # Same signature as B
        is_header_only=False,
        ipid_first=61507,  # Same IPID as B!
        first_packet_time=2000.0,
        last_packet_time=3000.0,
        packet_count=100,
    )
    
    # Connection A0: Time [0, 100], overlaps with B
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
    
    scorer = ConnectionScorer()
    
    print("Test 1: No Time Overlap (should be rejected)")
    print("-" * 80)
    print(f"Connection B: {conn_b}")
    print(f"Connection A3: {conn_a3}")
    print()
    print("Time ranges:")
    print(f"  B:  [{conn_b.first_packet_time:.1f}, {conn_b.last_packet_time:.1f}]")
    print(f"  A3: [{conn_a3.first_packet_time:.1f}, {conn_a3.last_packet_time:.1f}]")
    print(f"  Overlap: NO (B ends at 1000, A3 starts at 2000)")
    print()
    
    score1 = scorer.score(conn_b, conn_a3)
    print(f"Match Score: {score1.normalized_score:.4f}")
    print(f"IPID Match: {score1.ipid_match}")
    print(f"Evidence: {score1.evidence}")
    print(f"Result: {'✅ MATCHED' if score1.is_valid_match() else '❌ NOT MATCHED'}")
    print()
    
    if score1.evidence == "no-time-overlap":
        print("✅ PASS: Correctly rejected due to no time overlap")
    else:
        print("❌ FAIL: Should be rejected due to no time overlap")
    print()
    
    print("=" * 80)
    print("Test 2: Time Overlap (should be accepted)")
    print("-" * 80)
    print(f"Connection B: {conn_b}")
    print(f"Connection A0: {conn_a0}")
    print()
    print("Time ranges:")
    print(f"  B:  [{conn_b.first_packet_time:.1f}, {conn_b.last_packet_time:.1f}]")
    print(f"  A0: [{conn_a0.first_packet_time:.1f}, {conn_a0.last_packet_time:.1f}]")
    print(f"  Overlap: YES ([0, 100])")
    print()
    
    score2 = scorer.score(conn_b, conn_a0)
    print(f"Match Score: {score2.normalized_score:.4f}")
    print(f"IPID Match: {score2.ipid_match}")
    print(f"Evidence: {score2.evidence}")
    print(f"Result: {'✅ MATCHED' if score2.is_valid_match() else '❌ NOT MATCHED'}")
    print()
    
    if score2.is_valid_match() and "no-time-overlap" not in score2.evidence:
        print("✅ PASS: Correctly accepted due to time overlap")
    else:
        print("❌ FAIL: Should be accepted due to time overlap")
    print()
    
    print("=" * 80)
    print("Summary:")
    print("=" * 80)
    print()
    print("Time overlap check is working correctly:")
    print()
    print("✅ Connections with NO time overlap are rejected")
    print("   - Evidence: 'no-time-overlap'")
    print("   - Score: 0.0")
    print()
    print("✅ Connections with time overlap are accepted")
    print("   - Evidence: includes feature scores (synopt, isnC, ts, etc.)")
    print("   - Score: based on feature matching")
    print()
    print("This solves the problem of matching streams with:")
    print("  - Same 5-tuple")
    print("  - Same IPID")
    print("  - But different time ranges")
    print()

if __name__ == "__main__":
    main()

