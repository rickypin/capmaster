#!/usr/bin/env python3
"""Test script to verify what happens when IPID is same but direction is reversed."""

from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.scorer import ConnectionScorer

def main():
    print("=" * 80)
    print("Edge Case: Same IPID, Reversed Direction")
    print("=" * 80)
    print()
    
    # Connection 1: Client=A, Server=B
    conn1 = TcpConnection(
        stream_id=0,
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
    )
    
    # Connection 2: Client=B, Server=A (REVERSED), but SAME IPID
    conn2_reversed_same_ipid = TcpConnection(
        stream_id=1,
        client_ip="8.67.2.125",  # Swapped
        client_port=26302,        # Swapped
        server_ip="8.42.96.45",   # Swapped
        server_port=35101,        # Swapped
        syn_timestamp=1757441703.689601,
        syn_options="020405b40402080a7a3c283c0000000001030307",  # Different
        client_isn=300,  # Different
        server_isn=400,  # Different
        tcp_timestamp_tsval="2050762812",  # Different
        tcp_timestamp_tsecr="0",
        client_payload_md5="xyz789",  # Different
        server_payload_md5="uvw012",  # Different
        length_signature="C:100 S:200",  # Different
        is_header_only=False,
        ipid_first=61507,  # SAME IPID!
    )
    
    scorer = ConnectionScorer()
    
    print("Scenario: Same 5-tuple IPs/Ports, OPPOSITE direction, SAME IPID")
    print("-" * 80)
    print(f"Connection 1:")
    print(f"  Direction: {conn1.client_ip}:{conn1.client_port} → {conn1.server_ip}:{conn1.server_port}")
    print(f"  IPID: {conn1.ipid_first}")
    print(f"  SYN options: {conn1.syn_options[:30]}...")
    print(f"  Client ISN: {conn1.client_isn}, Server ISN: {conn1.server_isn}")
    print(f"  Timestamp: TSval={conn1.tcp_timestamp_tsval}, TSecr={conn1.tcp_timestamp_tsecr}")
    print(f"  Client payload MD5: {conn1.client_payload_md5}")
    print(f"  Server payload MD5: {conn1.server_payload_md5}")
    print(f"  Length signature: {conn1.length_signature}")
    print()
    
    print(f"Connection 2:")
    print(f"  Direction: {conn2_reversed_same_ipid.client_ip}:{conn2_reversed_same_ipid.client_port} → {conn2_reversed_same_ipid.server_ip}:{conn2_reversed_same_ipid.server_port}")
    print(f"  IPID: {conn2_reversed_same_ipid.ipid_first}")
    print(f"  SYN options: {conn2_reversed_same_ipid.syn_options[:30]}...")
    print(f"  Client ISN: {conn2_reversed_same_ipid.client_isn}, Server ISN: {conn2_reversed_same_ipid.server_isn}")
    print(f"  Timestamp: TSval={conn2_reversed_same_ipid.tcp_timestamp_tsval}, TSecr={conn2_reversed_same_ipid.tcp_timestamp_tsecr}")
    print(f"  Client payload MD5: {conn2_reversed_same_ipid.client_payload_md5}")
    print(f"  Server payload MD5: {conn2_reversed_same_ipid.server_payload_md5}")
    print(f"  Length signature: {conn2_reversed_same_ipid.length_signature}")
    print()
    
    score = scorer.score(conn1, conn2_reversed_same_ipid)
    
    print("Match Result:")
    print("-" * 80)
    print(f"Normalized Score: {score.normalized_score:.4f}")
    print(f"Raw Score: {score.raw_score:.4f}")
    print(f"Available Weight: {score.available_weight:.4f}")
    print(f"IPID Match: {score.ipid_match}")
    print(f"Evidence: {score.evidence}")
    print()
    print(f"Feature Scores:")
    print(f"  SYN options: {score.syn_options_score:.4f}")
    print(f"  Client ISN: {score.isn_client_score:.4f}")
    print(f"  Server ISN: {score.isn_server_score:.4f}")
    print(f"  TCP timestamp: {score.timestamp_score:.4f}")
    print(f"  Client payload: {score.payload_client_score:.4f}")
    print(f"  Server payload: {score.payload_server_score:.4f}")
    print(f"  Length signature: {score.length_sig_score:.4f}")
    print(f"  IPID: {score.ipid_score:.4f}")
    print()
    print(f"Is Valid Match (threshold=0.60): {'✅ YES' if score.is_valid_match() else '❌ NO'}")
    print()
    
    print("=" * 80)
    print("Analysis:")
    print("=" * 80)
    print()
    print("✅ IPID matches (61507 == 61507) - passes the 必要条件")
    print()
    print("But other features DON'T match because direction is reversed:")
    print("  ❌ SYN options are different")
    print("  ❌ Client ISN is different (conn1.client != conn2.client)")
    print("  ❌ Server ISN is different (conn1.server != conn2.server)")
    print("  ❌ TCP timestamp is different")
    print("  ❌ Client payload MD5 is different")
    print("  ❌ Server payload MD5 is different")
    print("  ❌ Length signature is different")
    print()
    print("Conclusion:")
    print(f"  Score: {score.normalized_score:.4f}")
    print(f"  Threshold: 0.60")
    print(f"  Result: {'MATCHED' if score.is_valid_match() else 'NOT MATCHED'}")
    print()
    print("Key Insight:")
    print("  Current logic does NOT explicitly check direction.")
    print("  It relies on feature mismatch to reject reversed connections.")
    print("  If features happen to match despite reversed direction,")
    print("  the connection COULD be incorrectly matched!")
    print()

if __name__ == "__main__":
    main()

