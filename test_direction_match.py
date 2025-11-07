#!/usr/bin/env python3
"""Test script to verify direction matching logic."""

from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.scorer import ConnectionScorer

def main():
    print("=" * 80)
    print("Direction Matching Test")
    print("=" * 80)
    print()
    
    # Create two connections with SAME 5-tuple but OPPOSITE direction
    # Connection 1: Client=8.42.96.45:35101, Server=8.67.2.125:26302
    conn1 = TcpConnection(
        stream_id=0,
        client_ip="8.42.96.45",
        client_port=35101,
        server_ip="8.67.2.125",
        server_port=26302,
        syn_timestamp=1757441703.700765,
        syn_options="",
        client_isn=0,
        server_isn=0,
        tcp_timestamp_tsval="2327256484",
        tcp_timestamp_tsecr="2049763571",
        client_payload_md5="",
        server_payload_md5="",
        length_signature="C:54 S:57 C:54 S:57",
        is_header_only=False,
        ipid_first=61507,
    )
    
    # Connection 2: Client=8.67.2.125:26302, Server=8.42.96.45:35101 (REVERSED)
    conn2_reversed = TcpConnection(
        stream_id=1,
        client_ip="8.67.2.125",  # Swapped
        client_port=26302,        # Swapped
        server_ip="8.42.96.45",   # Swapped
        server_port=35101,        # Swapped
        syn_timestamp=1757441703.689601,
        syn_options="020405b40402080a7a3c283c0000000001030307",
        client_isn=0,
        server_isn=0,
        tcp_timestamp_tsval="2050762812",  # Different
        tcp_timestamp_tsecr="0",
        client_payload_md5="",
        server_payload_md5="",
        length_signature="",
        is_header_only=True,
        ipid_first=9053,  # Different IPID
    )
    
    # Connection 3: Same direction as conn1, same IPID
    conn3_same_direction = TcpConnection(
        stream_id=0,
        client_ip="8.42.96.45",
        client_port=35101,
        server_ip="8.67.2.125",
        server_port=26302,
        syn_timestamp=1757441703.689601,
        syn_options="",
        client_isn=0,
        server_isn=0,
        tcp_timestamp_tsval="2327256484",
        tcp_timestamp_tsecr="2049763571",
        client_payload_md5="",
        server_payload_md5="",
        length_signature="C:54 S:57 C:54 S:57",
        is_header_only=False,
        ipid_first=61507,  # Same IPID as conn1
    )
    
    scorer = ConnectionScorer()
    
    print("Test 1: Same 5-tuple, OPPOSITE direction, DIFFERENT IPID")
    print("-" * 80)
    print(f"Connection 1: {conn1.client_ip}:{conn1.client_port} <-> {conn1.server_ip}:{conn1.server_port}")
    print(f"  IPID: {conn1.ipid_first}, Timestamp: {conn1.tcp_timestamp_tsval}")
    print(f"Connection 2: {conn2_reversed.client_ip}:{conn2_reversed.client_port} <-> {conn2_reversed.server_ip}:{conn2_reversed.server_port}")
    print(f"  IPID: {conn2_reversed.ipid_first}, Timestamp: {conn2_reversed.tcp_timestamp_tsval}")
    print()
    
    score1 = scorer.score(conn1, conn2_reversed)
    print(f"Match Score: {score1.normalized_score:.4f}")
    print(f"IPID Match: {score1.ipid_match}")
    print(f"Evidence: {score1.evidence}")
    print(f"Result: {'✅ MATCHED' if score1.is_valid_match() else '❌ NOT MATCHED'}")
    print()
    
    print("Test 2: Same 5-tuple, SAME direction, SAME IPID")
    print("-" * 80)
    print(f"Connection 1: {conn1.client_ip}:{conn1.client_port} <-> {conn1.server_ip}:{conn1.server_port}")
    print(f"  IPID: {conn1.ipid_first}, Timestamp: {conn1.tcp_timestamp_tsval}")
    print(f"Connection 3: {conn3_same_direction.client_ip}:{conn3_same_direction.client_port} <-> {conn3_same_direction.server_ip}:{conn3_same_direction.server_port}")
    print(f"  IPID: {conn3_same_direction.ipid_first}, Timestamp: {conn3_same_direction.tcp_timestamp_tsval}")
    print()
    
    score2 = scorer.score(conn1, conn3_same_direction)
    print(f"Match Score: {score2.normalized_score:.4f}")
    print(f"IPID Match: {score2.ipid_match}")
    print(f"Evidence: {score2.evidence}")
    print(f"Result: {'✅ MATCHED' if score2.is_valid_match() else '❌ NOT MATCHED'}")
    print()
    
    print("=" * 80)
    print("Conclusion:")
    print("=" * 80)
    print()
    print("Current matching logic:")
    print("1. Does NOT check if client/server IPs match")
    print("2. Does NOT check if direction is the same")
    print("3. ONLY checks if IPID matches (必要条件)")
    print("4. Then scores other features (SYN options, ISN, timestamp, payload, etc.)")
    print()
    print("For reversed connections (same 5-tuple, opposite direction):")
    print("- If IPID is different → NOT MATCHED (IPID requirement fails)")
    print("- If IPID is same → Could be MATCHED (if other features match)")
    print()
    print("In your case:")
    print("- Stream 0: IPID=61507")
    print("- Stream 1-15: IPID=9053, 14265, 49736, ... (all different from 61507)")
    print("- Result: Stream 1-15 are NOT MATCHED because IPID doesn't match")
    print()

if __name__ == "__main__":
    main()

