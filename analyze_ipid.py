#!/usr/bin/env python3
"""Analyze IPID overlap for matched connections."""

import sys
from pathlib import Path

# Add capmaster to path
sys.path.insert(0, str(Path(__file__).parent))

from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.core.connection.scorer import ConnectionScorer

def main():
    pcap_dir = Path("/Users/ricky/Downloads/2hops/dbs_1112")

    # Extract connections from both files
    print("Extracting connections from x01saulvweb3a-L.pcap...")
    conns1 = extract_connections_from_pcap(pcap_dir / "x01saulvweb3a-L.pcap")

    print("Extracting connections from x01saulvweb3a-c.pcap...")
    conns2 = extract_connections_from_pcap(pcap_dir / "x01saulvweb3a-c.pcap")
    
    # Find the matched pair
    # A: 10.52.170.71:36114 <-> 10.95.35.148:8080
    # B: 10.52.170.71:44614 <-> 10.95.35.148:8080
    
    conn1 = None
    conn2 = None
    
    for c in conns1:
        if ((c.client_ip == "10.52.170.71" and c.client_port == 36114 and 
             c.server_ip == "10.95.35.148" and c.server_port == 8080) or
            (c.server_ip == "10.52.170.71" and c.server_port == 36114 and 
             c.client_ip == "10.95.35.148" and c.client_port == 8080)):
            conn1 = c
            break
    
    for c in conns2:
        if ((c.client_ip == "10.52.170.71" and c.client_port == 44614 and 
             c.server_ip == "10.95.35.148" and c.server_port == 8080) or
            (c.server_ip == "10.52.170.71" and c.server_port == 44614 and 
             c.client_ip == "10.95.35.148" and c.client_port == 8080)):
            conn2 = c
            break
    
    if not conn1:
        print("ERROR: Could not find connection 1")
        return
    
    if not conn2:
        print("ERROR: Could not find connection 2")
        return
    
    print("\n" + "="*80)
    print("Connection 1 (x01saulvweb3a-L.pcap)")
    print("="*80)
    print(f"  5-tuple: {conn1.client_ip}:{conn1.client_port} <-> {conn1.server_ip}:{conn1.server_port}")
    print(f"  Stream ID: {conn1.stream_id}")
    print(f"  Packets: {conn1.packet_count}")
    print(f"  IPID set size: {len(conn1.ipid_set)}")
    print(f"  IPID values: {sorted(conn1.ipid_set)}")
    
    print("\n" + "="*80)
    print("Connection 2 (x01saulvweb3a-c.pcap)")
    print("="*80)
    print(f"  5-tuple: {conn2.client_ip}:{conn2.client_port} <-> {conn2.server_ip}:{conn2.server_port}")
    print(f"  Stream ID: {conn2.stream_id}")
    print(f"  Packets: {conn2.packet_count}")
    print(f"  IPID set size: {len(conn2.ipid_set)}")
    print(f"  IPID values: {sorted(conn2.ipid_set)}")
    
    # Calculate overlap
    intersection = conn1.ipid_set & conn2.ipid_set
    overlap_count = len(intersection)
    min_set_size = min(len(conn1.ipid_set), len(conn2.ipid_set))
    overlap_ratio = overlap_count / min_set_size if min_set_size > 0 else 0.0
    
    print("\n" + "="*80)
    print("IPID Overlap Analysis")
    print("="*80)
    print(f"  Intersection size: {overlap_count}")
    print(f"  Min set size: {min_set_size}")
    print(f"  Overlap ratio: {overlap_ratio:.4f} ({overlap_ratio*100:.2f}%)")
    print(f"  Overlapping IPIDs: {sorted(intersection)}")
    
    # Check strong IPID condition
    scorer = ConnectionScorer()
    is_strong = (overlap_count >= scorer.STRONG_IPID_MIN_OVERLAP and 
                 overlap_ratio >= scorer.STRONG_IPID_MIN_RATIO)
    
    print(f"\n  Strong IPID threshold: {scorer.STRONG_IPID_MIN_OVERLAP} overlaps AND {scorer.STRONG_IPID_MIN_RATIO} ratio")
    print(f"  Is strong IPID match: {is_strong} {'✅' if is_strong else '❌'}")
    
    # Show non-overlapping IPIDs
    only_in_1 = conn1.ipid_set - conn2.ipid_set
    only_in_2 = conn2.ipid_set - conn1.ipid_set

    if only_in_1:
        print(f"\n  IPIDs only in connection 1: {sorted(only_in_1)}")
    if only_in_2:
        print(f"  IPIDs only in connection 2: {sorted(only_in_2)}")

    # Analyze IPID by direction
    print("\n" + "="*80)
    print("IPID Distribution by Direction")
    print("="*80)

    # Re-extract packets to analyze IPID by direction
    from capmaster.core.connection.extractor import TcpFieldExtractor

    extractor = TcpFieldExtractor()

    # Analyze connection 1
    print("\nConnection 1 (x01saulvweb3a-L.pcap):")
    packets1 = list(extractor.extract(pcap_dir / "x01saulvweb3a-L.pcap"))
    stream1_packets = [p for p in packets1 if p.stream_id == conn1.stream_id]

    # Group by direction
    client_to_server_ipids_1 = set()
    server_to_client_ipids_1 = set()

    for pkt in stream1_packets:
        # Determine direction based on source IP/port
        if pkt.src_ip == conn1.client_ip and pkt.src_port == conn1.client_port:
            # Client -> Server
            if pkt.ip_id != 0:
                client_to_server_ipids_1.add(pkt.ip_id)
        elif pkt.src_ip == conn1.server_ip and pkt.src_port == conn1.server_port:
            # Server -> Client
            if pkt.ip_id != 0:
                server_to_client_ipids_1.add(pkt.ip_id)

    # Count zero IPIDs
    zero_ipids_c2s_1 = sum(1 for p in stream1_packets
                           if p.src_ip == conn1.client_ip and p.src_port == conn1.client_port and p.ip_id == 0)
    zero_ipids_s2c_1 = sum(1 for p in stream1_packets
                           if p.src_ip == conn1.server_ip and p.src_port == conn1.server_port and p.ip_id == 0)

    print(f"  Client -> Server:")
    print(f"    Non-zero IPIDs: {len(client_to_server_ipids_1)}")
    print(f"    Zero IPIDs: {zero_ipids_c2s_1}")
    print(f"    IPID range: {min(client_to_server_ipids_1) if client_to_server_ipids_1 else 'N/A'} - {max(client_to_server_ipids_1) if client_to_server_ipids_1 else 'N/A'}")

    print(f"  Server -> Client:")
    print(f"    Non-zero IPIDs: {len(server_to_client_ipids_1)}")
    print(f"    Zero IPIDs: {zero_ipids_s2c_1}")
    print(f"    IPID range: {min(server_to_client_ipids_1) if server_to_client_ipids_1 else 'N/A'} - {max(server_to_client_ipids_1) if server_to_client_ipids_1 else 'N/A'}")

    # Analyze connection 2
    print("\nConnection 2 (x01saulvweb3a-c.pcap):")
    packets2 = list(extractor.extract(pcap_dir / "x01saulvweb3a-c.pcap"))
    stream2_packets = [p for p in packets2 if p.stream_id == conn2.stream_id]

    # Group by direction
    client_to_server_ipids_2 = set()
    server_to_client_ipids_2 = set()

    for pkt in stream2_packets:
        # Determine direction based on source IP/port
        if pkt.src_ip == conn2.client_ip and pkt.src_port == conn2.client_port:
            # Client -> Server
            if pkt.ip_id != 0:
                client_to_server_ipids_2.add(pkt.ip_id)
        elif pkt.src_ip == conn2.server_ip and pkt.src_port == conn2.server_port:
            # Server -> Client
            if pkt.ip_id != 0:
                server_to_client_ipids_2.add(pkt.ip_id)

    # Count zero IPIDs
    zero_ipids_c2s_2 = sum(1 for p in stream2_packets
                           if p.src_ip == conn2.client_ip and p.src_port == conn2.client_port and p.ip_id == 0)
    zero_ipids_s2c_2 = sum(1 for p in stream2_packets
                           if p.src_ip == conn2.server_ip and p.src_port == conn2.server_port and p.ip_id == 0)

    print(f"  Client -> Server:")
    print(f"    Non-zero IPIDs: {len(client_to_server_ipids_2)}")
    print(f"    Zero IPIDs: {zero_ipids_c2s_2}")
    print(f"    IPID range: {min(client_to_server_ipids_2) if client_to_server_ipids_2 else 'N/A'} - {max(client_to_server_ipids_2) if client_to_server_ipids_2 else 'N/A'}")

    print(f"  Server -> Client:")
    print(f"    Non-zero IPIDs: {len(server_to_client_ipids_2)}")
    print(f"    Zero IPIDs: {zero_ipids_s2c_2}")
    print(f"    IPID range: {min(server_to_client_ipids_2) if server_to_client_ipids_2 else 'N/A'} - {max(server_to_client_ipids_2) if server_to_client_ipids_2 else 'N/A'}")

    # Cross-direction overlap analysis
    print("\n" + "="*80)
    print("Cross-Direction Overlap Analysis")
    print("="*80)

    # Check if all overlap comes from one direction
    c2s_overlap = client_to_server_ipids_1 & client_to_server_ipids_2
    s2c_overlap = server_to_client_ipids_1 & server_to_client_ipids_2

    print(f"\nClient->Server IPID overlap: {len(c2s_overlap)}")
    print(f"Server->Client IPID overlap: {len(s2c_overlap)}")
    print(f"Total overlap: {len(intersection)}")

    if len(c2s_overlap) == 0 and len(s2c_overlap) > 0:
        print("\n⚠️  WARNING: All IPID overlap comes from Server->Client direction!")
        print("    Client->Server IPIDs are likely all 0x0000")
    elif len(s2c_overlap) == 0 and len(c2s_overlap) > 0:
        print("\n⚠️  WARNING: All IPID overlap comes from Client->Server direction!")
        print("    Server->Client IPIDs are likely all 0x0000")
    elif len(c2s_overlap) > 0 and len(s2c_overlap) > 0:
        print("\n✅ IPID overlap exists in both directions (healthy)")

if __name__ == "__main__":
    main()

