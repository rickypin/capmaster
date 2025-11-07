#!/usr/bin/env python3
"""Debug script to show detailed match process results."""

from pathlib import Path
from capmaster.plugins.match.connection import ConnectionBuilder
from capmaster.plugins.match.extractor import TcpFieldExtractor
from capmaster.plugins.match.matcher import BucketStrategy, ConnectionMatcher

def main():
    # File paths
    file1 = Path("cases/dbs_20251028-Masked/B_processed.pcap")
    file2 = Path("cases/dbs_20251028-Masked/A_processed.pcap")
    
    print("=" * 80)
    print("Match Process Analysis")
    print("=" * 80)
    print(f"File 1 (Baseline): {file1}")
    print(f"File 2 (Compare):  {file2}")
    print()
    
    # Extract connections from both files
    print("Step 1: Extracting connections...")
    print("-" * 80)
    
    extractor = TcpFieldExtractor()
    builder1 = ConnectionBuilder()
    builder2 = ConnectionBuilder()
    
    # Extract from file1
    for packet in extractor.extract(file1):
        builder1.add_packet(packet)
    connections1 = list(builder1.build_connections())

    # Extract from file2
    for packet in extractor.extract(file2):
        builder2.add_packet(packet)
    connections2 = list(builder2.build_connections())
    
    print(f"File 1: Found {len(connections1)} connections")
    for i, conn in enumerate(connections1, 1):
        print(f"  {i}. Stream {conn.stream_id}: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
        print(f"     IPID: {conn.ipid_first}, SYN options: {conn.syn_options[:50]}...")
        print(f"     Client ISN: {conn.client_isn}, Server ISN: {conn.server_isn}")
        print(f"     TCP timestamp: TSval={conn.tcp_timestamp_tsval}, TSecr={conn.tcp_timestamp_tsecr}")
        print(f"     Client payload MD5: {conn.client_payload_md5}")
        print(f"     Server payload MD5: {conn.server_payload_md5}")
        print(f"     Length signature: {conn.length_signature[:100]}...")
        print(f"     Header only: {conn.is_header_only}")
        print()
    
    print(f"File 2: Found {len(connections2)} connections")
    for i, conn in enumerate(connections2, 1):
        print(f"  {i}. Stream {conn.stream_id}: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
        print(f"     IPID: {conn.ipid_first}, SYN options: {conn.syn_options[:50]}...")
        print(f"     Client ISN: {conn.client_isn}, Server ISN: {conn.server_isn}")
        print(f"     TCP timestamp: TSval={conn.tcp_timestamp_tsval}, TSecr={conn.tcp_timestamp_tsecr}")
        print(f"     Client payload MD5: {conn.client_payload_md5}")
        print(f"     Server payload MD5: {conn.server_payload_md5}")
        print(f"     Length signature: {conn.length_signature[:100]}...")
        print(f"     Header only: {conn.is_header_only}")
        print()
    
    # Match connections
    print()
    print("Step 2: Matching connections...")
    print("-" * 80)
    
    matcher = ConnectionMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
    )
    
    matches = matcher.match(connections1, connections2)
    
    print(f"Found {len(matches)} matched connection pairs")
    print()
    
    # Show match details
    for i, match in enumerate(matches, 1):
        print(f"Match {i}:")
        print(f"  Connection 1 (File 1): Stream {match.conn1.stream_id}")
        print(f"    {match.conn1.client_ip}:{match.conn1.client_port} <-> {match.conn1.server_ip}:{match.conn1.server_port}")
        print(f"  Connection 2 (File 2): Stream {match.conn2.stream_id}")
        print(f"    {match.conn2.client_ip}:{match.conn2.client_port} <-> {match.conn2.server_ip}:{match.conn2.server_port}")
        print()
        print(f"  Match Score:")
        print(f"    Normalized Score: {match.score.normalized_score:.4f}")
        print(f"    Raw Score: {match.score.raw_score:.4f}")
        print(f"    Available Weight: {match.score.available_weight:.4f}")
        print(f"    IPID Match: {match.score.ipid_match}")
        print(f"    Evidence: {match.score.evidence}")
        print()
        print(f"  Feature Scores:")
        print(f"    SYN options: {match.score.syn_options_score:.4f}")
        print(f"    Client ISN: {match.score.isn_client_score:.4f}")
        print(f"    Server ISN: {match.score.isn_server_score:.4f}")
        print(f"    TCP timestamp: {match.score.timestamp_score:.4f}")
        print(f"    Client payload: {match.score.payload_client_score:.4f}")
        print(f"    Server payload: {match.score.payload_server_score:.4f}")
        print(f"    Length signature: {match.score.length_sig_score:.4f}")
        print(f"    IPID: {match.score.ipid_score:.4f}")
        print()
    
    # Show unmatched connections
    matched_ids1 = {match.conn1.stream_id for match in matches}
    matched_ids2 = {match.conn2.stream_id for match in matches}
    
    unmatched1 = [c for c in connections1 if c.stream_id not in matched_ids1]
    unmatched2 = [c for c in connections2 if c.stream_id not in matched_ids2]
    
    if unmatched1:
        print()
        print(f"Unmatched connections in File 1: {len(unmatched1)}")
        for conn in unmatched1:
            print(f"  Stream {conn.stream_id}: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
    
    if unmatched2:
        print()
        print(f"Unmatched connections in File 2: {len(unmatched2)}")
        for conn in unmatched2:
            print(f"  Stream {conn.stream_id}: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
    
    print()
    print("=" * 80)

if __name__ == "__main__":
    main()

