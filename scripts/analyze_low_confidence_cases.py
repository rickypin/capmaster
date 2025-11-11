#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detailed analysis of low confidence match cases.
Extracts all features and explains why confidence is low.
"""
from __future__ import annotations

import sys
from pathlib import Path

from capmaster.plugins.match.connection_extractor import extract_connections_from_pcap
from capmaster.plugins.match.matcher import ConnectionMatcher, BucketStrategy, MatchMode
from capmaster.plugins.match.server_detector import ServerDetector
from capmaster.plugins.match.scorer import ConnectionScorer
from capmaster.plugins.match.plugin import MatchPlugin
from capmaster.plugins.match.connection import TcpConnection


def format_ipid_set(ipid_set: set[int]) -> str:
    """Format IPID set for display."""
    if not ipid_set:
        return "None"
    sorted_ipids = sorted(ipid_set)
    if len(sorted_ipids) <= 10:
        return ", ".join(str(x) for x in sorted_ipids)
    else:
        return f"{len(sorted_ipids)} unique values: [{sorted_ipids[0]}...{sorted_ipids[-1]}]"


def analyze_connection(conn: TcpConnection, label: str) -> None:
    """Print detailed connection features."""
    print(f"\n{'='*80}")
    print(f"{label}")
    print(f"{'='*80}")

    # Basic info
    print(f"\n[Basic Info]")
    print(f"  5-tuple: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
    print(f"  Stream ID: {conn.stream_id}")
    print(f"  Packet count: {conn.packet_count}")
    print(f"  Time range: {conn.first_packet_time:.6f} - {conn.last_packet_time:.6f}")
    print(f"  Duration: {conn.last_packet_time - conn.first_packet_time:.6f} seconds")
    print(f"  Header only: {conn.is_header_only}")
    print(f"  Total bytes: {conn.total_bytes}")

    # SYN options
    print(f"\n[SYN Options]")
    print(f"  SYN options: {conn.syn_options if conn.syn_options else 'None'}")

    # ISN
    print(f"\n[Initial Sequence Numbers]")
    print(f"  Client ISN: {conn.client_isn}")
    print(f"  Server ISN: {conn.server_isn}")

    # Timestamps
    print(f"\n[TCP Timestamps]")
    print(f"  TSval: {conn.tcp_timestamp_tsval if conn.tcp_timestamp_tsval else 'None'}")
    print(f"  TSecr: {conn.tcp_timestamp_tsecr if conn.tcp_timestamp_tsecr else 'None'}")

    # TTL
    print(f"\n[TTL Values]")
    print(f"  Client TTL: {conn.client_ttl if conn.client_ttl > 0 else 'N/A'}")
    print(f"  Server TTL: {conn.server_ttl if conn.server_ttl > 0 else 'N/A'}")

    # IPID
    print(f"\n[IP Identification]")
    print(f"  IPID first: {conn.ipid_first}")
    print(f"  Total IPID count: {len(conn.ipid_set)}")
    print(f"  Total IPID set: {format_ipid_set(conn.ipid_set)}")
    print(f"  Client IPID count: {len(conn.client_ipid_set)}")
    print(f"  Client IPID set: {format_ipid_set(conn.client_ipid_set)}")
    print(f"  Server IPID count: {len(conn.server_ipid_set)}")
    print(f"  Server IPID set: {format_ipid_set(conn.server_ipid_set)}")

    # Payload
    print(f"\n[Payload MD5]")
    print(f"  Client payload MD5: {conn.client_payload_md5 if conn.client_payload_md5 else 'None'}")
    print(f"  Server payload MD5: {conn.server_payload_md5 if conn.server_payload_md5 else 'None'}")

    # Length signature
    print(f"\n[Length Signature]")
    if conn.length_signature:
        # Parse length signature string
        parts = conn.length_signature.split()
        print(f"  Length signature: {len(parts)} entries")
        if len(parts) <= 20:
            print(f"  Full signature: {conn.length_signature}")
        else:
            print(f"  First 10: {' '.join(parts[:10])}")
            print(f"  Last 10: {' '.join(parts[-10:])}")
    else:
        print(f"  Length signature: None")


def analyze_match_score(conn1: TcpConnection, conn2: TcpConnection) -> None:
    """Analyze why the match score is what it is."""
    print(f"\n{'='*80}")
    print(f"MATCH SCORE ANALYSIS")
    print(f"{'='*80}")

    scorer = ConnectionScorer()

    # Get the match score
    score = scorer.score(conn1, conn2, use_payload=True)

    if not score:
        print("\n❌ No match score (should not happen if they matched)")
        return

    print(f"\n[Overall Score]")
    print(f"  Normalized score: {score.normalized_score:.4f}")
    print(f"  Raw score: {score.raw_score:.4f}")
    print(f"  Available weight: {score.available_weight:.4f}")
    print(f"  Evidence: {score.evidence}")
    print(f"  IPID match (necessary): {score.ipid_match}")

    # Analyze each feature
    print(f"\n[Feature Analysis]")

    # 1. SYN options
    print(f"\n  1. SYN Options:")
    if conn1.syn_options and conn2.syn_options:
        if conn1.syn_options == conn2.syn_options:
            print(f"     ✅ SYN options MATCH")
            print(f"        Value: {conn1.syn_options}")
        else:
            print(f"     ❌ SYN options DIFFER")
            print(f"        A: {conn1.syn_options}")
            print(f"        B: {conn2.syn_options}")
    else:
        print(f"     ⚠️  SYN options not available in both")
        print(f"        A: {conn1.syn_options if conn1.syn_options else 'None'}")
        print(f"        B: {conn2.syn_options if conn2.syn_options else 'None'}")

    # 2. Client ISN
    print(f"\n  2. Client ISN:")
    if conn1.client_isn == conn2.client_isn:
        print(f"     ✅ Client ISN MATCH: {conn1.client_isn}")
    else:
        print(f"     ❌ Client ISN DIFFER")
        print(f"        A: {conn1.client_isn}")
        print(f"        B: {conn2.client_isn}")

    # 3. Server ISN
    print(f"\n  3. Server ISN:")
    if conn1.server_isn == conn2.server_isn:
        print(f"     ✅ Server ISN MATCH: {conn1.server_isn}")
    else:
        print(f"     ❌ Server ISN DIFFER")
        print(f"        A: {conn1.server_isn}")
        print(f"        B: {conn2.server_isn}")

    # 4. Timestamps
    print(f"\n  4. TCP Timestamps:")
    if conn1.tcp_timestamp_tsval and conn2.tcp_timestamp_tsval:
        if conn1.tcp_timestamp_tsval == conn2.tcp_timestamp_tsval:
            print(f"     ✅ TSval MATCH: {conn1.tcp_timestamp_tsval}")
        else:
            print(f"     ❌ TSval DIFFER")
            print(f"        A: {conn1.tcp_timestamp_tsval}")
            print(f"        B: {conn2.tcp_timestamp_tsval}")
    else:
        print(f"     ⚠️  TSval not available in both")
        print(f"        A: {conn1.tcp_timestamp_tsval if conn1.tcp_timestamp_tsval else 'None'}")
        print(f"        B: {conn2.tcp_timestamp_tsval if conn2.tcp_timestamp_tsval else 'None'}")

    if conn1.tcp_timestamp_tsecr and conn2.tcp_timestamp_tsecr:
        if conn1.tcp_timestamp_tsecr == conn2.tcp_timestamp_tsecr:
            print(f"     ✅ TSecr MATCH: {conn1.tcp_timestamp_tsecr}")
        else:
            print(f"     ❌ TSecr DIFFER")
            print(f"        A: {conn1.tcp_timestamp_tsecr}")
            print(f"        B: {conn2.tcp_timestamp_tsecr}")
    else:
        print(f"     ⚠️  TSecr not available in both")
        print(f"        A: {conn1.tcp_timestamp_tsecr if conn1.tcp_timestamp_tsecr else 'None'}")
        print(f"        B: {conn2.tcp_timestamp_tsecr if conn2.tcp_timestamp_tsecr else 'None'}")
    
    # 5. TTL
    print(f"\n  5. TTL Values:")
    if conn1.client_ttl > 0 and conn2.client_ttl > 0:
        diff = abs(conn1.client_ttl - conn2.client_ttl)
        if diff <= 2:
            print(f"     ✅ Client TTL CLOSE: A={conn1.client_ttl}, B={conn2.client_ttl}, diff={diff}")
        else:
            print(f"     ❌ Client TTL DIFFER: A={conn1.client_ttl}, B={conn2.client_ttl}, diff={diff}")
    else:
        print(f"     ⚠️  Client TTL not available in both")
        print(f"        A: {conn1.client_ttl}")
        print(f"        B: {conn2.client_ttl}")

    if conn1.server_ttl > 0 and conn2.server_ttl > 0:
        diff = abs(conn1.server_ttl - conn2.server_ttl)
        if diff <= 2:
            print(f"     ✅ Server TTL CLOSE: A={conn1.server_ttl}, B={conn2.server_ttl}, diff={diff}")
        else:
            print(f"     ❌ Server TTL DIFFER: A={conn1.server_ttl}, B={conn2.server_ttl}, diff={diff}")
    else:
        print(f"     ⚠️  Server TTL not available in both")
        print(f"        A: {conn1.server_ttl}")
        print(f"        B: {conn2.server_ttl}")

    # 6. IPID
    print(f"\n  6. IP Identification:")
    total_overlap = len(conn1.ipid_set & conn2.ipid_set)
    client_overlap = len(conn1.client_ipid_set & conn2.client_ipid_set)
    server_overlap = len(conn1.server_ipid_set & conn2.server_ipid_set)

    print(f"     Total IPID overlap: {total_overlap} (from {len(conn1.ipid_set)} and {len(conn2.ipid_set)})")
    print(f"     Client IPID overlap: {client_overlap}")
    print(f"     Server IPID overlap: {server_overlap}")

    if total_overlap >= 10:
        print(f"     ✅ STRONG IPID overlap (≥10) - This is a SUFFICIENT condition!")
    elif total_overlap >= 2:
        print(f"     ⚠️  Weak IPID overlap (2-9) - Necessary but not sufficient")
    else:
        print(f"     ❌ Insufficient IPID overlap (<2) - Would fail matching")

    # 7. Payload
    print(f"\n  7. Payload MD5:")
    if conn1.client_payload_md5 and conn2.client_payload_md5:
        if conn1.client_payload_md5 == conn2.client_payload_md5:
            print(f"     ✅ Client payload MD5 MATCH: {conn1.client_payload_md5}")
        else:
            print(f"     ❌ Client payload MD5 DIFFER")
            print(f"        A: {conn1.client_payload_md5}")
            print(f"        B: {conn2.client_payload_md5}")
    else:
        print(f"     ⚠️  Client payload MD5 not available")
        print(f"        A: {conn1.client_payload_md5 if conn1.client_payload_md5 else 'None'}")
        print(f"        B: {conn2.client_payload_md5 if conn2.client_payload_md5 else 'None'}")

    if conn1.server_payload_md5 and conn2.server_payload_md5:
        if conn1.server_payload_md5 == conn2.server_payload_md5:
            print(f"     ✅ Server payload MD5 MATCH: {conn1.server_payload_md5}")
        else:
            print(f"     ❌ Server payload MD5 DIFFER")
            print(f"        A: {conn1.server_payload_md5}")
            print(f"        B: {conn2.server_payload_md5}")
    else:
        print(f"     ⚠️  Server payload MD5 not available")
        print(f"        A: {conn1.server_payload_md5 if conn1.server_payload_md5 else 'None'}")
        print(f"        B: {conn2.server_payload_md5 if conn2.server_payload_md5 else 'None'}")

    # 8. Length signature
    print(f"\n  8. Length Signature:")
    if conn1.length_signature and conn2.length_signature:
        # Parse length signatures
        parts1 = conn1.length_signature.split()
        parts2 = conn2.length_signature.split()

        # Calculate Jaccard similarity on the string representation
        set1 = set(parts1)
        set2 = set(parts2)
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        similarity = intersection / union if union > 0 else 0.0

        if similarity >= 0.5:
            print(f"     ✅ Length signature SIMILAR: Jaccard={similarity:.4f}")
        else:
            print(f"     ❌ Length signature DIFFER: Jaccard={similarity:.4f}")
        print(f"        A: {len(parts1)} entries, {len(set1)} unique")
        print(f"        B: {len(parts2)} entries, {len(set2)} unique")
    else:
        print(f"     ⚠️  Length signature not available")
        print(f"        A: {'Yes' if conn1.length_signature else 'None'}")
        print(f"        B: {'Yes' if conn2.length_signature else 'None'}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_low_confidence_cases.py <case_dir>")
        sys.exit(1)
    
    case_dir = Path(sys.argv[1])
    if not case_dir.is_dir():
        print(f"Error: {case_dir} is not a directory")
        sys.exit(1)
    
    # Find PCAP files
    pcaps = [f for f in case_dir.iterdir() if f.suffix.lower() in (".pcap", ".pcapng")]
    if len(pcaps) != 2:
        print(f"Error: Expected 2 PCAP files, found {len(pcaps)}")
        sys.exit(1)
    
    pcaps = sorted(pcaps)
    f1, f2 = pcaps
    
    print(f"{'='*80}")
    print(f"DETAILED ANALYSIS: {case_dir.name}")
    print(f"{'='*80}")
    print(f"PCAP A: {f1.name}")
    print(f"PCAP B: {f2.name}")
    
    # Extract connections
    conns1 = extract_connections_from_pcap(f1)
    conns2 = extract_connections_from_pcap(f2)
    
    print(f"\nConnections found: A={len(conns1)}, B={len(conns2)}")
    
    if len(conns1) != 1 or len(conns2) != 1:
        print("Warning: Expected exactly 1 connection in each file")
    
    # Improve server detection
    det = ServerDetector()
    for c in conns1:
        det.collect_connection(c)
    for c in conns2:
        det.collect_connection(c)
    det.finalize_cardinality()
    
    plug = MatchPlugin()
    conns1 = plug._improve_server_detection(conns1, det)
    conns2 = plug._improve_server_detection(conns2, det)
    
    # Analyze each connection
    if conns1:
        analyze_connection(conns1[0], "CONNECTION A")
    if conns2:
        analyze_connection(conns2[0], "CONNECTION B")
    
    # Analyze match score
    if conns1 and conns2:
        analyze_match_score(conns1[0], conns2[0])
    
    # Match
    matcher = ConnectionMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
        match_mode=MatchMode.ONE_TO_ONE,
    )
    matches = matcher.match(conns1, conns2)
    
    print(f"\n{'='*80}")
    print(f"FINAL RESULT")
    print(f"{'='*80}")
    print(f"Matched: {len(matches) > 0}")
    if matches:
        m = matches[0]
        print(f"Score: {m.score.normalized_score:.4f}")
        print(f"Evidence: {m.score.evidence}")


if __name__ == "__main__":
    main()

