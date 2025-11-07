#!/usr/bin/env python3
"""Debug script to analyze TC-001-1-20160407 matching."""

from pathlib import Path
from capmaster.plugins.match.extractor import TcpFieldExtractor
from capmaster.plugins.match.connection import ConnectionBuilder
from capmaster.plugins.match.scorer import ConnectionScorer

# Extract connections from both files
extractor = TcpFieldExtractor()
builder = ConnectionBuilder()

print("Extracting connections from file A...")
builder_a = ConnectionBuilder()
for packet in extractor.extract(Path("cases/TC-001-1-20160407/TC-001-1-20160407-A.pcap")):
    builder_a.add_packet(packet)
conns_a = list(builder_a.build_connections())
print(f"Found {len(conns_a)} connections in file A")

print("\nExtracting connections from file B...")
builder_b = ConnectionBuilder()
for packet in extractor.extract(Path("cases/TC-001-1-20160407/TC-001-1-20160407-B.pcap")):
    builder_b.add_packet(packet)
conns_b = list(builder_b.build_connections())
print(f"Found {len(conns_b)} connections in file B")

# Show first few connections from each file
print("\n" + "="*80)
print("First 5 connections from file A:")
print("="*80)
for i, conn in enumerate(conns_a[:5]):
    print(f"\nConnection {i} (Stream {conn.stream_id}):")
    print(f"  5-tuple: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
    print(f"  Normalized 5-tuple: {conn.get_normalized_5tuple()}")
    print(f"  IPID set: {sorted(list(conn.ipid_set))[:10]}{'...' if len(conn.ipid_set) > 10 else ''}")
    print(f"  Time range: [{conn.first_packet_time:.3f}, {conn.last_packet_time:.3f}]")
    print(f"  SYN options: {conn.syn_options[:50]}{'...' if len(conn.syn_options) > 50 else ''}")
    print(f"  Client ISN: {conn.client_isn}")
    print(f"  Server ISN: {conn.server_isn}")
    print(f"  TCP timestamp: TSval={conn.tcp_timestamp_tsval}, TSecr={conn.tcp_timestamp_tsecr}")
    print(f"  Header only: {conn.is_header_only}")

print("\n" + "="*80)
print("First 5 connections from file B:")
print("="*80)
for i, conn in enumerate(conns_b[:5]):
    print(f"\nConnection {i} (Stream {conn.stream_id}):")
    print(f"  5-tuple: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
    print(f"  Normalized 5-tuple: {conn.get_normalized_5tuple()}")
    print(f"  IPID set: {sorted(list(conn.ipid_set))[:10]}{'...' if len(conn.ipid_set) > 10 else ''}")
    print(f"  Time range: [{conn.first_packet_time:.3f}, {conn.last_packet_time:.3f}]")
    print(f"  SYN options: {conn.syn_options[:50]}{'...' if len(conn.syn_options) > 50 else ''}")
    print(f"  Client ISN: {conn.client_isn}")
    print(f"  Server ISN: {conn.server_isn}")
    print(f"  TCP timestamp: TSval={conn.tcp_timestamp_tsval}, TSecr={conn.tcp_timestamp_tsecr}")
    print(f"  Header only: {conn.is_header_only}")

# Try to match first connection from A with first connection from B
print("\n" + "="*80)
print("Attempting to match A[0] with B[0]:")
print("="*80)

scorer = ConnectionScorer()
score = scorer.score(conns_a[0], conns_b[0])

print(f"\nMatch score:")
print(f"  Normalized score: {score.normalized_score:.3f}")
print(f"  Raw score: {score.raw_score:.3f}")
print(f"  Available weight: {score.available_weight:.3f}")
print(f"  IPID match: {score.ipid_match}")
print(f"  Evidence: {score.evidence}")

# Check individual requirements
print(f"\nDetailed checks:")
print(f"  5-tuple match: {scorer._check_5tuple(conns_a[0], conns_b[0])}")
print(f"  IPID match: {scorer._check_ipid(conns_a[0], conns_b[0])}")
print(f"    A[0] IPID set: {sorted(list(conns_a[0].ipid_set))[:20]}")
print(f"    B[0] IPID set: {sorted(list(conns_b[0].ipid_set))[:20]}")
print(f"    Common IPIDs: {sorted(list(conns_a[0].ipid_set & conns_b[0].ipid_set))[:20]}")
print(f"  Time overlap: {scorer._check_time_overlap(conns_a[0], conns_b[0])}")

# Check if there are any common 5-tuples
print("\n" + "="*80)
print("Checking for common 5-tuples:")
print("="*80)

tuples_a = {conn.get_normalized_5tuple() for conn in conns_a}
tuples_b = {conn.get_normalized_5tuple() for conn in conns_b}
common_tuples = tuples_a & tuples_b

print(f"Unique 5-tuples in A: {len(tuples_a)}")
print(f"Unique 5-tuples in B: {len(tuples_b)}")
print(f"Common 5-tuples: {len(common_tuples)}")

if common_tuples:
    print(f"\nCommon 5-tuples (first 5):")
    for i, t in enumerate(list(common_tuples)[:5]):
        print(f"  {i+1}. {t}")
        
# Check for any potential matches
print("\n" + "="*80)
print("Checking all pairs for potential matches:")
print("="*80)

match_count = 0
for i, conn_a in enumerate(conns_a[:10]):  # Check first 10 from A
    for j, conn_b in enumerate(conns_b[:10]):  # Check first 10 from B
        score = scorer.score(conn_a, conn_b)
        if score.normalized_score > 0:
            match_count += 1
            print(f"\nPotential match found:")
            print(f"  A[{i}] <-> B[{j}]")
            print(f"  Score: {score.normalized_score:.3f}")
            print(f"  Evidence: {score.evidence}")
            
print(f"\nTotal potential matches found (first 10x10): {match_count}")

