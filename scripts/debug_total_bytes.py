#!/usr/bin/env python3
"""Debug script to check if total_bytes is being populated correctly."""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from capmaster.core.connection.extractor import TcpFieldExtractor
from capmaster.core.connection.models import ConnectionBuilder

def main() -> int:
    # Test with one of the cases
    case_dir = Path("/Users/ricky/Downloads/2hops/TC-001-1-20160407")
    pcaps = sorted(case_dir.glob("*.pcap"))
    
    if len(pcaps) < 2:
        print(f"Error: Need at least 2 PCAP files in {case_dir}")
        return 1
    
    print(f"Extracting connections from {pcaps[0].name}...")
    extractor = TcpFieldExtractor()
    builder = ConnectionBuilder()

    for packet in extractor.extract(pcaps[0]):
        builder.add_packet(packet)

    connections = list(builder.build_connections())
    
    print(f"\nTotal connections: {len(connections)}")
    print(f"\nFirst 10 connections:")
    print(f"{'Stream ID':>12s} {'Packets':>8s} {'Total Bytes':>12s} {'Avg Bytes/Pkt':>15s}")
    print("-" * 60)
    
    for conn in connections[:10]:
        avg_bytes = conn.total_bytes / conn.packet_count if conn.packet_count > 0 else 0
        print(f"{conn.stream_id:12d} {conn.packet_count:8d} {conn.total_bytes:12d} {avg_bytes:15.1f}")
    
    # Check if any have total_bytes > 0
    with_bytes = [c for c in connections if c.total_bytes > 0]
    print(f"\nConnections with total_bytes > 0: {len(with_bytes)} / {len(connections)}")
    
    if len(with_bytes) == 0:
        print("\n⚠️  WARNING: All connections have total_bytes=0!")
        print("This suggests the frame_len field is not being populated during extraction.")
    else:
        print(f"\n✓ total_bytes is being populated correctly")
        print(f"  Min: {min(c.total_bytes for c in with_bytes)}")
        print(f"  Max: {max(c.total_bytes for c in with_bytes)}")
        print(f"  Avg: {sum(c.total_bytes for c in with_bytes) / len(with_bytes):.0f}")
    
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

