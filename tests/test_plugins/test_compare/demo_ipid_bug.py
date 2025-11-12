#!/usr/bin/env python3
"""
Standalone demonstration of the IPID direction confusion bug.

This script can be run directly without pytest to demonstrate the bug.

Usage:
    python3 tests/test_plugins/test_compare/demo_ipid_bug.py
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass
class TcpPacket:
    """Simplified TcpPacket for demonstration."""
    frame_number: int
    ip_id: int
    tcp_flags: str
    seq: int
    ack: int
    direction: str  # Added for clarity in this demo: 'C->S' or 'S->C'


def demonstrate_bug():
    """Demonstrate the IPID direction confusion bug."""
    
    print("=" * 80)
    print("IPID Direction Confusion Bug Demonstration")
    print("=" * 80)
    
    # Scenario: Two TCP connections with overlapping IPID values
    
    print("\n--- Connection A Packets ---")
    packets_a = [
        TcpPacket(1, 0x1234, "0x002", 1000, 0, "C->S"),      # Client->Server: SYN
        TcpPacket(2, 0x5678, "0x012", 2000, 1001, "S->C"),   # Server->Client: SYN-ACK
        TcpPacket(3, 0x1235, "0x010", 1001, 2001, "C->S"),   # Client->Server: ACK
    ]
    
    for pkt in packets_a:
        print(f"  Frame {pkt.frame_number}: IPID={pkt.ip_id:#06x} {pkt.direction} "
              f"Flags={pkt.tcp_flags} Seq={pkt.seq} Ack={pkt.ack}")
    
    print("\n--- Connection B Packets ---")
    packets_b = [
        TcpPacket(1, 0x1234, "0x002", 1000, 0, "C->S"),      # Client->Server: SYN
        TcpPacket(2, 0x1234, "0x012", 2000, 1001, "S->C"),   # Server->Client: SYN-ACK (SAME IPID!)
        TcpPacket(3, 0x1235, "0x010", 1001, 2001, "C->S"),   # Client->Server: ACK
    ]
    
    for pkt in packets_b:
        print(f"  Frame {pkt.frame_number}: IPID={pkt.ip_id:#06x} {pkt.direction} "
              f"Flags={pkt.tcp_flags} Seq={pkt.seq} Ack={pkt.ack}")
    
    # Current buggy implementation: Group by IPID only (no direction awareness)
    print("\n" + "=" * 80)
    print("CURRENT BUGGY BEHAVIOR: Grouping by IPID only")
    print("=" * 80)
    
    # Build IPID maps (current implementation)
    ipid_map_a = {}
    for pkt in packets_a:
        if pkt.ip_id not in ipid_map_a:
            ipid_map_a[pkt.ip_id] = []
        ipid_map_a[pkt.ip_id].append(pkt)
    
    ipid_map_b = {}
    for pkt in packets_b:
        if pkt.ip_id not in ipid_map_b:
            ipid_map_b[pkt.ip_id] = []
        ipid_map_b[pkt.ip_id].append(pkt)
    
    print("\nIPID Map A:")
    for ipid, pkts in sorted(ipid_map_a.items()):
        print(f"  IPID {ipid:#06x}:")
        for pkt in pkts:
            print(f"    Frame {pkt.frame_number} ({pkt.direction}): Flags={pkt.tcp_flags}")
    
    print("\nIPID Map B:")
    for ipid, pkts in sorted(ipid_map_b.items()):
        print(f"  IPID {ipid:#06x}:")
        for pkt in pkts:
            print(f"    Frame {pkt.frame_number} ({pkt.direction}): Flags={pkt.tcp_flags}")
    
    # Compare packets with matching IPIDs (current buggy logic)
    print("\n--- Packet Comparisons (Current Buggy Logic) ---")
    matched_ipids = set(ipid_map_a.keys()) & set(ipid_map_b.keys())
    
    for ipid in sorted(matched_ipids):
        pkts_a = ipid_map_a[ipid]
        pkts_b = ipid_map_b[ipid]
        
        print(f"\nIPID {ipid:#06x}: Comparing {len(pkts_a)} packet(s) from A with {len(pkts_b)} packet(s) from B")
        
        # Current implementation compares pairwise
        for i in range(min(len(pkts_a), len(pkts_b))):
            pkt_a = pkts_a[i]
            pkt_b = pkts_b[i]
            
            print(f"  Comparing:")
            print(f"    A Frame {pkt_a.frame_number} ({pkt_a.direction}): Flags={pkt_a.tcp_flags} Seq={pkt_a.seq} Ack={pkt_a.ack}")
            print(f"    B Frame {pkt_b.frame_number} ({pkt_b.direction}): Flags={pkt_b.tcp_flags} Seq={pkt_b.seq} Ack={pkt_b.ack}")
            
            # Check for differences
            if pkt_a.direction != pkt_b.direction:
                print(f"    ❌ BUG: Comparing packets from DIFFERENT directions!")
            
            if pkt_a.tcp_flags != pkt_b.tcp_flags:
                print(f"    ⚠️  TCP Flags differ: {pkt_a.tcp_flags} != {pkt_b.tcp_flags}")
            if pkt_a.seq != pkt_b.seq:
                print(f"    ⚠️  Seq differs: {pkt_a.seq} != {pkt_b.seq}")
            if pkt_a.ack != pkt_b.ack:
                print(f"    ⚠️  Ack differs: {pkt_a.ack} != {pkt_b.ack}")
            
            if pkt_a.direction == pkt_b.direction and \
               pkt_a.tcp_flags == pkt_b.tcp_flags and \
               pkt_a.seq == pkt_b.seq and \
               pkt_a.ack == pkt_b.ack:
                print(f"    ✓ Packets match correctly")
    
    # Correct implementation: Group by (direction, IPID)
    print("\n" + "=" * 80)
    print("CORRECT BEHAVIOR: Grouping by (Direction, IPID)")
    print("=" * 80)
    
    # Build direction-aware IPID maps
    dir_ipid_map_a = {}
    for pkt in packets_a:
        key = (pkt.direction, pkt.ip_id)
        if key not in dir_ipid_map_a:
            dir_ipid_map_a[key] = []
        dir_ipid_map_a[key].append(pkt)
    
    dir_ipid_map_b = {}
    for pkt in packets_b:
        key = (pkt.direction, pkt.ip_id)
        if key not in dir_ipid_map_b:
            dir_ipid_map_b[key] = []
        dir_ipid_map_b[key].append(pkt)
    
    print("\nDirection-aware IPID Map A:")
    for (direction, ipid), pkts in sorted(dir_ipid_map_a.items()):
        print(f"  ({direction}, IPID {ipid:#06x}):")
        for pkt in pkts:
            print(f"    Frame {pkt.frame_number}: Flags={pkt.tcp_flags}")
    
    print("\nDirection-aware IPID Map B:")
    for (direction, ipid), pkts in sorted(dir_ipid_map_b.items()):
        print(f"  ({direction}, IPID {ipid:#06x}):")
        for pkt in pkts:
            print(f"    Frame {pkt.frame_number}: Flags={pkt.tcp_flags}")
    
    # Compare packets with matching (direction, IPID)
    print("\n--- Packet Comparisons (Correct Logic) ---")
    matched_keys = set(dir_ipid_map_a.keys()) & set(dir_ipid_map_b.keys())
    only_in_a = set(dir_ipid_map_a.keys()) - set(dir_ipid_map_b.keys())
    only_in_b = set(dir_ipid_map_b.keys()) - set(dir_ipid_map_a.keys())
    
    for direction, ipid in sorted(matched_keys):
        pkts_a = dir_ipid_map_a[(direction, ipid)]
        pkts_b = dir_ipid_map_b[(direction, ipid)]
        
        print(f"\n({direction}, IPID {ipid:#06x}): Comparing {len(pkts_a)} packet(s) from A with {len(pkts_b)} packet(s) from B")
        
        for i in range(min(len(pkts_a), len(pkts_b))):
            pkt_a = pkts_a[i]
            pkt_b = pkts_b[i]
            
            print(f"  Comparing:")
            print(f"    A Frame {pkt_a.frame_number} ({pkt_a.direction}): Flags={pkt_a.tcp_flags} Seq={pkt_a.seq} Ack={pkt_a.ack}")
            print(f"    B Frame {pkt_b.frame_number} ({pkt_b.direction}): Flags={pkt_b.tcp_flags} Seq={pkt_b.seq} Ack={pkt_b.ack}")
            
            if pkt_a.tcp_flags == pkt_b.tcp_flags and \
               pkt_a.seq == pkt_b.seq and \
               pkt_a.ack == pkt_b.ack:
                print(f"    ✓ Packets match correctly (same direction guaranteed)")
            else:
                print(f"    ⚠️  Legitimate difference detected")
    
    if only_in_a:
        print("\n--- Keys only in A ---")
        for direction, ipid in sorted(only_in_a):
            print(f"  ({direction}, IPID {ipid:#06x})")
    
    if only_in_b:
        print("\n--- Keys only in B ---")
        for direction, ipid in sorted(only_in_b):
            print(f"  ({direction}, IPID {ipid:#06x})")
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print("\nBUG IMPACT:")
    print("- Current implementation groups packets by IPID only")
    print("- This causes packets from different directions to be incorrectly matched")
    print("- In this example, IPID 0x1234 appears in both C->S and S->C directions in B")
    print("- The buggy code compares A's C->S packet with B's S->C packet (WRONG!)")
    print("\nFIX REQUIRED:")
    print("- Add direction field to TcpPacket dataclass")
    print("- Use (direction, IPID) as the matching key")
    print("- Only compare packets with same direction AND same IPID")
    print("=" * 80)


if __name__ == "__main__":
    demonstrate_bug()

