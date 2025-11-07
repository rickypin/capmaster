#!/usr/bin/env python3
"""Test a potential fix for bidirectional consistency."""

import ipaddress
import sys
sys.path.insert(0, '/Users/ricky/Downloads/code/capmaster')

from test_new_flow_hash import siphash13, u64_to_i64


def calculate_flow_hash_bidirectional(ip1: str, ip2: str, port1: int, port2: int, proto: int = 6) -> int:
    """Modified version that should be bidirectional."""
    key = b"\x00" * 16

    msg = port1.to_bytes(2, "big")
    msg2 = port2.to_bytes(2, "big")
    msg3 = (0).to_bytes(8, "little")
    msg4 = (4).to_bytes(8, "little")
    msg5 = ipaddress.IPv4Address(ip1).packed
    msg6 = (0).to_bytes(8, "little")
    msg7 = (4).to_bytes(8, "little")
    msg8 = ipaddress.IPv4Address(ip2).packed
    msg9 = (1).to_bytes(8, "little")
    msg10 = proto.to_bytes(1, "big")

    # Swap logic - MODIFIED for bidirectional consistency
    # Compare ports as little-endian
    port1_le = int.from_bytes(msg, "little")
    port2_le = int.from_bytes(msg2, "little")
    
    if port1_le < port2_le:  # Changed from <= to <
        # Swap both ports AND IPs together
        msg, msg2 = msg2, msg
        msg3, msg4, msg5, msg6 = msg6, msg3, msg8, msg4
        msg8 = msg5  # This is wrong, let me fix it
    elif port1_le == port2_le:
        # If ports are equal, compare IPs
        if msg5 < msg8:
            msg, msg2 = msg2, msg
            msg3, msg4, msg5, msg6 = msg6, msg3, msg8, msg4
            msg8 = msg5

    return u64_to_i64(siphash13(key, [msg, msg2, msg3, msg4, msg5, msg6, msg7, msg8, msg9, msg10]))


def calculate_flow_hash_bidirectional_v2(ip1: str, ip2: str, port1: int, port2: int, proto: int = 6) -> int:
    """Modified version 2 - simpler approach."""
    key = b"\x00" * 16

    # Compare ports first
    port1_le = int.from_bytes(port1.to_bytes(2, "big"), "little")
    port2_le = int.from_bytes(port2.to_bytes(2, "big"), "little")
    
    # Determine canonical order
    if port1_le > port2_le:
        # port1 is larger, use original order
        p1, p2 = port1, port2
        ip_1, ip_2 = ip1, ip2
    elif port1_le < port2_le:
        # port2 is larger, swap
        p1, p2 = port2, port1
        ip_1, ip_2 = ip2, ip1
    else:
        # Ports equal, compare IPs
        if ipaddress.IPv4Address(ip1) >= ipaddress.IPv4Address(ip2):
            p1, p2 = port1, port2
            ip_1, ip_2 = ip1, ip2
        else:
            p1, p2 = port2, port1
            ip_1, ip_2 = ip2, ip1
    
    # Build messages in canonical order
    msg = p1.to_bytes(2, "big")
    msg2 = p2.to_bytes(2, "big")
    msg3 = (0).to_bytes(8, "little")
    msg4 = (4).to_bytes(8, "little")
    msg5 = ipaddress.IPv4Address(ip_1).packed
    msg6 = (0).to_bytes(8, "little")
    msg7 = (4).to_bytes(8, "little")
    msg8 = ipaddress.IPv4Address(ip_2).packed
    msg9 = (1).to_bytes(8, "little")
    msg10 = proto.to_bytes(1, "big")

    return u64_to_i64(siphash13(key, [msg, msg2, msg3, msg4, msg5, msg6, msg7, msg8, msg9, msg10]))


# Test
ip1 = "8.67.2.125"
ip2 = "8.42.96.45"
port1 = 26302
port2 = 35101

print("Testing bidirectional v2:")
hash1 = calculate_flow_hash_bidirectional_v2(ip1, ip2, port1, port2, 6)
hash2 = calculate_flow_hash_bidirectional_v2(ip2, ip1, port2, port1, 6)

print(f"Forward:  {ip1}:{port1} -> {ip2}:{port2} = {hash1}")
print(f"Reverse:  {ip2}:{port2} -> {ip1}:{port1} = {hash2}")
print(f"Match: {hash1 == hash2}")
print()

# Compare with original expected value
print(f"Original expected: -1173584886679544929")
print(f"New hash: {hash1}")

