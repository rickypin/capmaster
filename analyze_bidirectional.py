#!/usr/bin/env python3
"""Analyze if the swap logic should produce bidirectional consistency."""

import ipaddress


def analyze_swap(ip1, ip2, port1, port2, label=""):
    """Analyze the swap logic step by step."""
    print(f"\n{'='*70}")
    print(f"{label}")
    print(f"{'='*70}")
    print(f"Input: {ip1}:{port1} <-> {ip2}:{port2}")
    
    msg = port1.to_bytes(2, "big")
    msg2 = port2.to_bytes(2, "big")
    msg3 = (0).to_bytes(8, "little")
    msg4 = (4).to_bytes(8, "little")
    msg5 = ipaddress.IPv4Address(ip1).packed
    msg6 = (0).to_bytes(8, "little")
    msg7 = (4).to_bytes(8, "little")
    msg8 = ipaddress.IPv4Address(ip2).packed
    
    print(f"\nBefore swap:")
    print(f"  msg (port1={port1}): {msg.hex()}, as LE int: {int.from_bytes(msg, 'little')}")
    print(f"  msg2 (port2={port2}): {msg2.hex()}, as LE int: {int.from_bytes(msg2, 'little')}")
    print(f"  msg5 (ip1={ip1}): {msg5.hex()}")
    print(f"  msg8 (ip2={ip2}): {msg8.hex()}")
    
    port1_le = int.from_bytes(msg, "little")
    port2_le = int.from_bytes(msg2, "little")
    
    swapped = False
    if port1_le <= port2_le:
        print(f"\n  Condition: port1_le ({port1_le}) <= port2_le ({port2_le}) = TRUE")
        print(f"  Action: Swap ports")
        msg, msg2 = msg2, msg
        swapped = True
        
        print(f"\n  After port swap:")
        print(f"    msg: {msg.hex()}")
        print(f"    msg2: {msg2.hex()}")
        print(f"    msg < msg2 (bytes): {msg < msg2}")
        print(f"    msg3 < msg4 (bytes): {msg3 < msg4}")
        
        if msg < msg2 or msg3 < msg4:
            print(f"  Condition: msg < msg2 OR msg3 < msg4 = TRUE")
            print(f"  Action: Swap IPs")
            msg4, msg6 = msg6, msg4
            msg3, msg5 = msg5, msg3
        else:
            print(f"  Condition: msg < msg2 OR msg3 < msg4 = FALSE")
            print(f"  Action: No IP swap")
    else:
        print(f"\n  Condition: port1_le ({port1_le}) <= port2_le ({port2_le}) = FALSE")
        print(f"  Action: No swap")
    
    print(f"\nFinal message order:")
    print(f"  msg (port): {msg.hex()}")
    print(f"  msg2 (port): {msg2.hex()}")
    print(f"  msg3: {msg3.hex()}")
    print(f"  msg4: {msg4.hex()}")
    print(f"  msg5 (IP): {msg5.hex()}")
    print(f"  msg6: {msg6.hex()}")
    
    return (msg, msg2, msg3, msg4, msg5, msg6, swapped)


# Test the bidirectional case
ip1 = "8.67.2.125"
ip2 = "8.42.96.45"
port1 = 26302
port2 = 35101

result1 = analyze_swap(ip1, ip2, port1, port2, "Forward: 8.67.2.125:26302 -> 8.42.96.45:35101")
result2 = analyze_swap(ip2, ip1, port2, port1, "Reverse: 8.42.96.45:35101 -> 8.67.2.125:26302")

print(f"\n{'='*70}")
print("COMPARISON")
print(f"{'='*70}")

msgs1 = result1[:6]
msgs2 = result2[:6]

print(f"\nForward final messages:")
for i, m in enumerate(msgs1, 1):
    print(f"  msg{i}: {m.hex()}")

print(f"\nReverse final messages:")
for i, m in enumerate(msgs2, 1):
    print(f"  msg{i}: {m.hex()}")

if msgs1 == msgs2:
    print(f"\n✓ Messages are IDENTICAL - Bidirectional consistency achieved!")
else:
    print(f"\n✗ Messages are DIFFERENT - No bidirectional consistency")
    print(f"\nDifferences:")
    for i, (m1, m2) in enumerate(zip(msgs1, msgs2), 1):
        if m1 != m2:
            print(f"  msg{i}: {m1.hex()} != {m2.hex()}")

