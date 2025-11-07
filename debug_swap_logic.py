#!/usr/bin/env python3
"""Debug the swap logic in the reference implementation."""

import ipaddress


def test_swap_logic():
    """Test the swap logic with different port combinations."""
    
    test_cases = [
        # (ip1, ip2, port1, port2)
        ("8.67.2.125", "8.42.96.45", 26302, 35101),
        ("8.42.96.45", "8.67.2.125", 35101, 26302),  # Reverse
        ("192.168.1.1", "10.0.0.1", 12345, 80),
        ("10.0.0.1", "192.168.1.1", 80, 12345),  # Reverse
    ]
    
    for ip1, ip2, port1, port2 in test_cases:
        print(f"\nTest: {ip1}:{port1} <-> {ip2}:{port2}")
        
        msg = port1.to_bytes(2, "big")
        msg2 = port2.to_bytes(2, "big")
        msg3 = (0).to_bytes(8, "little")
        msg4 = (4).to_bytes(8, "little")
        msg5 = ipaddress.IPv4Address(ip1).packed
        msg6 = (0).to_bytes(8, "little")
        msg7 = (4).to_bytes(8, "little")
        msg8 = ipaddress.IPv4Address(ip2).packed
        
        print(f"  Before swap:")
        print(f"    msg (port1 big-endian): {msg.hex()}, as little-endian int: {int.from_bytes(msg, 'little')}")
        print(f"    msg2 (port2 big-endian): {msg2.hex()}, as little-endian int: {int.from_bytes(msg2, 'little')}")
        print(f"    msg3: {msg3.hex()}")
        print(f"    msg4: {msg4.hex()}")
        print(f"    msg5 (ip1): {msg5.hex()}")
        print(f"    msg6: {msg6.hex()}")
        print(f"    msg8 (ip2): {msg8.hex()}")
        
        # Apply swap logic
        if int.from_bytes(msg, "little") <= int.from_bytes(msg2, "little"):
            print(f"  Swapping ports (port1_le <= port2_le)")
            msg, msg2 = msg2, msg
            
            print(f"    After port swap:")
            print(f"      msg: {msg.hex()}")
            print(f"      msg2: {msg2.hex()}")
            print(f"      msg < msg2: {msg < msg2}")
            print(f"      msg3 < msg4: {msg3 < msg4}")
            
            if msg < msg2 or msg3 < msg4:
                print(f"    Swapping IPs (msg < msg2 or msg3 < msg4)")
                msg4, msg6 = msg6, msg4
                msg3, msg5 = msg5, msg3
        
        print(f"  After all swaps:")
        print(f"    msg: {msg.hex()}")
        print(f"    msg2: {msg2.hex()}")
        print(f"    msg3: {msg3.hex()}")
        print(f"    msg4: {msg4.hex()}")
        print(f"    msg5: {msg5.hex()}")
        print(f"    msg6: {msg6.hex()}")


if __name__ == "__main__":
    test_swap_logic()

