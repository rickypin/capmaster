#!/usr/bin/env python3
"""Test different IP address hashing orders."""

import struct
import ipaddress
from capmaster.plugins.compare.flow_hash import siphash13


def test_ip_byte_orders():
    """Test different byte orders for IP addresses."""
    
    ip_str = "8.42.96.45"
    ip = ipaddress.ip_address(ip_str)
    
    print(f"IP Address: {ip_str}")
    print(f"  Packed (network order): {ip.packed.hex()}")
    print(f"  As u32 big-endian:      {struct.pack('>I', int(ip)).hex()}")
    print(f"  As u32 little-endian:   {struct.pack('<I', int(ip)).hex()}")
    
    # Rust's IpAddr might hash as u32 in native endian
    print(f"\nRust IpAddr::V4 likely hashes as:")
    print(f"  u32 in native endian (little on x86_64)")
    
    # Test with little-endian IP
    data_le = bytearray()
    data_le.extend(struct.pack('<H', 35101))  # port1
    data_le.extend(struct.pack('<H', 26302))  # port2
    data_le.extend(struct.pack('<I', int(ipaddress.ip_address("8.42.96.45"))))  # ip1 as u32 LE
    data_le.extend(struct.pack('<I', int(ipaddress.ip_address("8.67.2.125"))))  # ip2 as u32 LE
    data_le.extend(struct.pack('B', 6))  # protocol
    
    hash_le = siphash13(bytes(data_le))
    
    print(f"\nWith IP as u32 little-endian:")
    print(f"  Byte sequence: {data_le.hex()}")
    print(f"  Hash: {hash_le}")
    print(f"  Rust expected: -1173584886679544929")
    print(f"  Match: {hash_le == -1173584886679544929}")


if __name__ == "__main__":
    test_ip_byte_orders()

