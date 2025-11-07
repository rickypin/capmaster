#!/usr/bin/env python3
"""Debug script to analyze flow hash calculation differences."""

import struct
import ipaddress
from capmaster.plugins.compare.flow_hash import (
    calculate_flow_hash,
    FlowSide,
    siphash13,
    _compare_ports,
)


def debug_flow_hash(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int = 6):
    """Debug flow hash calculation with detailed output."""
    
    print(f"\n{'='*80}")
    print(f"Debugging Flow Hash Calculation")
    print(f"{'='*80}")
    
    print(f"\nInput:")
    print(f"  src_ip:    {src_ip}")
    print(f"  dst_ip:    {dst_ip}")
    print(f"  src_port:  {src_port}")
    print(f"  dst_port:  {dst_port}")
    print(f"  protocol:  {protocol}")
    
    # Step 1: Determine flow side
    flow_side = _compare_ports(src_port, dst_port)
    print(f"\nStep 1: Flow Side Determination")
    print(f"  Port comparison: {src_port} vs {dst_port}")
    print(f"  flow_side: {flow_side.name} ({flow_side})")
    
    # Step 2: Build byte sequence
    data = bytearray()
    
    print(f"\nStep 2: Build Byte Sequence")
    
    # Ports
    if flow_side == FlowSide.LHS_GE_RHS:
        port1, port2 = src_port, dst_port
        print(f"  Port order: [{src_port}, {dst_port}] (LHS >= RHS)")
    else:
        port1, port2 = dst_port, src_port
        print(f"  Port order: [{dst_port}, {src_port}] (RHS > LHS)")

    port1_bytes = struct.pack('<H', port1)  # Little-endian (native)
    port2_bytes = struct.pack('<H', port2)  # Little-endian (native)
    data.extend(port1_bytes)
    data.extend(port2_bytes)

    print(f"  Port 1 ({port1}): {port1_bytes.hex()} (little-endian/native)")
    print(f"  Port 2 ({port2}): {port2_bytes.hex()} (little-endian/native)")
    
    # IP addresses
    ip1 = ipaddress.ip_address(src_ip)
    ip2 = ipaddress.ip_address(dst_ip)
    
    if flow_side == FlowSide.LHS_GE_RHS:
        addr1, addr2 = ip1, ip2
        print(f"  IP order: [{src_ip}, {dst_ip}] (LHS >= RHS)")
    else:
        addr1, addr2 = ip2, ip1
        print(f"  IP order: [{dst_ip}, {src_ip}] (RHS > LHS)")
    
    addr1_bytes = addr1.packed
    addr2_bytes = addr2.packed
    data.extend(addr1_bytes)
    data.extend(addr2_bytes)
    
    print(f"  IP 1 ({addr1}): {addr1_bytes.hex()}")
    print(f"  IP 2 ({addr2}): {addr2_bytes.hex()}")
    
    # Protocol
    proto_bytes = struct.pack('B', protocol)
    data.extend(proto_bytes)
    print(f"  Protocol ({protocol}): {proto_bytes.hex()}")
    
    # Full byte sequence
    print(f"\nStep 3: Complete Byte Sequence")
    print(f"  Length: {len(data)} bytes")
    print(f"  Hex: {data.hex()}")
    print(f"  Breakdown:")
    print(f"    Ports:    {data[0:4].hex()}")
    print(f"    IPs:      {data[4:12].hex()}")
    print(f"    Protocol: {data[12:13].hex()}")
    
    # Calculate hash
    hash_value = siphash13(bytes(data))
    
    print(f"\nStep 4: SipHash-1-3 Calculation")
    print(f"  Hash (signed i64):   {hash_value}")
    print(f"  Hash (unsigned u64): {hash_value & 0xFFFFFFFFFFFFFFFF}")
    print(f"  Hash (hex):          0x{(hash_value & 0xFFFFFFFFFFFFFFFF):016x}")
    
    # Also calculate using the main function
    hash_val2, flow_side2 = calculate_flow_hash(src_ip, dst_ip, src_port, dst_port, protocol)
    
    print(f"\nStep 5: Verification")
    print(f"  Main function hash: {hash_val2}")
    print(f"  Main function side: {flow_side2.name}")
    print(f"  Match: {hash_value == hash_val2}")
    
    # Convert to Rust format
    print(f"\nRust Comparison:")
    print(f"  Python result: {hash_value}")
    print(f"  Expected Rust: -1173584886679544929")
    print(f"  Match: {hash_value == -1173584886679544929}")
    
    # Show as unsigned for comparison
    python_unsigned = hash_value & 0xFFFFFFFFFFFFFFFF
    rust_signed = -1173584886679544929
    rust_unsigned = rust_signed & 0xFFFFFFFFFFFFFFFF
    
    print(f"\nUnsigned Comparison:")
    print(f"  Python (unsigned): {python_unsigned}")
    print(f"  Rust (unsigned):   {rust_unsigned}")
    print(f"  Match: {python_unsigned == rust_unsigned}")
    
    return hash_value, flow_side


def test_specific_case():
    """Test the specific case from the user."""
    print("\n" + "="*80)
    print("Testing Specific Case: 8.42.96.45:35101 <-> 8.67.2.125:26302")
    print("="*80)
    
    # Test case from user
    hash_val, flow_side = debug_flow_hash(
        src_ip="8.42.96.45",
        dst_ip="8.67.2.125",
        src_port=35101,
        dst_port=26302,
        protocol=6,
    )
    
    print(f"\n{'='*80}")
    print(f"Result Summary")
    print(f"{'='*80}")
    print(f"Python hash: {hash_val}")
    print(f"Rust hash:   -1173584886679544929")
    print(f"Flow side:   {flow_side.name}")
    
    if hash_val == -1173584886679544929:
        print("\n✅ MATCH! Python and Rust produce the same hash!")
    else:
        print("\n❌ MISMATCH! Hashes are different.")
        print("\nPossible reasons:")
        print("1. Different SipHash keys (k0, k1)")
        print("2. Different byte order interpretation")
        print("3. Different normalization logic")
        print("4. Bug in implementation")


def test_reverse_direction():
    """Test the reverse direction."""
    print("\n" + "="*80)
    print("Testing Reverse Direction: 8.67.2.125:26302 <-> 8.42.96.45:35101")
    print("="*80)
    
    hash_val, flow_side = debug_flow_hash(
        src_ip="8.67.2.125",
        dst_ip="8.42.96.45",
        src_port=26302,
        dst_port=35101,
        protocol=6,
    )
    
    print(f"\nReverse direction hash: {hash_val}")


def analyze_byte_order():
    """Analyze byte order issues."""
    print("\n" + "="*80)
    print("Byte Order Analysis")
    print("="*80)

    port = 35101

    print("\nRust Hash trait behavior:")
    print("  Hasher::write_u16() uses native endian (little-endian on x86_64)")
    print("  Even though NetEndian<u16> stores big-endian, Hash uses native endian!")
    
    print(f"\nPort {port} in different byte orders:")
    print(f"  Big-endian ('>H'):    {struct.pack('>H', port).hex()}")
    print(f"  Little-endian ('<H'): {struct.pack('<H', port).hex()}")
    print(f"  Native ('H'):         {struct.pack('H', port).hex()}")
    
    print(f"\nIP 8.42.96.45 as bytes:")
    ip = ipaddress.ip_address("8.42.96.45")
    print(f"  Packed: {ip.packed.hex()}")
    print(f"  Decimal: {[b for b in ip.packed]}")


if __name__ == "__main__":
    test_specific_case()
    test_reverse_direction()
    analyze_byte_order()

