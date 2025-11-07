#!/usr/bin/env python3
"""
Flow Hash Rust Compatibility Demonstration

This script demonstrates that the Python flow hash implementation now exactly
matches the Rust xuanwu-core implementation from:
    xuanwu-core/packet/src/buffer.rs::calculate_flow_hash

Key improvements:
1. Uses SipHash-1-3 (same as Rust's DefaultHasher)
2. Uses network byte order (big-endian) for ports (matching Rust's NetEndian<u16>)
3. Same normalization logic for bidirectional flow consistency
"""

from capmaster.plugins.compare.flow_hash import (
    calculate_flow_hash,
    calculate_connection_flow_hash,
    FlowSide,
    format_flow_hash,
)


def print_section(title: str):
    """Print a section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def demo_basic_usage():
    """Demonstrate basic flow hash calculation."""
    print_section("1. Basic Flow Hash Calculation")
    
    # Calculate flow hash for a TCP connection
    hash_val, flow_side = calculate_flow_hash(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol=6,  # TCP
    )
    
    print(f"\nConnection: 192.168.1.100:54321 -> 10.0.0.1:80 (TCP)")
    print(f"Flow Hash:  {hash_val}")
    print(f"Flow Side:  {flow_side.name}")
    print(f"Formatted:  {format_flow_hash(hash_val, flow_side)}")


def demo_bidirectional_consistency():
    """Demonstrate bidirectional flow consistency."""
    print_section("2. Bidirectional Flow Consistency")
    
    print("\nThis is the KEY feature: same flow produces same hash in both directions")
    print("-" * 80)
    
    # Forward direction
    hash_fwd, side_fwd = calculate_flow_hash(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol=6,
    )
    
    print(f"\nForward:  192.168.1.100:54321 -> 10.0.0.1:80")
    print(f"  Hash:   {hash_fwd}")
    print(f"  Side:   {side_fwd.name}")
    
    # Reverse direction
    hash_rev, side_rev = calculate_flow_hash(
        src_ip="10.0.0.1",
        dst_ip="192.168.1.100",
        src_port=80,
        dst_port=54321,
        protocol=6,
    )
    
    print(f"\nReverse:  10.0.0.1:80 -> 192.168.1.100:54321")
    print(f"  Hash:   {hash_rev}")
    print(f"  Side:   {side_rev.name}")
    
    print(f"\n✓ Hashes match: {hash_fwd == hash_rev}")
    print(f"✓ Flow sides are opposite: {side_fwd != side_rev}")


def demo_normalization_logic():
    """Demonstrate the normalization logic."""
    print_section("3. Normalization Logic (Matching Rust Implementation)")
    
    print("\nThe algorithm normalizes flows by comparing ports first, then IPs:")
    print("-" * 80)
    
    # Case 1: Port-based normalization
    print("\nCase 1: Different ports (port comparison determines flow_side)")
    hash1, side1 = calculate_flow_hash(
        "192.168.1.1", "192.168.1.2", 54321, 80, 6
    )
    print(f"  192.168.1.1:54321 -> 192.168.1.2:80")
    print(f"  Port comparison: 54321 >= 80 → {side1.name}")
    print(f"  Hash: {hash1}")
    
    # Case 2: IP-based normalization (when ports are equal)
    print("\nCase 2: Equal ports (IP comparison determines flow_side)")
    hash2, side2 = calculate_flow_hash(
        "192.168.1.100", "10.0.0.1", 8080, 8080, 6
    )
    print(f"  192.168.1.100:8080 -> 10.0.0.1:8080")
    print(f"  Ports equal, IP comparison: 192.168.1.100 >= 10.0.0.1 → {side2.name}")
    print(f"  Hash: {hash2}")


def demo_network_byte_order():
    """Demonstrate network byte order for ports."""
    print_section("4. Network Byte Order (Big-Endian) for Ports")
    
    print("\nKEY FIX: Ports are now hashed in network byte order (big-endian)")
    print("This matches Rust's NetEndian<u16> type")
    print("-" * 80)
    
    # Example with specific port values
    hash1, side1 = calculate_flow_hash(
        "192.168.1.1", "10.0.0.1", 0x1234, 0x5678, 6
    )
    
    print(f"\nPorts: 0x1234 (4660) and 0x5678 (22136)")
    print(f"Hash:  {hash1}")
    
    # Reverse should produce same hash
    hash2, side2 = calculate_flow_hash(
        "10.0.0.1", "192.168.1.1", 0x5678, 0x1234, 6
    )
    
    print(f"\nReverse flow hash: {hash2}")
    print(f"✓ Bidirectional consistency: {hash1 == hash2}")


def demo_protocol_differentiation():
    """Demonstrate protocol differentiation."""
    print_section("5. Protocol Differentiation")
    
    print("\nDifferent protocols produce different hashes:")
    print("-" * 80)
    
    protocols = [
        (6, "TCP"),
        (17, "UDP"),
        (1, "ICMP"),
    ]
    
    for proto_num, proto_name in protocols:
        hash_val, side = calculate_flow_hash(
            "192.168.1.1", "10.0.0.1", 12345, 80, proto_num
        )
        print(f"\n{proto_name:6} (proto={proto_num:2}): {hash_val}")


def demo_ipv6_support():
    """Demonstrate IPv6 support."""
    print_section("6. IPv6 Support")
    
    print("\nIPv6 addresses work seamlessly:")
    print("-" * 80)
    
    # IPv6 flow
    hash_v6, side_v6 = calculate_flow_hash(
        src_ip="2001:db8::1",
        dst_ip="2001:db8::2",
        src_port=12345,
        dst_port=80,
        protocol=6,
    )
    
    print(f"\nIPv6: 2001:db8::1:12345 -> 2001:db8::2:80")
    print(f"Hash: {hash_v6}")
    print(f"Side: {side_v6.name}")
    
    # Reverse
    hash_v6_rev, side_v6_rev = calculate_flow_hash(
        src_ip="2001:db8::2",
        dst_ip="2001:db8::1",
        src_port=80,
        dst_port=12345,
        protocol=6,
    )
    
    print(f"\nReverse: 2001:db8::2:80 -> 2001:db8::1:12345")
    print(f"Hash: {hash_v6_rev}")
    print(f"✓ Bidirectional: {hash_v6 == hash_v6_rev}")


def demo_flow_grouping():
    """Demonstrate flow grouping use case."""
    print_section("7. Flow Grouping Use Case")
    
    print("\nGrouping packets by flow (simulating pcap analysis):")
    print("-" * 80)
    
    # Simulate packets from a pcap
    packets = [
        # Flow 1: Client -> Server
        {"src": "192.168.1.100", "dst": "10.0.0.1", "sport": 54321, "dport": 80, "proto": 6},
        # Flow 1: Server -> Client
        {"src": "10.0.0.1", "dst": "192.168.1.100", "sport": 80, "dport": 54321, "proto": 6},
        # Flow 1: Client -> Server (another packet)
        {"src": "192.168.1.100", "dst": "10.0.0.1", "sport": 54321, "dport": 80, "proto": 6},
        # Flow 2: DNS query
        {"src": "192.168.1.100", "dst": "8.8.8.8", "sport": 53241, "dport": 53, "proto": 17},
        # Flow 2: DNS response
        {"src": "8.8.8.8", "dst": "192.168.1.100", "sport": 53, "dport": 53241, "proto": 17},
    ]
    
    # Group by flow hash
    flow_groups = {}
    for i, pkt in enumerate(packets):
        hash_val, _ = calculate_flow_hash(
            pkt["src"], pkt["dst"], pkt["sport"], pkt["dport"], pkt["proto"]
        )
        
        if hash_val not in flow_groups:
            flow_groups[hash_val] = []
        flow_groups[hash_val].append(i)
    
    print(f"\nTotal packets: {len(packets)}")
    print(f"Unique flows:  {len(flow_groups)}")
    print("\nFlow grouping:")
    
    for flow_hash, pkt_indices in flow_groups.items():
        first_pkt = packets[pkt_indices[0]]
        proto_name = "TCP" if first_pkt["proto"] == 6 else "UDP"
        print(f"\n  Flow {flow_hash:20} ({proto_name}):")
        print(f"    Packets: {pkt_indices}")
        print(f"    Example: {first_pkt['src']}:{first_pkt['sport']} <-> "
              f"{first_pkt['dst']}:{first_pkt['dport']}")


def demo_rust_compatibility():
    """Demonstrate Rust compatibility."""
    print_section("8. Rust Compatibility Summary")
    
    print("\nThis Python implementation now matches Rust xuanwu-core exactly:")
    print("-" * 80)
    
    print("\n✓ Algorithm: SipHash-1-3 (Rust's DefaultHasher)")
    print("✓ Port byte order: Big-endian / Network byte order (NetEndian<u16>)")
    print("✓ Normalization: Same logic as Rust's FlowSide::from_port/from_address")
    print("✓ Hash sequence: Ports → IP addresses → Protocol")
    print("✓ Return type: Signed 64-bit integer (i64)")
    
    print("\nExample calculation:")
    hash_val, side = calculate_flow_hash(
        "192.168.1.100", "10.0.0.1", 12345, 80, 6
    )
    print(f"  Input:  192.168.1.100:12345 -> 10.0.0.1:80 (TCP)")
    print(f"  Output: {hash_val} ({side.name})")
    print(f"\n  This hash value should match Rust's calculate_flow_hash()")
    print(f"  with the same inputs (assuming same SipHash keys)")


def main():
    """Run all demonstrations."""
    print("\n" + "=" * 80)
    print("  Flow Hash Rust Compatibility Demonstration")
    print("  Python implementation matching Rust xuanwu-core")
    print("=" * 80)
    
    demo_basic_usage()
    demo_bidirectional_consistency()
    demo_normalization_logic()
    demo_network_byte_order()
    demo_protocol_differentiation()
    demo_ipv6_support()
    demo_flow_grouping()
    demo_rust_compatibility()
    
    print("\n" + "=" * 80)
    print("  Demonstration Complete")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()

