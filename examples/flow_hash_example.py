#!/usr/bin/env python3
"""
Example: Flow Hash Calculation

This example demonstrates how to use the flow hash feature to identify
and group TCP connections bidirectionally.
"""

from capmaster.plugins.compare_common.flow_hash import (
    FlowSide,
    calculate_connection_flow_hash,
    calculate_flow_hash,
    format_flow_hash,
)


def example_basic_usage():
    """Basic flow hash calculation."""
    print("=" * 80)
    print("Example 1: Basic Flow Hash Calculation")
    print("=" * 80)
    
    # Calculate flow hash for a connection
    hash_hex, flow_side = calculate_flow_hash(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol=6,  # TCP
    )
    
    print(f"Connection: 192.168.1.100:54321 -> 10.0.0.1:80")
    print(f"Flow Hash: {hash_hex}")
    print(f"Flow Side: {flow_side.name}")
    print(f"Formatted: {format_flow_hash(hash_hex, flow_side)}")
    print()


def example_bidirectional_consistency():
    """Demonstrate bidirectional consistency."""
    print("=" * 80)
    print("Example 2: Bidirectional Consistency")
    print("=" * 80)
    
    # Forward direction
    hash1, side1 = calculate_flow_hash(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol=6,
    )
    
    # Reverse direction
    hash2, side2 = calculate_flow_hash(
        src_ip="10.0.0.1",
        dst_ip="192.168.1.100",
        src_port=80,
        dst_port=54321,
        protocol=6,
    )
    
    print(f"Forward:  192.168.1.100:54321 -> 10.0.0.1:80")
    print(f"  Hash: {hash1}, Side: {side1.name}")
    print()
    print(f"Reverse:  10.0.0.1:80 -> 192.168.1.100:54321")
    print(f"  Hash: {hash2}, Side: {side2.name}")
    print()
    print(f"Hashes match: {hash1 == hash2}")
    print(f"Sides differ: {side1 != side2}")
    print()


def example_connection_grouping():
    """Group connections by flow hash."""
    print("=" * 80)
    print("Example 3: Connection Grouping")
    print("=" * 80)
    
    # Simulate multiple connections (some are bidirectional pairs)
    connections = [
        ("192.168.1.100", "10.0.0.1", 54321, 80),
        ("10.0.0.1", "192.168.1.100", 80, 54321),  # Reverse of first
        ("192.168.1.101", "10.0.0.1", 54322, 443),
        ("192.168.1.102", "10.0.0.2", 54323, 22),
        ("10.0.0.1", "192.168.1.101", 443, 54322),  # Reverse of third
    ]
    
    # Group by flow hash
    flows = {}
    for src_ip, dst_ip, src_port, dst_port in connections:
        hash_hex, flow_side = calculate_flow_hash(
            src_ip, dst_ip, src_port, dst_port, protocol=6
        )
        
        if hash_hex not in flows:
            flows[hash_hex] = []
        
        flows[hash_hex].append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "flow_side": flow_side,
        })
    
    print(f"Total connections: {len(connections)}")
    print(f"Unique flows: {len(flows)}")
    print()
    
    for i, (hash_hex, conns) in enumerate(flows.items(), 1):
        print(f"Flow {i}: {hash_hex}")
        for conn in conns:
            side_str = "LHS>=RHS" if conn["flow_side"] == FlowSide.LHS_GE_RHS else "RHS>LHS"
            print(f"  {conn['src_ip']}:{conn['src_port']} -> "
                  f"{conn['dst_ip']}:{conn['dst_port']} ({side_str})")
        print()


def example_ipv6_support():
    """Demonstrate IPv6 support."""
    print("=" * 80)
    print("Example 4: IPv6 Support")
    print("=" * 80)
    
    # IPv6 connection
    hash_hex, flow_side = calculate_flow_hash(
        src_ip="2001:db8::1",
        dst_ip="2001:db8::2",
        src_port=12345,
        dst_port=80,
        protocol=6,
    )
    
    print(f"Connection: [2001:db8::1]:12345 -> [2001:db8::2]:80")
    print(f"Flow Hash: {hash_hex}")
    print(f"Flow Side: {flow_side.name}")
    print()


def example_connection_wrapper():
    """Use the connection wrapper function."""
    print("=" * 80)
    print("Example 5: Connection Wrapper Function")
    print("=" * 80)
    
    # Using the convenience wrapper
    hash_hex, flow_side = calculate_connection_flow_hash(
        client_ip="192.168.1.100",
        server_ip="10.0.0.1",
        client_port=54321,
        server_port=80,
    )
    
    print(f"Client: 192.168.1.100:54321")
    print(f"Server: 10.0.0.1:80")
    print(f"Flow Hash: {format_flow_hash(hash_hex, flow_side)}")
    print()


def example_multiple_protocols():
    """Show that different protocols produce different hashes."""
    print("=" * 80)
    print("Example 6: Protocol Differentiation")
    print("=" * 80)
    
    # Same endpoints, different protocols
    tcp_hash, _ = calculate_flow_hash(
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol=6,  # TCP
    )
    
    udp_hash, _ = calculate_flow_hash(
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol=17,  # UDP
    )
    
    print(f"Same endpoints, different protocols:")
    print(f"  TCP (protocol 6):  {tcp_hash}")
    print(f"  UDP (protocol 17): {udp_hash}")
    print(f"  Hashes differ: {tcp_hash != udp_hash}")
    print()


def main():
    """Run all examples."""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "Flow Hash Examples" + " " * 40 + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    example_basic_usage()
    example_bidirectional_consistency()
    example_connection_grouping()
    example_ipv6_support()
    example_connection_wrapper()
    example_multiple_protocols()
    
    print("=" * 80)
    print("All examples completed!")
    print("=" * 80)


if __name__ == "__main__":
    main()
