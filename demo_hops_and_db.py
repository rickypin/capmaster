#!/usr/bin/env python3
"""
Demo script for network hops feature with database integration.

This script demonstrates:
1. TTL-based hop count calculation
2. Endpoint statistics with hop information
3. Database writing with network device nodes
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from capmaster.plugins.match.ttl_utils import calculate_hops, analyze_ttl_info
from capmaster.plugins.match.endpoint_stats import (
    EndpointStatsCollector,
    EndpointPairStats,
    EndpointTuple,
    format_endpoint_stats,
    format_endpoint_stats_table,
)
from capmaster.plugins.match.server_detector import ServerDetector
from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.matcher import ConnectionMatch, MatchScore


def print_section(title: str):
    """Print a section header."""
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def demo_ttl_calculation():
    """Demonstrate TTL-based hop calculation."""
    print_section("1. TTL-Based Hop Calculation")
    
    test_cases = [
        (64, "Linux/Unix direct connection"),
        (60, "Linux/Unix with 4 hops"),
        (128, "Windows direct connection"),
        (120, "Windows with 8 hops"),
        (255, "Network device direct"),
        (240, "Network device with 15 hops"),
    ]
    
    print("\nTTL → Hops Conversion:")
    print("-" * 80)
    for ttl, description in test_cases:
        hops = calculate_hops(ttl)
        print(f"  TTL={ttl:3d} → {hops:2d} hops  ({description})")
    
    print("\n" + "-" * 80)


def demo_ttl_analysis():
    """Demonstrate TTL analysis for endpoint pairs."""
    print_section("2. TTL Analysis for Endpoint Pairs")
    
    scenarios = [
        {
            "name": "Scenario A: Direct client, 4-hop server",
            "client_ttls": [64, 64, 64],
            "server_ttls": [60, 60, 61],
        },
        {
            "name": "Scenario B: 3-hop client, 6-hop server",
            "client_ttls": [61, 61, 62],
            "server_ttls": [58, 58, 58],
        },
        {
            "name": "Scenario C: Windows client, 10-hop server",
            "client_ttls": [128, 128, 127],
            "server_ttls": [118, 118, 119],
        },
    ]
    
    for scenario in scenarios:
        print(f"\n{scenario['name']}:")
        print(f"  Client TTLs: {scenario['client_ttls']}")
        print(f"  Server TTLs: {scenario['server_ttls']}")
        
        info = analyze_ttl_info(scenario['client_ttls'], scenario['server_ttls'])
        print(f"  Analysis:")
        print(f"    - Client hops: {info['client_hops']}")
        print(f"    - Server hops: {info['server_hops']}")
        print(f"    - Client has device: {'Yes' if info['client_has_device'] else 'No'}")
        print(f"    - Server has device: {'Yes' if info['server_has_device'] else 'No'}")


def create_test_connection(
    stream_id: int,
    client_ip: str,
    server_ip: str,
    server_port: int,
    client_ttl: int = 0,
    server_ttl: int = 0,
) -> TcpConnection:
    """Create a test TCP connection."""
    return TcpConnection(
        stream_id=stream_id,
        protocol=6,  # TCP
        client_ip=client_ip,
        client_port=50000 + stream_id,
        server_ip=server_ip,
        server_port=server_port,
        syn_timestamp=1000.0,
        syn_options="mss=1460;ws=7;sack=1;ts=1",
        client_isn=1000,
        server_isn=2000,
        tcp_timestamp_tsval="100",
        tcp_timestamp_tsecr="200",
        client_payload_md5="abc123",
        server_payload_md5="def456",
        length_signature="C:100 S:200",
        is_header_only=False,
        ipid_first=12345,
        ipid_set={12345, 12346},
        first_packet_time=1000.0,
        last_packet_time=1010.0,
        packet_count=10,
        client_ttl=client_ttl,
        server_ttl=server_ttl,
    )


def demo_endpoint_stats():
    """Demonstrate endpoint statistics with hop information."""
    print_section("3. Endpoint Statistics with Network Hops")
    
    # Create server detector and stats collector
    detector = ServerDetector()
    collector = EndpointStatsCollector(detector)
    
    # Create test connections with different TTL values
    connections = [
        # Pair 1: Direct client, 4-hop server (File A) vs Direct client, 8-hop server (File B)
        (
            create_test_connection(1, "192.168.1.100", "10.0.0.50", 80, 64, 60),
            create_test_connection(101, "172.16.0.200", "10.0.0.51", 80, 128, 120),
        ),
        # Pair 2: Direct client, 10-hop server (File A) vs Direct client, 2-hop server (File B)
        (
            create_test_connection(2, "192.168.1.101", "10.0.0.52", 443, 128, 118),
            create_test_connection(102, "172.16.0.201", "10.0.0.53", 443, 64, 62),
        ),
        # Pair 3: 3-hop client, 6-hop server (File A) vs 3-hop client, 13-hop server (File B)
        (
            create_test_connection(3, "192.168.1.102", "10.0.0.54", 22, 61, 58),
            create_test_connection(103, "172.16.0.202", "10.0.0.55", 22, 125, 115),
        ),
    ]
    
    # Create matches
    for conn_a, conn_b in connections:
        match = ConnectionMatch(
            conn1=conn_a,
            conn2=conn_b,
            score=MatchScore(
                normalized_score=0.95,
                raw_score=0.95,
                available_weight=1.0,
                ipid_match=True,
                evidence="SYN+ISN+TS+PL+LEN+IPID",
            ),
        )
        collector.add_match(match)
    
    # Finalize and get stats
    collector.finalize()
    stats = collector.get_stats()
    
    print(f"\nCollected {len(stats)} endpoint pairs\n")
    
    # Display detailed format
    print("\n" + "-" * 80)
    print("Detailed Format:")
    print("-" * 80)
    output = format_endpoint_stats(stats, "file_a.pcap", "file_b.pcap")
    print(output)
    
    # Display table format
    print("\n" + "-" * 80)
    print("Table Format:")
    print("-" * 80)
    table_output = format_endpoint_stats_table(stats, "file_a.pcap", "file_b.pcap")
    print(table_output)
    
    return stats


def demo_database_nodes(stats: list[EndpointPairStats]):
    """Demonstrate database node structure."""
    print_section("4. Database Node Structure")
    
    print("\nFor each endpoint pair, the following nodes are inserted:\n")
    
    for i, stat in enumerate(stats, 1):
        print(f"Group {i}:")
        print(f"  File A: {stat.tuple_a.client_ip} → {stat.tuple_a.server_ip}:{stat.tuple_a.server_port}")
        print(f"    Client hops: {stat.client_hops_a}, Server hops: {stat.server_hops_a}")
        print(f"  File B: {stat.tuple_b.client_ip} → {stat.tuple_b.server_ip}:{stat.tuple_b.server_port}")
        print(f"    Client hops: {stat.client_hops_b}, Server hops: {stat.server_hops_b}")
        
        # Count nodes
        base_nodes = 4  # Always: 2 clients + 2 servers
        net_device_nodes = 0
        
        nodes_a = []
        nodes_b = []
        
        # File A nodes
        nodes_a.append(f"  [pcap_id=0] Client (type=1): {stat.tuple_a.client_ip}")
        if stat.client_hops_a > 0:
            nodes_a.append(f"  [pcap_id=0] NetDevice (type=1001): Client-Capture ({stat.client_hops_a} hops)")
            net_device_nodes += 1
        nodes_a.append(f"  [pcap_id=0] Server (type=2): {stat.tuple_a.server_ip}:{stat.tuple_a.server_port}")
        if stat.server_hops_a > 0:
            nodes_a.append(f"  [pcap_id=0] NetDevice (type=1002): Capture-Server ({stat.server_hops_a} hops)")
            net_device_nodes += 1
        
        # File B nodes
        nodes_b.append(f"  [pcap_id=1] Client (type=1): {stat.tuple_b.client_ip}")
        if stat.client_hops_b > 0:
            nodes_b.append(f"  [pcap_id=1] NetDevice (type=1001): Client-Capture ({stat.client_hops_b} hops)")
            net_device_nodes += 1
        nodes_b.append(f"  [pcap_id=1] Server (type=2): {stat.tuple_b.server_ip}:{stat.tuple_b.server_port}")
        if stat.server_hops_b > 0:
            nodes_b.append(f"  [pcap_id=1] NetDevice (type=1002): Capture-Server ({stat.server_hops_b} hops)")
            net_device_nodes += 1
        
        print(f"\n  Nodes to insert ({base_nodes + net_device_nodes} total):")
        for node in nodes_a + nodes_b:
            print(node)
        print()


def main():
    """Run all demonstrations."""
    print("\n" + "=" * 80)
    print("Network Hops Feature Demonstration")
    print("=" * 80)
    
    try:
        # Demo 1: TTL calculation
        demo_ttl_calculation()
        
        # Demo 2: TTL analysis
        demo_ttl_analysis()
        
        # Demo 3: Endpoint statistics
        stats = demo_endpoint_stats()
        
        # Demo 4: Database node structure
        demo_database_nodes(stats)
        
        print_section("Summary")
        print("\n✅ All demonstrations completed successfully!")
        print("\nKey Features:")
        print("  1. TTL-based hop count calculation (64/128/255 initial values)")
        print("  2. Endpoint statistics with hop information")
        print("  3. Network device node insertion (type=1001/1002)")
        print("  4. Detailed and table format output")
        print("\nFor database integration, run: python test_match_endpoint_db.py")
        print()
        
        return 0
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

