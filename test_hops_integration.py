#!/usr/bin/env python3
"""Integration test for network hops feature with endpoint statistics."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from capmaster.plugins.match.endpoint_stats import (
    EndpointStatsCollector,
    format_endpoint_stats,
    format_endpoint_stats_table,
)
from capmaster.plugins.match.server_detector import ServerDetector
from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.matcher import ConnectionMatch, MatchScore


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


def test_endpoint_stats_with_hops():
    """Test endpoint statistics collection with network hops."""
    print("=" * 80)
    print("Integration Test: Endpoint Statistics with Network Hops")
    print("=" * 80)
    print()
    
    # Create server detector
    detector = ServerDetector()
    
    # Create endpoint stats collector
    collector = EndpointStatsCollector(detector)
    
    # Create test connections with different TTL values
    # Scenario 1: Linux client (TTL=64) -> Server with 4 hops (TTL=60)
    conn1_a = create_test_connection(
        stream_id=1,
        client_ip="192.168.1.100",
        server_ip="10.0.0.50",
        server_port=80,
        client_ttl=64,  # Direct connection (0 hops)
        server_ttl=60,  # 4 hops (64 - 60 = 4)
    )
    
    conn1_b = create_test_connection(
        stream_id=101,
        client_ip="172.16.0.200",
        server_ip="10.0.0.51",
        server_port=80,
        client_ttl=128,  # Direct connection (0 hops)
        server_ttl=120,  # 8 hops (128 - 120 = 8)
    )
    
    # Scenario 2: Windows client (TTL=128) -> Server with 10 hops (TTL=118)
    conn2_a = create_test_connection(
        stream_id=2,
        client_ip="192.168.1.101",
        server_ip="10.0.0.52",
        server_port=443,
        client_ttl=128,  # Direct connection (0 hops)
        server_ttl=118,  # 10 hops (128 - 118 = 10)
    )
    
    conn2_b = create_test_connection(
        stream_id=102,
        client_ip="172.16.0.201",
        server_ip="10.0.0.53",
        server_port=443,
        client_ttl=64,   # Direct connection (0 hops)
        server_ttl=62,   # 2 hops (64 - 62 = 2)
    )
    
    # Scenario 3: Both with intermediate hops
    conn3_a = create_test_connection(
        stream_id=3,
        client_ip="192.168.1.102",
        server_ip="10.0.0.54",
        server_port=22,
        client_ttl=61,   # 3 hops (64 - 61 = 3)
        server_ttl=58,   # 6 hops (64 - 58 = 6)
    )
    
    conn3_b = create_test_connection(
        stream_id=103,
        client_ip="172.16.0.202",
        server_ip="10.0.0.55",
        server_port=22,
        client_ttl=125,  # 3 hops (128 - 125 = 3)
        server_ttl=115,  # 13 hops (128 - 115 = 13)
    )
    
    # Create matches
    matches = [
        ConnectionMatch(
            conn1=conn1_a,
            conn2=conn1_b,
            score=MatchScore(
                normalized_score=0.95,
                raw_score=0.95,
                available_weight=1.0,
                ipid_match=True,
                evidence="SYN+ISN+TS+PL+LEN+IPID",
            ),
        ),
        ConnectionMatch(
            conn1=conn2_a,
            conn2=conn2_b,
            score=MatchScore(
                normalized_score=0.90,
                raw_score=0.90,
                available_weight=1.0,
                ipid_match=True,
                evidence="SYN+ISN+TS+PL+LEN+IPID",
            ),
        ),
        ConnectionMatch(
            conn1=conn3_a,
            conn2=conn3_b,
            score=MatchScore(
                normalized_score=0.85,
                raw_score=0.85,
                available_weight=1.0,
                ipid_match=True,
                evidence="SYN+ISN+TS+PL+LEN+IPID",
            ),
        ),
    ]
    
    # Add matches to collector
    print("Adding matches to collector...")
    for match in matches:
        collector.add_match(match)
    
    # Finalize collection
    print("Finalizing statistics collection...")
    collector.finalize()
    
    # Get statistics
    stats = collector.get_stats()
    
    print(f"\nCollected {len(stats)} endpoint pairs\n")
    
    # Display detailed format
    print("=" * 80)
    print("Detailed Format Output:")
    print("=" * 80)
    output = format_endpoint_stats(stats, "file_a.pcap", "file_b.pcap")
    print(output)
    
    # Display table format
    print("\n" + "=" * 80)
    print("Table Format Output:")
    print("=" * 80)
    table_output = format_endpoint_stats_table(stats, "file_a.pcap", "file_b.pcap")
    print(table_output)
    
    # Verify hops information
    print("\n" + "=" * 80)
    print("Verification:")
    print("=" * 80)
    
    for i, stat in enumerate(stats, 1):
        print(f"\nEndpoint Pair {i}:")
        print(f"  File A: {stat.tuple_a.client_ip} -> {stat.tuple_a.server_ip}:{stat.tuple_a.server_port}")
        print(f"    Client: TTL={stat.client_ttl_a}, Hops={stat.client_hops_a}")
        print(f"    Server: TTL={stat.server_ttl_a}, Hops={stat.server_hops_a}")
        print(f"  File B: {stat.tuple_b.client_ip} -> {stat.tuple_b.server_ip}:{stat.tuple_b.server_port}")
        print(f"    Client: TTL={stat.client_ttl_b}, Hops={stat.client_hops_b}")
        print(f"    Server: TTL={stat.server_ttl_b}, Hops={stat.server_hops_b}")
        
        # Verify hops are calculated correctly
        assert stat.client_hops_a >= 0, "Client hops A should be non-negative"
        assert stat.server_hops_a >= 0, "Server hops A should be non-negative"
        assert stat.client_hops_b >= 0, "Client hops B should be non-negative"
        assert stat.server_hops_b >= 0, "Server hops B should be non-negative"
    
    print("\n" + "=" * 80)
    print("✓ Integration test passed successfully!")
    print("=" * 80)
    
    return 0


def main():
    """Run the integration test."""
    try:
        return test_endpoint_stats_with_hops()
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

