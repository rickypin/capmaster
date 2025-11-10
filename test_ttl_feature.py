#!/usr/bin/env python3
"""Test script for TTL feature in endpoint statistics."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from capmaster.plugins.match.connection import TcpConnection, TcpPacket, ConnectionBuilder
from capmaster.plugins.match.endpoint_stats import (
    EndpointStatsCollector,
    EndpointPairStats,
    EndpointTuple,
    format_endpoint_stats,
)
from capmaster.plugins.match.matcher import ConnectionMatch, MatchScore
from capmaster.plugins.match.server_detector import ServerDetector


def test_ttl_extraction():
    """Test TTL extraction from packets."""
    print("=" * 80)
    print("Test 1: TTL Extraction from Packets")
    print("=" * 80)
    
    # Create test packets with TTL values
    packets = [
        TcpPacket(
            frame_number=1,
            stream_id=1,
            protocol=6,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            flags="0x002",  # SYN
            seq=0,
            ack=0,
            options="",
            length=0,
            ip_id=1000,
            timestamp=1234567890.0,
            ttl=64,  # Client TTL
        ),
        TcpPacket(
            frame_number=2,
            stream_id=1,
            protocol=6,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=54321,
            flags="0x012",  # SYN-ACK
            seq=0,
            ack=1,
            options="",
            length=0,
            ip_id=2000,
            timestamp=1234567890.1,
            ttl=128,  # Server TTL
        ),
        TcpPacket(
            frame_number=3,
            stream_id=1,
            protocol=6,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            flags="0x010",  # ACK
            seq=1,
            ack=1,
            options="",
            length=100,
            ip_id=1001,
            timestamp=1234567890.2,
            payload_data="a" * 200,
            ttl=64,  # Client TTL
        ),
        TcpPacket(
            frame_number=4,
            stream_id=1,
            protocol=6,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=54321,
            flags="0x010",  # ACK
            seq=1,
            ack=101,
            options="",
            length=200,
            ip_id=2001,
            timestamp=1234567890.3,
            payload_data="b" * 400,
            ttl=128,  # Server TTL
        ),
    ]
    
    # Build connection
    builder = ConnectionBuilder()
    for packet in packets:
        builder.add_packet(packet)
    
    connections = list(builder.build_connections())
    assert len(connections) == 1, "Should build one connection"
    
    conn = connections[0]
    print(f"Connection: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
    print(f"Client TTL: {conn.client_ttl}")
    print(f"Server TTL: {conn.server_ttl}")
    
    assert conn.client_ttl == 64, f"Expected client TTL 64, got {conn.client_ttl}"
    assert conn.server_ttl == 128, f"Expected server TTL 128, got {conn.server_ttl}"
    
    print("✓ TTL extraction test passed!\n")
    return conn


def test_endpoint_stats_with_ttl(conn1: TcpConnection):
    """Test endpoint statistics with TTL information."""
    print("=" * 80)
    print("Test 2: Endpoint Statistics with TTL")
    print("=" * 80)
    
    # Create a second connection with different TTL values
    conn2 = TcpConnection(
        stream_id=2,
        protocol=6,
        client_ip="192.168.1.100",
        client_port=54322,
        server_ip="10.0.0.1",
        server_port=80,
        syn_timestamp=1234567891.0,
        syn_options=conn1.syn_options,
        client_isn=conn1.client_isn,
        server_isn=conn1.server_isn,
        tcp_timestamp_tsval="",
        tcp_timestamp_tsecr="",
        client_payload_md5=conn1.client_payload_md5,
        server_payload_md5=conn1.server_payload_md5,
        length_signature=conn1.length_signature,
        is_header_only=False,
        ipid_first=conn1.ipid_first,
        ipid_set=conn1.ipid_set,
        first_packet_time=1234567891.0,
        last_packet_time=1234567891.5,
        packet_count=4,
        client_ttl=63,  # Different client TTL
        server_ttl=127,  # Different server TTL
    )
    
    # Create matches
    match = ConnectionMatch(
        conn1=conn1,
        conn2=conn2,
        score=MatchScore(
            normalized_score=1.0,
            raw_score=100.0,
            available_weight=100.0,
            ipid_match=True,
            evidence="test-match",
        ),
    )
    
    # Collect statistics
    detector = ServerDetector()
    collector = EndpointStatsCollector(detector)
    collector.add_match(match)
    collector.finalize()
    
    stats = collector.get_stats()
    assert len(stats) > 0, "Should have at least one stat entry"
    
    stat = stats[0]
    print(f"Endpoint Pair Stats:")
    print(f"  File A: {stat.tuple_a}")
    print(f"  File B: {stat.tuple_b}")
    print(f"  Count: {stat.count}")
    print(f"  Confidence: {stat.confidence}")
    print(f"  TTL A - Client: {stat.client_ttl_a}, Server: {stat.server_ttl_a}")
    print(f"  TTL B - Client: {stat.client_ttl_b}, Server: {stat.server_ttl_b}")
    
    assert stat.client_ttl_a == 64, f"Expected client_ttl_a=64, got {stat.client_ttl_a}"
    assert stat.server_ttl_a == 128, f"Expected server_ttl_a=128, got {stat.server_ttl_a}"
    assert stat.client_ttl_b == 63, f"Expected client_ttl_b=63, got {stat.client_ttl_b}"
    assert stat.server_ttl_b == 127, f"Expected server_ttl_b=127, got {stat.server_ttl_b}"
    
    print("✓ Endpoint statistics with TTL test passed!\n")
    return stats


def test_format_output(stats: list[EndpointPairStats]):
    """Test formatted output with TTL information."""
    print("=" * 80)
    print("Test 3: Formatted Output with TTL")
    print("=" * 80)
    
    output = format_endpoint_stats(stats, "file_a.pcap", "file_b.pcap")
    print(output)
    
    # Check that TTL information is in the output
    assert "TTL:" in output or "TTL A:" in output, "Output should contain TTL information"
    assert "64" in output, "Output should contain client TTL value 64"
    assert "128" in output, "Output should contain server TTL value 128"
    
    print("\n✓ Formatted output test passed!\n")


def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("Testing TTL Feature in Endpoint Statistics")
    print("=" * 80 + "\n")
    
    try:
        # Test 1: TTL extraction
        conn = test_ttl_extraction()
        
        # Test 2: Endpoint statistics with TTL
        stats = test_endpoint_stats_with_ttl(conn)
        
        # Test 3: Formatted output
        test_format_output(stats)
        
        print("=" * 80)
        print("✓ All tests passed successfully!")
        print("=" * 80)
        return 0
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

