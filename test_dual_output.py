#!/usr/bin/env python3
"""Test dual output for VERY_LOW confidence connections."""

from capmaster.plugins.match.endpoint_stats import EndpointStatsCollector, EndpointTuple
from capmaster.plugins.match.server_detector import ServerDetector
from capmaster.plugins.match.matcher import ConnectionMatch
from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.scorer import MatchScore


def create_test_connection(
    client_ip: str,
    client_port: int,
    server_ip: str,
    server_port: int,
) -> TcpConnection:
    """Create a test TCP connection."""
    return TcpConnection(
        stream_id=1,
        client_ip=client_ip,
        client_port=client_port,
        server_ip=server_ip,
        server_port=server_port,
        syn_timestamp=0.0,
        syn_options="",  # No SYN packet
        client_isn=0,
        server_isn=0,
        tcp_timestamp_tsval="",
        tcp_timestamp_tsecr="",
        client_payload_md5="",
        server_payload_md5="",
        length_signature="",
        is_header_only=False,
        ipid_first=0,
        ipid_set=set(),
        first_packet_time=0.0,
        last_packet_time=0.0,
        packet_count=1,
    )


def test_dual_output_for_very_low_confidence():
    """
    Test that VERY_LOW confidence connections produce dual output.
    
    Scenario: Single connection between two machines using non-standard ports
    - No SYN packet
    - Ports not in well-known/database lists
    - Both ports >= 1024
    - Only one connection (no cardinality analysis possible)
    
    Expected: Both interpretations should be output
    """
    print("=" * 80)
    print("Testing Dual Output for VERY_LOW Confidence Connections")
    print("=" * 80)
    
    # Create a single connection with non-standard ports
    # Use completely different IPs in conn2 to avoid cardinality detection
    # This ensures each connection is isolated and falls into FALLBACK_PORT_COMPARISON
    conn1 = create_test_connection(
        client_ip="192.168.1.100",
        client_port=50001,  # Non-standard port
        server_ip="192.168.1.200",
        server_port=60001,  # Non-standard port
    )

    conn2 = create_test_connection(
        client_ip="10.0.1.100",  # Different client IP
        client_port=50001,
        server_ip="10.0.2.200",  # Different server IP
        server_port=60001,
    )
    
    # Create match score
    score = MatchScore(
        normalized_score=0.8,
        raw_score=0.8,
        available_weight=1.0,
        ipid_match=True,
        evidence="test",
    )

    # Create match
    match = ConnectionMatch(conn1=conn1, conn2=conn2, score=score)
    
    # Create collector and detector
    detector = ServerDetector()
    collector = EndpointStatsCollector(detector)
    
    # Add match and finalize
    collector.add_match(match)
    collector.finalize()
    
    # Get statistics
    stats = collector.get_stats()
    
    print(f"\nTotal endpoint pairs: {len(stats)}")
    print("\nEndpoint Pairs:")
    print("-" * 80)
    
    for i, pair in enumerate(stats, 1):
        print(f"\n[{i}] {pair}")
    
    # Verify we have 2 pairs (original + reversed)
    assert len(stats) == 2, f"Expected 2 pairs, got {len(stats)}"
    
    # Verify both have VERY_LOW confidence
    for pair in stats:
        assert pair.confidence == "VERY_LOW", f"Expected VERY_LOW, got {pair.confidence}"
    
    # Verify the pairs are reversed versions of each other
    pair1, pair2 = stats[0], stats[1]

    # Check that server/client are swapped
    # Note: EndpointTuple doesn't have client_port, only server_port
    assert pair1.tuple_a.server_ip == pair2.tuple_a.client_ip
    assert pair1.tuple_a.client_ip == pair2.tuple_a.server_ip
    # The server_port in pair1 should be the original client_port (50001)
    # The server_port in pair2 should be the original server_port (60001)

    assert pair1.tuple_b.server_ip == pair2.tuple_b.client_ip
    assert pair1.tuple_b.client_ip == pair2.tuple_b.server_ip
    
    print("\n" + "=" * 80)
    print("✅ Test passed! Dual output is working correctly.")
    print("=" * 80)
    
    # Print interpretation
    print("\nInterpretation 1:")
    print(f"  Server: {pair1.tuple_a.server_ip}:{pair1.tuple_a.server_port}")
    print(f"  Client: {pair1.tuple_a.client_ip}")
    
    print("\nInterpretation 2:")
    print(f"  Server: {pair2.tuple_a.server_ip}:{pair2.tuple_a.server_port}")
    print(f"  Client: {pair2.tuple_a.client_ip}")
    
    print("\nBoth interpretations are provided to avoid missing connections due to")
    print("incorrect server detection in VERY_LOW confidence scenarios.")


def test_no_dual_output_for_high_confidence():
    """
    Test that HIGH confidence connections do NOT produce dual output.
    
    Scenario: Multiple connections showing clear server pattern
    Expected: Only one interpretation (the correct one)
    """
    print("\n" + "=" * 80)
    print("Testing NO Dual Output for HIGH Confidence Connections")
    print("=" * 80)
    
    # Create multiple connections to the same server port
    # This should trigger port stability detection
    matches = []
    for client_port in [50001, 50002, 50003]:
        conn1 = create_test_connection(
            client_ip="192.168.1.100",
            client_port=client_port,
            server_ip="192.168.1.200",
            server_port=60001,  # Same server port
        )
        
        conn2 = create_test_connection(
            client_ip="192.168.1.100",
            client_port=client_port,
            server_ip="10.0.0.50",
            server_port=60001,  # Same server port
        )
        
        score = MatchScore(
            normalized_score=0.8,
            raw_score=0.8,
            available_weight=1.0,
            ipid_match=True,
            evidence="test",
        )
        matches.append(ConnectionMatch(conn1=conn1, conn2=conn2, score=score))
    
    # Create collector and detector
    detector = ServerDetector()
    collector = EndpointStatsCollector(detector)
    
    # Add matches and finalize
    for match in matches:
        collector.add_match(match)
    collector.finalize()
    
    # Get statistics
    stats = collector.get_stats()
    
    print(f"\nTotal endpoint pairs: {len(stats)}")
    print("\nEndpoint Pairs:")
    print("-" * 80)
    
    for i, pair in enumerate(stats, 1):
        print(f"\n[{i}] {pair}")
    
    # Verify we have 3 pairs (one for each connection, no dual output)
    # If dual output was triggered, we would have 6 pairs (3 * 2)
    assert len(stats) == 3, f"Expected 3 pairs, got {len(stats)}"

    # Verify all have MEDIUM or HIGH confidence (port stability detection)
    for pair in stats:
        assert pair.confidence in ["MEDIUM", "HIGH"], f"Expected MEDIUM/HIGH, got {pair.confidence}"
        # Verify count is 1 (not doubled)
        assert pair.count == 1, f"Expected count=1, got {pair.count}"
    
    print("\n" + "=" * 80)
    print("✅ Test passed! No dual output for high confidence connections.")
    print("=" * 80)


if __name__ == "__main__":
    test_dual_output_for_very_low_confidence()
    test_no_dual_output_for_high_confidence()
    print("\n" + "=" * 80)
    print("All tests passed! ✅")
    print("=" * 80)

