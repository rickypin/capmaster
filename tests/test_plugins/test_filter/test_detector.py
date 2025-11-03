"""
Tests for the OneWayDetector class.
"""

import pytest

from capmaster.plugins.filter.detector import (
    DirectionStats,
    OneWayDetector,
    StreamAnalysis,
    TcpPacketInfo,
    MAX_SEQ_ACK,
)


class TestAckDeltaCalculation:
    """Test ACK increment calculation with wraparound handling."""
    
    def test_normal_ack_increment(self):
        """Test normal ACK increment without wraparound."""
        detector = OneWayDetector()
        
        # Normal case: last_ack > first_ack
        delta = detector._calculate_ack_delta(1000, 2000)
        assert delta == 1000
        
        delta = detector._calculate_ack_delta(0, 100)
        assert delta == 100
        
        delta = detector._calculate_ack_delta(12345, 67890)
        assert delta == 55545
    
    def test_ack_wraparound(self):
        """Test ACK increment with 32-bit wraparound."""
        detector = OneWayDetector()
        
        # Wraparound case: last_ack < first_ack
        # Example: first_ack = 2^32 - 100, last_ack = 100
        # Expected delta = 100 + 100 = 200
        first_ack = MAX_SEQ_ACK - 100
        last_ack = 100
        delta = detector._calculate_ack_delta(first_ack, last_ack)
        assert delta == 200
        
        # Another wraparound case
        first_ack = MAX_SEQ_ACK - 1000
        last_ack = 500
        delta = detector._calculate_ack_delta(first_ack, last_ack)
        assert delta == 1500
    
    def test_ack_no_change(self):
        """Test ACK with no change."""
        detector = OneWayDetector()
        
        delta = detector._calculate_ack_delta(1000, 1000)
        assert delta == 0
    
    def test_ack_edge_cases(self):
        """Test ACK calculation edge cases."""
        detector = OneWayDetector()
        
        # Maximum value
        delta = detector._calculate_ack_delta(0, MAX_SEQ_ACK - 1)
        assert delta == MAX_SEQ_ACK - 1
        
        # Wraparound at boundary
        delta = detector._calculate_ack_delta(MAX_SEQ_ACK - 1, 0)
        assert delta == 1


class TestDirectionStats:
    """Test DirectionStats dataclass."""
    
    def test_default_values(self):
        """Test default values of DirectionStats."""
        stats = DirectionStats()
        assert stats.packet_count == 0
        assert stats.first_ack == 0
        assert stats.last_ack == 0
        assert stats.has_pure_ack is False
        assert stats.prev_ack == 0


class TestOneWayDetector:
    """Test OneWayDetector class."""
    
    def test_initialization(self):
        """Test detector initialization."""
        detector = OneWayDetector()
        assert detector.ack_threshold == 20
        
        detector = OneWayDetector(ack_threshold=100)
        assert detector.ack_threshold == 100
    
    def test_add_packet_single_direction(self):
        """Test adding packets from a single direction."""
        detector = OneWayDetector()
        
        # Add packets from one direction
        for i in range(5):
            packet = TcpPacketInfo(
                stream_id=1,
                src_ip="192.168.1.1",
                src_port=12345,
                dst_ip="10.0.0.1",
                dst_port=80,
                ack=1000 + i * 100,
                tcp_len=0,
            )
            detector.add_packet(packet)
        
        # Check internal state
        assert 1 in detector._streams
        direction = "192.168.1.1:12345->10.0.0.1:80"
        assert direction in detector._streams[1]
        stats = detector._streams[1][direction]
        assert stats.packet_count == 5
        assert stats.first_ack == 1000
        assert stats.last_ack == 1400
    
    def test_add_packet_bidirectional(self):
        """Test adding packets from both directions."""
        detector = OneWayDetector()
        
        # Add packets from forward direction
        for i in range(3):
            packet = TcpPacketInfo(
                stream_id=1,
                src_ip="192.168.1.1",
                src_port=12345,
                dst_ip="10.0.0.1",
                dst_port=80,
                ack=1000 + i * 100,
                tcp_len=100,
            )
            detector.add_packet(packet)
        
        # Add packets from reverse direction
        for i in range(2):
            packet = TcpPacketInfo(
                stream_id=1,
                src_ip="10.0.0.1",
                src_port=80,
                dst_ip="192.168.1.1",
                dst_port=12345,
                ack=2000 + i * 100,
                tcp_len=100,
            )
            detector.add_packet(packet)
        
        # Check both directions exist
        assert 1 in detector._streams
        forward_dir = "192.168.1.1:12345->10.0.0.1:80"
        reverse_dir = "10.0.0.1:80->192.168.1.1:12345"
        assert forward_dir in detector._streams[1]
        assert reverse_dir in detector._streams[1]
    
    def test_pure_ack_detection(self):
        """Test detection of pure ACK packets (tcp.len==0)."""
        detector = OneWayDetector()
        
        # Add packets with tcp.len > 0 (not pure ACK)
        packet = TcpPacketInfo(
            stream_id=1,
            src_ip="192.168.1.1",
            src_port=12345,
            dst_ip="10.0.0.1",
            dst_port=80,
            ack=1000,
            tcp_len=100,
        )
        detector.add_packet(packet)
        
        packet = TcpPacketInfo(
            stream_id=1,
            src_ip="192.168.1.1",
            src_port=12345,
            dst_ip="10.0.0.1",
            dst_port=80,
            ack=1100,
            tcp_len=100,
        )
        detector.add_packet(packet)
        
        direction = "192.168.1.1:12345->10.0.0.1:80"
        stats = detector._streams[1][direction]
        assert stats.has_pure_ack is False
        
        # Add pure ACK packets (tcp.len == 0)
        packet = TcpPacketInfo(
            stream_id=1,
            src_ip="192.168.1.1",
            src_port=12345,
            dst_ip="10.0.0.1",
            dst_port=80,
            ack=1200,
            tcp_len=0,
        )
        detector.add_packet(packet)
        
        # Should now have pure ACK
        assert stats.has_pure_ack is True
    
    def test_analyze_one_way_stream(self):
        """Test analysis of a one-way stream."""
        detector = OneWayDetector(ack_threshold=20)
        
        # Add packets from only one direction with pure ACKs
        for i in range(10):
            packet = TcpPacketInfo(
                stream_id=1,
                src_ip="192.168.1.1",
                src_port=12345,
                dst_ip="10.0.0.1",
                dst_port=80,
                ack=1000 + i * 10,
                tcp_len=0,
            )
            detector.add_packet(packet)
        
        # Analyze
        results = list(detector.analyze())
        assert len(results) == 1
        
        analysis = results[0]
        assert analysis.stream_id == 1
        assert analysis.is_one_way is True
        assert analysis.ack_delta == 90  # 1090 - 1000
        assert analysis.has_pure_ack is True
    
    def test_analyze_bidirectional_stream(self):
        """Test analysis of a bidirectional stream (should not be detected)."""
        detector = OneWayDetector(ack_threshold=20)
        
        # Add packets from both directions
        for i in range(5):
            # Forward
            packet = TcpPacketInfo(
                stream_id=1,
                src_ip="192.168.1.1",
                src_port=12345,
                dst_ip="10.0.0.1",
                dst_port=80,
                ack=1000 + i * 10,
                tcp_len=0,
            )
            detector.add_packet(packet)
            
            # Reverse
            packet = TcpPacketInfo(
                stream_id=1,
                src_ip="10.0.0.1",
                src_port=80,
                dst_ip="192.168.1.1",
                dst_port=12345,
                ack=2000 + i * 10,
                tcp_len=0,
            )
            detector.add_packet(packet)
        
        # Analyze - should not detect as one-way
        results = list(detector.analyze())
        assert len(results) == 0
    
    def test_analyze_below_threshold(self):
        """Test analysis with ACK delta below threshold."""
        detector = OneWayDetector(ack_threshold=100)
        
        # Add packets with small ACK delta
        for i in range(5):
            packet = TcpPacketInfo(
                stream_id=1,
                src_ip="192.168.1.1",
                src_port=12345,
                dst_ip="10.0.0.1",
                dst_port=80,
                ack=1000 + i * 5,
                tcp_len=0,
            )
            detector.add_packet(packet)
        
        # Analyze - ACK delta is 20, below threshold of 100
        results = list(detector.analyze())
        assert len(results) == 0
    
    def test_analyze_no_pure_ack(self):
        """Test analysis without pure ACK packets."""
        detector = OneWayDetector(ack_threshold=20)
        
        # Add packets without pure ACKs (all have tcp.len > 0)
        for i in range(10):
            packet = TcpPacketInfo(
                stream_id=1,
                src_ip="192.168.1.1",
                src_port=12345,
                dst_ip="10.0.0.1",
                dst_port=80,
                ack=1000 + i * 10,
                tcp_len=100,  # Not pure ACK
            )
            detector.add_packet(packet)
        
        # Analyze - should not detect without pure ACKs
        results = list(detector.analyze())
        assert len(results) == 0
    
    def test_get_reverse_direction(self):
        """Test reverse direction calculation."""
        detector = OneWayDetector()
        
        direction = "192.168.1.1:12345->10.0.0.1:80"
        reverse = detector._get_reverse_direction(direction)
        assert reverse == "10.0.0.1:80->192.168.1.1:12345"
        
        # Test reverse of reverse
        reverse2 = detector._get_reverse_direction(reverse)
        assert reverse2 == direction
    
    def test_multiple_streams(self):
        """Test analysis with multiple streams."""
        detector = OneWayDetector(ack_threshold=20)
        
        # Stream 1: one-way
        for i in range(10):
            packet = TcpPacketInfo(
                stream_id=1,
                src_ip="192.168.1.1",
                src_port=12345,
                dst_ip="10.0.0.1",
                dst_port=80,
                ack=1000 + i * 10,
                tcp_len=0,
            )
            detector.add_packet(packet)
        
        # Stream 2: bidirectional (not one-way)
        for i in range(5):
            packet = TcpPacketInfo(
                stream_id=2,
                src_ip="192.168.1.2",
                src_port=23456,
                dst_ip="10.0.0.2",
                dst_port=443,
                ack=2000 + i * 10,
                tcp_len=0,
            )
            detector.add_packet(packet)
            
            packet = TcpPacketInfo(
                stream_id=2,
                src_ip="10.0.0.2",
                src_port=443,
                dst_ip="192.168.1.2",
                dst_port=23456,
                ack=3000 + i * 10,
                tcp_len=0,
            )
            detector.add_packet(packet)
        
        # Stream 3: one-way
        for i in range(15):
            packet = TcpPacketInfo(
                stream_id=3,
                src_ip="192.168.1.3",
                src_port=34567,
                dst_ip="10.0.0.3",
                dst_port=22,
                ack=4000 + i * 10,
                tcp_len=0,
            )
            detector.add_packet(packet)
        
        # Analyze
        results = list(detector.analyze())
        assert len(results) == 2
        
        stream_ids = {r.stream_id for r in results}
        assert stream_ids == {1, 3}

