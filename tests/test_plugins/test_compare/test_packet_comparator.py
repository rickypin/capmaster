"""Unit tests for packet comparator."""

from __future__ import annotations

import pytest

from capmaster.plugins.compare.packet_comparator import (
    ComparisonResult,
    DiffType,
    PacketComparator,
    PacketDiff,
    TcpPacket,
)


@pytest.mark.integration
class TestTcpPacket:
    """Test TcpPacket dataclass."""

    def test_tcp_packet_creation(self):
        """Test creating a TcpPacket."""
        packet = TcpPacket(
            frame_number=1,
            ip_id=12345,
            tcp_flags="0x002",
            seq=1000000,
            ack=0,
            timestamp=1234567890.123456,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            info="Test Packet",
        )

        assert packet.frame_number == 1
        assert packet.ip_id == 12345
        assert packet.tcp_flags == "0x002"
        assert packet.seq == 1000000
        assert packet.ack == 0
        assert packet.timestamp == 1234567890.123456
        assert packet.src_ip == "192.168.1.1"
        assert packet.dst_ip == "10.0.0.1"
        assert packet.src_port == 12345
        assert packet.dst_port == 80
        assert packet.info == "Test Packet"

    def test_tcp_packet_with_none_values(self):
        """Test TcpPacket with None values."""
        packet = TcpPacket(
            frame_number=1,
            ip_id=None,
            tcp_flags="0x010",
            seq=1000000,
            ack=None,
            timestamp=1234567890.0,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            info="Test Packet",
        )

        assert packet.ip_id is None
        assert packet.ack is None


@pytest.mark.integration
class TestPacketDiff:
    """Test PacketDiff dataclass."""

    def test_packet_diff_creation(self):
        """Test creating a PacketDiff."""
        diff = PacketDiff(
            diff_type=DiffType.TCP_FLAGS,
            packet_index=0,
            frame_a=1,
            frame_b=2,
            value_a="0x002",
            value_b="0x012",
        )

        assert diff.diff_type == DiffType.TCP_FLAGS
        assert diff.packet_index == 0
        assert diff.frame_a == 1
        assert diff.frame_b == 2
        assert diff.value_a == "0x002"
        assert diff.value_b == "0x012"


@pytest.mark.integration
class TestComparisonResult:
    """Test ComparisonResult dataclass."""

    def test_comparison_result_creation(self):
        """Test creating a ComparisonResult."""
        result = ComparisonResult(
            connection_id="192.168.1.100:54321 <-> 10.0.0.1:80",
            packets_a=10,
            packets_b=10,
            differences=[],
        )

        assert result.connection_id == "192.168.1.100:54321 <-> 10.0.0.1:80"
        assert result.packets_a == 10
        assert result.packets_b == 10
        assert len(result.differences) == 0

    def test_comparison_result_with_differences(self):
        """Test ComparisonResult with differences."""
        diff = PacketDiff(
            diff_type=DiffType.TCP_FLAGS,
            packet_index=0,
            frame_a=1,
            frame_b=2,
            value_a="0x002",
            value_b="0x012",
        )

        result = ComparisonResult(
            connection_id="test",
            packets_a=5,
            packets_b=5,
            differences=[diff],
        )

        assert len(result.differences) == 1
        assert result.differences[0].diff_type == DiffType.TCP_FLAGS


@pytest.mark.integration
class TestPacketComparator:
    """Test PacketComparator class."""

    @pytest.fixture
    def comparator(self) -> PacketComparator:
        """Create a PacketComparator instance."""
        return PacketComparator()

    def test_compare_identical_packets(self, comparator: PacketComparator):
        """Test comparing identical packet sequences."""
        packets_a = [
            TcpPacket(1, 100, "0x002", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
            TcpPacket(2, 101, "0x010", 1000001, 1000000, 1000.1, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
        ]

        packets_b = [
            TcpPacket(1, 100, "0x002", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
            TcpPacket(2, 101, "0x010", 1000001, 1000000, 1000.1, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
        ]

        result = comparator.compare(packets_a, packets_b, "test_conn")

        assert result.packets_a == 2
        assert result.packets_b == 2
        assert len(result.differences) == 0

    def test_compare_tcp_flags_difference(self, comparator: PacketComparator):
        """Test detecting TCP flags differences."""
        packets_a = [
            TcpPacket(1, 100, "0x002", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),  # SYN
        ]

        packets_b = [
            TcpPacket(1, 100, "0x012", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),  # SYN+ACK
        ]

        result = comparator.compare(packets_a, packets_b, "test_conn")

        assert len(result.differences) == 1
        assert result.differences[0].diff_type == DiffType.TCP_FLAGS
        assert result.differences[0].value_a == "0x002"
        assert result.differences[0].value_b == "0x012"

    def test_compare_seq_num_difference(self, comparator: PacketComparator):
        """Test detecting sequence number differences."""
        packets_a = [
            TcpPacket(1, 100, "0x002", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
        ]

        packets_b = [
            TcpPacket(1, 100, "0x002", 2000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),  # Different seq
        ]

        result = comparator.compare(packets_a, packets_b, "test_conn")

        assert len(result.differences) == 1
        assert result.differences[0].diff_type == DiffType.SEQ_NUM
        assert result.differences[0].value_a == 1000000
        assert result.differences[0].value_b == 2000000

    def test_compare_ack_num_difference(self, comparator: PacketComparator):
        """Test detecting acknowledgment number differences."""
        packets_a = [
            TcpPacket(1, 100, "0x010", 1000000, 500000, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
        ]

        packets_b = [
            TcpPacket(1, 100, "0x010", 1000000, 600000, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),  # Different ack
        ]

        result = comparator.compare(packets_a, packets_b, "test_conn")

        assert len(result.differences) == 1
        assert result.differences[0].diff_type == DiffType.ACK_NUM
        assert result.differences[0].value_a == 500000
        assert result.differences[0].value_b == 600000

    def test_compare_multiple_differences(self, comparator: PacketComparator):
        """Test detecting multiple differences in same packet."""
        packets_a = [
            TcpPacket(1, 100, "0x002", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
        ]

        packets_b = [
            TcpPacket(1, 100, "0x012", 2000000, 500000, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),  # All different
        ]

        result = comparator.compare(packets_a, packets_b, "test_conn")

        # Should detect all three differences
        assert len(result.differences) == 3
        diff_types = {diff.diff_type for diff in result.differences}
        assert DiffType.TCP_FLAGS in diff_types
        assert DiffType.SEQ_NUM in diff_types
        assert DiffType.ACK_NUM in diff_types

    def test_compare_different_packet_counts(self, comparator: PacketComparator):
        """Test comparing sequences with different packet counts."""
        packets_a = [
            TcpPacket(1, 100, "0x002", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
            TcpPacket(2, 101, "0x010", 1000001, 1000000, 1000.1, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
        ]

        packets_b = [
            TcpPacket(1, 100, "0x002", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
        ]

        result = comparator.compare(packets_a, packets_b, "test_conn")

        assert result.packets_a == 2
        assert result.packets_b == 1
        # Should have differences: packet count mismatch + IP ID only in A
        assert len(result.differences) >= 1
        # Check for packet count difference
        packet_count_diffs = [d for d in result.differences if d.diff_type == DiffType.PACKET_COUNT]
        assert len(packet_count_diffs) == 1

    def test_compare_empty_sequences(self, comparator: PacketComparator):
        """Test comparing empty packet sequences."""
        result = comparator.compare([], [], "test_conn")

        assert result.packets_a == 0
        assert result.packets_b == 0
        assert len(result.differences) == 0

    def test_compare_one_empty_sequence(self, comparator: PacketComparator):
        """Test comparing when one sequence is empty."""
        packets_a = [
            TcpPacket(1, 100, "0x002", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
        ]

        result = comparator.compare(packets_a, [], "test_conn")

        assert result.packets_a == 1
        assert result.packets_b == 0

    def test_compare_matched_only_mode(self, comparator: PacketComparator):
        """Test matched-only comparison mode."""
        # In matched-only mode, only packets with matching IPID are compared
        packets_a = [
            TcpPacket(1, 100, "0x002", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
            TcpPacket(2, 101, "0x010", 1000001, 1000000, 1000.1, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
            TcpPacket(3, 102, "0x010", 1000002, 1000001, 1000.2, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),  # Only in A
        ]

        packets_b = [
            TcpPacket(1, 100, "0x002", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
            TcpPacket(2, 101, "0x010", 1000001, 1000000, 1000.1, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
            TcpPacket(4, 103, "0x010", 1000003, 1000002, 1000.3, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),  # Only in B
        ]

        result = comparator.compare(packets_a, packets_b, "test_conn", matched_only=True)

        # In matched-only mode, should only compare packets with matching IPID
        # Packets with IPID 100 and 101 should be compared
        # Packets with IPID 102 (only in A) and 103 (only in B) should be ignored
        # The result should have fewer differences than full comparison
        assert result.packets_a == 3
        assert result.packets_b == 3

    def test_compare_with_none_ipid(self, comparator: PacketComparator):
        """Test comparing packets with None IPID values."""
        packets_a = [
            TcpPacket(1, None, "0x002", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
        ]

        packets_b = [
            TcpPacket(1, None, "0x002", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
        ]

        # Should handle None IPID gracefully
        result = comparator.compare(packets_a, packets_b, "test_conn")

        assert result.packets_a == 1
        assert result.packets_b == 1

    def test_compare_preserves_frame_numbers(self, comparator: PacketComparator):
        """Test that frame numbers are preserved in differences."""
        packets_a = [
            TcpPacket(10, 100, "0x002", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
        ]

        packets_b = [
            TcpPacket(20, 100, "0x012", 1000000, 0, 1000.0, "1.1.1.1", "2.2.2.2", 1000, 2000, "Info"),
        ]

        result = comparator.compare(packets_a, packets_b, "test_conn")

        assert len(result.differences) == 1
        assert result.differences[0].frame_a == 10
        assert result.differences[0].frame_b == 20

