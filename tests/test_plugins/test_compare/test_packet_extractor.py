"""Unit tests for packet extractor."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
from collections import namedtuple

import pytest

from capmaster.plugins.compare_common.packet_extractor import PacketExtractor, TcpPacket
from capmaster.core.tshark_wrapper import TsharkWrapper
from capmaster.utils.errors import TsharkExecutionError

# Create a simple result object for mocking tshark results
TsharkResult = namedtuple('TsharkResult', ['returncode', 'stdout', 'stderr'])


@pytest.mark.integration
class TestPacketExtractor:
    """Test PacketExtractor class."""

    @pytest.fixture
    def extractor(self) -> PacketExtractor:
        """Create a PacketExtractor instance."""
        return PacketExtractor()

    @pytest.fixture
    def mock_tshark(self) -> MagicMock:
        """Create a mock TsharkWrapper."""
        mock = MagicMock(spec=TsharkWrapper)
        return mock

    @pytest.fixture
    def sample_pcap(self, tmp_path: Path, pcap_builder) -> Path:
        """Create a sample PCAP file with TCP packets."""
        return pcap_builder().add_tcp_packet(
            "192.168.1.100", "10.0.0.1", 54321, 80,
            flags=0x02, seq=1000000, timestamp_sec=1000
        ).add_tcp_packet(
            "10.0.0.1", "192.168.1.100", 80, 54321,
            flags=0x12, seq=2000000, ack=1000001, timestamp_sec=1000, timestamp_usec=10000
        ).add_tcp_packet(
            "192.168.1.100", "10.0.0.1", 54321, 80,
            flags=0x10, seq=1000001, ack=2000001, timestamp_sec=1000, timestamp_usec=20000
        ).build(tmp_path / "sample.pcap")

    def test_extractor_initialization(self):
        """Test PacketExtractor initialization."""
        extractor = PacketExtractor()
        assert extractor.tshark is not None
        assert isinstance(extractor.tshark, TsharkWrapper)

    def test_extractor_with_custom_tshark(self, mock_tshark: MagicMock):
        """Test PacketExtractor with custom TsharkWrapper."""
        extractor = PacketExtractor(tshark=mock_tshark)
        assert extractor.tshark is mock_tshark

    def test_extract_packets_builds_correct_filter(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test that extract_packets builds correct display filter."""
        extractor.tshark = mock_tshark
        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout="",
            stderr=""
        )

        extractor.extract_packets(
            sample_pcap,
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="10.0.0.1",
            dst_port=80
        )

        # Verify tshark was called
        assert mock_tshark.execute.called

        # Get the arguments passed to tshark
        call_args = mock_tshark.execute.call_args[0][0]

        # Should include display filter for bidirectional traffic
        assert "-Y" in call_args
        filter_idx = call_args.index("-Y") + 1
        filter_expr = call_args[filter_idx]

        # Filter should match both directions
        assert "192.168.1.100" in filter_expr
        assert "10.0.0.1" in filter_expr
        assert "54321" in filter_expr
        assert "80" in filter_expr

    def test_extract_packets_uses_absolute_seq_numbers(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test that extract_packets uses absolute sequence numbers."""
        extractor.tshark = mock_tshark
        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout="",
            stderr=""
        )

        extractor.extract_packets(
            sample_pcap,
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="10.0.0.1",
            dst_port=80
        )

        call_args = mock_tshark.execute.call_args[0][0]

        # Should disable relative sequence numbers
        assert "-o" in call_args
        assert "tcp.relative_sequence_numbers:false" in call_args

    def test_extract_packets_parses_output(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test that extract_packets correctly parses tshark output."""
        extractor.tshark = mock_tshark
        
        # Mock tshark output with 3 packets
        # Format: frame_num, ip_id, flags, seq, ack, timestamp, src_ip, dst_ip, src_port, dst_port, info
        mock_output = (
            "1\t64\t0x002\t1000000\t0\t1234567890.123456\t192.168.1.100\t10.0.0.1\t54321\t80\tSYN\n"
            "2\t65\t0x012\t2000000\t1000001\t1234567890.234567\t10.0.0.1\t192.168.1.100\t80\t54321\tSYN, ACK\n"
            "3\t66\t0x010\t1000001\t2000001\t1234567890.345678\t192.168.1.100\t10.0.0.1\t54321\t80\tACK\n"
        )

        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout=mock_output,
            stderr=""
        )

        packets = extractor.extract_packets(
            sample_pcap,
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="10.0.0.1",
            dst_port=80
        )

        assert len(packets) == 3

        # Check first packet
        # IP ID "64" (hex) = 100 (decimal)
        from decimal import Decimal
        assert packets[0].frame_number == 1
        assert packets[0].ip_id == 100
        assert packets[0].tcp_flags == "0x002"
        assert packets[0].seq == 1000000
        assert packets[0].ack == 0
        assert packets[0].timestamp == Decimal('1234567890.123456')
        assert packets[0].src_ip == "192.168.1.100"
        assert packets[0].dst_ip == "10.0.0.1"
        assert packets[0].src_port == 54321
        assert packets[0].dst_port == 80
        assert packets[0].info == "SYN"

        # Check second packet
        # IP ID "65" (hex) = 101 (decimal)
        assert packets[1].frame_number == 2
        assert packets[1].ip_id == 101
        assert packets[1].tcp_flags == "0x012"
        assert packets[1].seq == 2000000
        assert packets[1].ack == 1000001

        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout=mock_output,
            stderr=""
        )

        packets = extractor.extract_packets(
            sample_pcap,
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="10.0.0.1",
            dst_port=80
        )

        assert len(packets) == 3

        # Check first packet
        # IP ID "64" (hex) = 100 (decimal)
        from decimal import Decimal
        assert packets[0].frame_number == 1
        assert packets[0].ip_id == 100
        assert packets[0].tcp_flags == "0x002"
        assert packets[0].seq == 1000000
        assert packets[0].ack == 0
        assert packets[0].timestamp == Decimal('1234567890.123456')

        # Check second packet
        # IP ID "65" (hex) = 101 (decimal)
        assert packets[1].frame_number == 2
        assert packets[1].ip_id == 101
        assert packets[1].tcp_flags == "0x012"
        assert packets[1].seq == 2000000
        assert packets[1].ack == 1000001

    def test_extract_packets_handles_empty_output(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test that extract_packets handles empty tshark output."""
        extractor.tshark = mock_tshark
        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout="",
            stderr=""
        )

        packets = extractor.extract_packets(
            sample_pcap,
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="10.0.0.1",
            dst_port=80
        )

        assert len(packets) == 0

    def test_extract_packets_handles_tshark_error(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test that extract_packets handles tshark errors."""
        extractor.tshark = mock_tshark
        # TsharkWrapper.execute() raises TsharkExecutionError for non-zero exit codes (except 2)
        mock_tshark.execute.side_effect = TsharkExecutionError(
            "tshark", 1, "tshark: error message"
        )

        with pytest.raises(TsharkExecutionError) as exc_info:
            extractor.extract_packets(
                sample_pcap,
                src_ip="192.168.1.100",
                src_port=54321,
                dst_ip="10.0.0.1",
                dst_port=80
            )

        assert "exit code 1" in exc_info.value.message

    def test_extract_by_stream_id_builds_correct_filter(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test that extract_by_stream_id builds correct filter."""
        extractor.tshark = mock_tshark
        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout="",
            stderr=""
        )

        extractor.extract_by_stream_id(sample_pcap, stream_id=5)

        call_args = mock_tshark.execute.call_args[0][0]

        # Should include stream filter
        assert "-Y" in call_args
        filter_idx = call_args.index("-Y") + 1
        filter_expr = call_args[filter_idx]

        assert "tcp.stream==5" in filter_expr

    def test_extract_by_stream_id_parses_output(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test that extract_by_stream_id correctly parses output."""
        extractor.tshark = mock_tshark

        mock_output = (
            "1\t100\t0x002\t1000000\t0\t1234567890.123456\t192.168.1.100\t10.0.0.1\t54321\t80\tSYN\n"
            "2\t101\t0x012\t2000000\t1000001\t1234567890.234567\t10.0.0.1\t192.168.1.100\t80\t54321\tSYN, ACK\n"
        )

        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout=mock_output,
            stderr=""
        )

        packets = extractor.extract_by_stream_id(sample_pcap, stream_id=5)

        assert len(packets) == 2
        assert packets[0].frame_number == 1
        assert packets[1].frame_number == 2

    def test_extract_packets_skips_malformed_lines(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test that extract_packets skips malformed lines."""
        extractor.tshark = mock_tshark

        # Include a malformed line (missing fields)
        mock_output = (
            "1\t100\t0x002\t1000000\t0\t1234567890.123456\t192.168.1.100\t10.0.0.1\t54321\t80\tSYN\n"
            "2\t101\t0x012\n"  # Malformed: missing fields
            "3\t102\t0x010\t1000001\t2000001\t1234567890.345678\t192.168.1.100\t10.0.0.1\t54321\t80\tACK\n"
        )

        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout=mock_output,
            stderr=""
        )

        packets = extractor.extract_packets(
            sample_pcap,
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="10.0.0.1",
            dst_port=80
        )

        # Should skip malformed line and return 2 packets
        assert len(packets) == 2
        assert packets[0].frame_number == 1
        assert packets[1].frame_number == 3

    def test_extract_packets_handles_none_values(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test that extract_packets handles None/empty values."""
        extractor.tshark = mock_tshark

        # Empty IPID and ACK fields - these are converted to 0, not None
        mock_output = "1\t\t0x002\t1000000\t\t1234567890.123456\t192.168.1.100\t10.0.0.1\t54321\t80\tSYN\n"

        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout=mock_output,
            stderr=""
        )

        packets = extractor.extract_packets(
            sample_pcap,
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="10.0.0.1",
            dst_port=80
        )

        assert len(packets) == 1
        # Empty values are converted to 0, not None
        assert packets[0].ip_id == 0
        assert packets[0].ack == 0

    def test_extract_multiple_streams_empty_list(
        self, extractor: PacketExtractor, sample_pcap: Path
    ):
        """Test extract_multiple_streams with empty stream ID list."""
        result = extractor.extract_multiple_streams(sample_pcap, [])
        assert result == {}

    def test_extract_multiple_streams_single_stream(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test extract_multiple_streams with single stream."""
        extractor.tshark = mock_tshark

        # Mock output with tcp.stream field first
        mock_output = (
            "0\t1\t0x0001\t0x002\t1000000\t0\t1234567890.123456\t192.168.1.100\t10.0.0.1\t54321\t80\tSYN\n"
            "0\t2\t0x0002\t0x012\t2000000\t1000001\t1234567890.234567\t10.0.0.1\t192.168.1.100\t80\t54321\tSYN, ACK\n"
        )

        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout=mock_output,
            stderr=""
        )

        result = extractor.extract_multiple_streams(sample_pcap, [0])

        # Verify tshark was called with correct filter
        args = mock_tshark.execute.call_args[0][0]
        assert "-Y" in args
        filter_idx = args.index("-Y") + 1
        assert args[filter_idx] == "tcp.stream==0"

        # Verify tcp.stream field was added
        assert "-e" in args
        assert "tcp.stream" in args

        # Verify results
        assert 0 in result
        assert len(result[0]) == 2
        assert result[0][0].frame_number == 1
        assert result[0][1].frame_number == 2

    def test_extract_multiple_streams_multiple_streams(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test extract_multiple_streams with multiple streams."""
        extractor.tshark = mock_tshark

        # Mock output with mixed streams
        mock_output = (
            "0\t1\t0x0001\t0x002\t1000000\t0\t1234567890.123456\t192.168.1.100\t10.0.0.1\t54321\t80\tSYN\n"
            "1\t2\t0x0002\t0x012\t2000000\t1000001\t1234567890.234567\t10.0.0.1\t192.168.1.100\t80\t54321\tSYN, ACK\n"
            "0\t3\t0x0003\t0x010\t1000001\t2000001\t1234567890.345678\t192.168.1.100\t10.0.0.1\t54321\t80\tACK\n"
            "2\t4\t0x0004\t0x002\t3000000\t0\t1234567890.456789\t192.168.1.100\t10.0.0.1\t54321\t80\tSYN\n"
        )

        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout=mock_output,
            stderr=""
        )

        result = extractor.extract_multiple_streams(sample_pcap, [0, 1])

        # Verify filter includes both streams
        args = mock_tshark.execute.call_args[0][0]
        filter_idx = args.index("-Y") + 1
        assert "tcp.stream==0" in args[filter_idx]
        assert "tcp.stream==1" in args[filter_idx]

        # Verify results
        assert 0 in result
        assert 1 in result
        assert 2 not in result  # Stream 2 was not requested (though present in output)

        assert len(result[0]) == 2
        assert len(result[1]) == 1

    def test_extract_multiple_streams_handles_tshark_error(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test extract_multiple_streams handles tshark errors."""
        extractor.tshark = mock_tshark
        mock_tshark.execute.side_effect = TsharkExecutionError(
            "tshark", 1, "tshark: error message"
        )

        with pytest.raises(TsharkExecutionError):
            extractor.extract_multiple_streams(sample_pcap, [0])

    def test_extract_multiple_streams_skips_unknown_streams(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test extract_multiple_streams skips streams not in request list."""
        extractor.tshark = mock_tshark

        # Output contains stream 99 which was not requested
        mock_output = (
            "0\t1\t0x0001\t0x002\t1000000\t0\t1234567890.123456\t192.168.1.100\t10.0.0.1\t54321\t80\tSYN\n"
            "99\t2\t0x0002\t0x012\t2000000\t1000001\t1234567890.234567\t10.0.0.1\t192.168.1.100\t80\t54321\tSYN, ACK\n"
            "1\t3\t0x0003\t0x010\t1000001\t2000001\t1234567890.345678\t192.168.1.100\t10.0.0.1\t54321\t80\tACK\n"
        )

        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout=mock_output,
            stderr=""
        )

        result = extractor.extract_multiple_streams(sample_pcap, [0, 1])

        assert 0 in result
        assert 1 in result
        assert 99 not in result

        assert len(result[0]) == 1
        assert len(result[1]) == 1

    def test_extract_multiple_streams_multiple_streams(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test extract_multiple_streams with multiple streams."""
        extractor.tshark = mock_tshark

        # Mock output with packets from different streams
        mock_output = (
            "0\t1\t0x0001\t0x002\t1000000\t0\t1234567890.123456\t192.168.1.100\t10.0.0.1\t54321\t80\tSYN\n"
            "1\t2\t0x0002\t0x012\t2000000\t1000001\t1234567890.234567\t10.0.0.1\t192.168.1.100\t80\t54321\tSYN, ACK\n"
            "0\t3\t0x0003\t0x010\t1000001\t2000001\t1234567890.345678\t192.168.1.100\t10.0.0.1\t54321\t80\tACK\n"
            "2\t4\t0x0004\t0x002\t3000000\t0\t1234567890.456789\t192.168.1.100\t10.0.0.1\t54321\t80\tSYN\n"
        )

        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout=mock_output,
            stderr=""
        )

        result = extractor.extract_multiple_streams(sample_pcap, [0, 1, 2])

        # Verify tshark was called with correct filter (OR of all streams)
        args = mock_tshark.execute.call_args[0][0]
        assert "-Y" in args
        filter_idx = args.index("-Y") + 1
        assert "tcp.stream==0 or tcp.stream==1 or tcp.stream==2" == args[filter_idx]

        # Verify results are grouped by stream
        assert len(result) == 3
        assert 0 in result
        assert 1 in result
        assert 2 in result

        # Stream 0 has 2 packets
        assert len(result[0]) == 2
        assert result[0][0].frame_number == 1
        assert result[0][1].frame_number == 3

        # Stream 1 has 1 packet
        assert len(result[1]) == 1
        assert result[1][0].frame_number == 2

        # Stream 2 has 1 packet
        assert len(result[2]) == 1
        assert result[2][0].frame_number == 4

    def test_extract_multiple_streams_handles_tshark_error(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test extract_multiple_streams handles tshark errors."""
        extractor.tshark = mock_tshark

        # TsharkWrapper.execute() raises TsharkExecutionError for non-zero exit codes (except 2)
        mock_tshark.execute.side_effect = TsharkExecutionError(
            "tshark", 1, "tshark: error message"
        )

        with pytest.raises(TsharkExecutionError) as exc_info:
            extractor.extract_multiple_streams(sample_pcap, [0, 1])

        assert "exit code 1" in exc_info.value.message

    def test_extract_multiple_streams_skips_unknown_streams(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test extract_multiple_streams skips packets from unrequested streams."""
        extractor.tshark = mock_tshark

        # Mock output includes stream 99 which is not requested
        mock_output = (
            "0\t1\t0x0001\t0x002\t1000000\t0\t1234567890.123456\t192.168.1.100\t10.0.0.1\t54321\t80\tSYN\n"
            "99\t2\t0x0002\t0x012\t2000000\t1000001\t1234567890.234567\t10.0.0.1\t192.168.1.100\t80\t54321\tSYN, ACK\n"
            "1\t3\t0x0003\t0x010\t1000001\t2000001\t1234567890.345678\t192.168.1.100\t10.0.0.1\t54321\t80\tACK\n"
        )

        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout=mock_output,
            stderr=""
        )

        result = extractor.extract_multiple_streams(sample_pcap, [0, 1])

        # Stream 99 should be skipped
        assert 99 not in result
        assert len(result) == 2
        assert len(result[0]) == 1
        assert len(result[1]) == 1

    def test_extract_multiple_streams_performance_optimization(
        self, extractor: PacketExtractor, sample_pcap: Path, mock_tshark: MagicMock
    ):
        """Test that extract_multiple_streams uses single tshark call for multiple streams."""
        extractor.tshark = mock_tshark

        # Mock output for 3 streams
        mock_output = (
            "0\t1\t0x0001\t0x002\t1000000\t0\t1234567890.123456\t192.168.1.100\t10.0.0.1\t54321\t80\tSYN\n"
            "1\t2\t0x0002\t0x012\t2000000\t1000001\t1234567890.234567\t10.0.0.1\t192.168.1.100\t80\t54321\tSYN, ACK\n"
            "2\t3\t0x0003\t0x010\t1000001\t2000001\t1234567890.345678\t192.168.1.100\t10.0.0.1\t54321\t80\tACK\n"
        )

        mock_tshark.execute.return_value = TsharkResult(
            returncode=0,
            stdout=mock_output,
            stderr=""
        )

        # Extract 3 streams
        result = extractor.extract_multiple_streams(sample_pcap, [0, 1, 2])

        # Should call tshark only ONCE (not 3 times)
        assert mock_tshark.execute.call_count == 1

        # Verify the filter includes all 3 streams
        call_args = mock_tshark.execute.call_args[0][0]
        filter_arg_index = call_args.index("-Y") + 1
        filter_expr = call_args[filter_arg_index]
        assert "tcp.stream==0" in filter_expr
        assert "tcp.stream==1" in filter_expr
        assert "tcp.stream==2" in filter_expr
        assert " or " in filter_expr  # Should use OR to combine filters

        # Verify results
        assert len(result) == 3
        assert 0 in result
        assert 1 in result
        assert 2 in result
