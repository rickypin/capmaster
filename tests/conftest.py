"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator

import pytest
from click.testing import CliRunner

# Import PCAP builder for use in fixtures
from tests.fixtures import PcapBuilder, create_tcp_connection_pcap


@pytest.fixture
def runner() -> CliRunner:
    """Provide a Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def tmp_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Provide a temporary directory path."""
    return tmp_path_factory.mktemp("test")


def _create_pcap_header() -> bytes:
    """Create a standard PCAP file header."""
    # PCAP Global Header (24 bytes)
    # Magic number: 0xa1b2c3d4 (microsecond resolution, little-endian)
    # Version: 2.4
    # Timezone: 0
    # Timestamp accuracy: 0
    # Snapshot length: 65535
    # Link-layer type: 1 (Ethernet)
    return bytes.fromhex(
        "d4c3b2a1"  # Magic number (little-endian)
        "0200"      # Major version
        "0400"      # Minor version
        "00000000"  # Timezone
        "00000000"  # Timestamp accuracy
        "ffff0000"  # Snapshot length (65535)
        "01000000"  # Link-layer type (Ethernet)
    )


def _create_packet_header(timestamp_sec: int, timestamp_usec: int, packet_len: int) -> bytes:
    """Create a PCAP packet header."""
    # Packet Header (16 bytes)
    # Timestamp seconds: 4 bytes
    # Timestamp microseconds: 4 bytes
    # Captured length: 4 bytes
    # Original length: 4 bytes
    return struct.pack('<IIII', timestamp_sec, timestamp_usec, packet_len, packet_len)


def _create_tcp_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Create a minimal TCP SYN packet."""
    # Ethernet header (14 bytes)
    eth_header = bytes.fromhex(
        "ffffffffffff"  # Destination MAC (broadcast)
        "000000000001"  # Source MAC
        "0800"          # EtherType (IPv4)
    )

    # IP header (20 bytes)
    src_ip_bytes = bytes([int(x) for x in src_ip.split('.')])
    dst_ip_bytes = bytes([int(x) for x in dst_ip.split('.')])
    ip_header = bytes.fromhex(
        "45"    # Version (4) + IHL (5)
        "00"    # DSCP + ECN
        "0028"  # Total length (40 bytes: 20 IP + 20 TCP)
        "0001"  # Identification
        "0000"  # Flags + Fragment offset
        "40"    # TTL (64)
        "06"    # Protocol (TCP)
        "0000"  # Checksum (placeholder)
    ) + src_ip_bytes + dst_ip_bytes

    # TCP header (20 bytes) - SYN packet
    tcp_header = struct.pack(
        '>HHIIBBHHH',
        src_port,       # Source port
        dst_port,       # Destination port
        1000000,        # Sequence number
        0,              # Acknowledgment number
        0x50,           # Data offset (5) + Reserved
        0x02,           # Flags (SYN)
        8192,           # Window size
        0,              # Checksum (placeholder)
        0               # Urgent pointer
    )

    return eth_header + ip_header + tcp_header


@pytest.fixture
def test_pcap(tmp_path: Path) -> Path:
    """
    Create a minimal test PCAP file with header only.

    For tests that need actual packets, use test_pcap_with_packets fixture.
    """
    pcap_file = tmp_path / "test.pcap"
    pcap_file.write_bytes(_create_pcap_header())
    return pcap_file


@pytest.fixture
def test_pcap_with_packets(tmp_path: Path) -> Path:
    """
    Create a test PCAP file with actual TCP packets.

    Contains 3 TCP SYN packets for basic testing.
    """
    pcap_file = tmp_path / "test_with_packets.pcap"

    # Start with PCAP header
    data = _create_pcap_header()

    # Add 3 TCP SYN packets
    packets = [
        ("192.168.1.100", "10.0.0.1", 54321, 80),
        ("192.168.1.101", "10.0.0.1", 54322, 80),
        ("192.168.1.102", "10.0.0.1", 54323, 443),
    ]

    for i, (src_ip, dst_ip, src_port, dst_port) in enumerate(packets):
        packet_data = _create_tcp_syn_packet(src_ip, dst_ip, src_port, dst_port)
        packet_header = _create_packet_header(
            timestamp_sec=1234567890 + i,
            timestamp_usec=i * 1000,
            packet_len=len(packet_data)
        )
        data += packet_header + packet_data

    pcap_file.write_bytes(data)
    return pcap_file


@pytest.fixture
def test_dir(tmp_path: Path) -> Path:
    """
    Create a test directory with multiple PCAP files.
    """
    test_dir = tmp_path / "pcaps"
    test_dir.mkdir()

    # Create multiple test PCAP files
    for i in range(3):
        pcap_file = test_dir / f"test{i}.pcap"
        pcap_file.write_bytes(_create_pcap_header())

    return test_dir


@pytest.fixture
def temp_output(tmp_path: Path) -> Iterator[Path]:
    """
    Provide a temporary output directory.

    Yields:
        Path to temporary output directory
    """
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    yield output_dir


@pytest.fixture
def real_pcap() -> Path:
    """
    Provide path to a real PCAP file from cases directory.

    Returns:
        Path to a real PCAP file, or None if not available
    """
    # Try to find a real PCAP file in cases directory
    cases_dir = Path(__file__).parent.parent / "cases"
    if not cases_dir.exists():
        pytest.skip("cases directory not found")

    # Look for VOIP.pcap in V-001
    voip_pcap = cases_dir / "V-001" / "VOIP.pcap"
    if voip_pcap.exists():
        return voip_pcap

    # Look for any .pcap file
    for pcap_file in cases_dir.rglob("*.pcap"):
        if pcap_file.is_file() and pcap_file.stat().st_size > 0:
            return pcap_file

    pytest.skip("No real PCAP files found in cases directory")


@pytest.fixture
def tcp_connection_pcap(tmp_path: Path) -> Path:
    """
    Create a PCAP file with a complete TCP connection.

    Contains SYN, SYN-ACK, ACK, data packets, and FIN.
    Useful for testing TCP analysis and matching.
    """
    return create_tcp_connection_pcap(tmp_path / "tcp_connection.pcap")


@pytest.fixture
def multi_connection_pcap(tmp_path: Path) -> Path:
    """
    Create a PCAP file with multiple TCP connections.

    Useful for testing connection matching and filtering.
    """
    builder = PcapBuilder()

    # Connection 1: 192.168.1.100 -> 10.0.0.1:80
    builder.add_tcp_packet("192.168.1.100", "10.0.0.1", 54321, 80, flags=0x02, timestamp_sec=1000)
    builder.add_tcp_packet("10.0.0.1", "192.168.1.100", 80, 54321, flags=0x12, timestamp_sec=1000, timestamp_usec=10000)
    builder.add_tcp_packet("192.168.1.100", "10.0.0.1", 54321, 80, flags=0x10, timestamp_sec=1000, timestamp_usec=20000)

    # Connection 2: 192.168.1.101 -> 10.0.0.1:443
    builder.add_tcp_packet("192.168.1.101", "10.0.0.1", 54322, 443, flags=0x02, timestamp_sec=1001)
    builder.add_tcp_packet("10.0.0.1", "192.168.1.101", 443, 54322, flags=0x12, timestamp_sec=1001, timestamp_usec=10000)
    builder.add_tcp_packet("192.168.1.101", "10.0.0.1", 54322, 443, flags=0x10, timestamp_sec=1001, timestamp_usec=20000)

    # Connection 3: 192.168.1.102 -> 10.0.0.2:22
    builder.add_tcp_packet("192.168.1.102", "10.0.0.2", 54323, 22, flags=0x02, timestamp_sec=1002)
    builder.add_tcp_packet("10.0.0.2", "192.168.1.102", 22, 54323, flags=0x12, timestamp_sec=1002, timestamp_usec=10000)
    builder.add_tcp_packet("192.168.1.102", "10.0.0.2", 54323, 22, flags=0x10, timestamp_sec=1002, timestamp_usec=20000)

    return builder.build(tmp_path / "multi_connection.pcap")


@pytest.fixture
def mixed_protocol_pcap(tmp_path: Path) -> Path:
    """
    Create a PCAP file with mixed protocols (TCP, UDP, ICMP).

    Useful for testing protocol detection and filtering.
    """
    builder = PcapBuilder()

    # TCP packets
    builder.add_tcp_packet("192.168.1.100", "10.0.0.1", 54321, 80, timestamp_sec=1000)
    builder.add_tcp_packet("192.168.1.100", "10.0.0.1", 54322, 443, timestamp_sec=1001)

    # UDP packets
    builder.add_udp_packet("192.168.1.100", "8.8.8.8", 12345, 53, timestamp_sec=1002)
    builder.add_udp_packet("192.168.1.100", "8.8.4.4", 12346, 53, timestamp_sec=1003)

    # ICMP packets
    builder.add_icmp_packet("192.168.1.100", "8.8.8.8", icmp_type=8, timestamp_sec=1004)
    builder.add_icmp_packet("8.8.8.8", "192.168.1.100", icmp_type=0, timestamp_sec=1005)

    return builder.build(tmp_path / "mixed_protocol.pcap")


@pytest.fixture
def pcap_builder() -> type[PcapBuilder]:
    """
    Provide the PcapBuilder class for custom PCAP creation in tests.

    Example usage:
        def test_something(pcap_builder, tmp_path):
            pcap = (pcap_builder()
                .add_tcp_packet("192.168.1.1", "10.0.0.1", 1234, 80)
                .build(tmp_path / "custom.pcap"))
    """
    return PcapBuilder

