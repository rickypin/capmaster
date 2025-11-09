"""Tests for test fixtures and PCAP builder."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.fixtures import PcapBuilder, create_tcp_connection_pcap


class TestPcapBuilder:
    """Test the PCAP builder utility."""
    
    def test_create_empty_pcap(self, tmp_path: Path):
        """Test creating an empty PCAP file with just header."""
        builder = PcapBuilder()
        pcap_file = builder.build(tmp_path / "empty.pcap")
        
        assert pcap_file.exists()
        assert pcap_file.stat().st_size == 24  # Just the PCAP header
    
    def test_create_tcp_syn_packet(self, tmp_path: Path):
        """Test creating a PCAP with a single TCP SYN packet."""
        builder = PcapBuilder()
        builder.add_tcp_packet(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            flags=0x02,  # SYN
        )
        
        pcap_file = builder.build(tmp_path / "syn.pcap")
        
        assert pcap_file.exists()
        # Header (24) + Packet header (16) + Ethernet (14) + IP (20) + TCP (20)
        assert pcap_file.stat().st_size == 24 + 16 + 14 + 20 + 20
    
    def test_create_multiple_packets(self, tmp_path: Path):
        """Test creating a PCAP with multiple packets."""
        builder = PcapBuilder()
        
        for i in range(5):
            builder.add_tcp_packet(
                src_ip=f"192.168.1.{100 + i}",
                dst_ip="10.0.0.1",
                src_port=54321 + i,
                dst_port=80,
                timestamp_sec=1234567890 + i,
            )
        
        pcap_file = builder.build(tmp_path / "multiple.pcap")
        
        assert pcap_file.exists()
        # Header + 5 * (Packet header + Ethernet + IP + TCP)
        expected_size = 24 + 5 * (16 + 14 + 20 + 20)
        assert pcap_file.stat().st_size == expected_size
    
    def test_create_udp_packet(self, tmp_path: Path):
        """Test creating a PCAP with UDP packet."""
        builder = PcapBuilder()
        builder.add_udp_packet(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=53,
            payload=b"\x00\x01\x01\x00\x00\x01",  # DNS query
        )
        
        pcap_file = builder.build(tmp_path / "udp.pcap")
        
        assert pcap_file.exists()
        assert pcap_file.stat().st_size > 24
    
    def test_create_icmp_packet(self, tmp_path: Path):
        """Test creating a PCAP with ICMP packet."""
        builder = PcapBuilder()
        builder.add_icmp_packet(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            icmp_type=8,  # Echo request
        )
        
        pcap_file = builder.build(tmp_path / "icmp.pcap")
        
        assert pcap_file.exists()
        assert pcap_file.stat().st_size > 24
    
    def test_tcp_with_payload(self, tmp_path: Path):
        """Test creating TCP packet with payload."""
        builder = PcapBuilder()
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        builder.add_tcp_packet(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            flags=0x18,  # PSH+ACK
            payload=payload,
        )
        
        pcap_file = builder.build(tmp_path / "http.pcap")
        
        assert pcap_file.exists()
        # Should include the payload
        assert pcap_file.stat().st_size > 24 + 16 + 14 + 20 + 20
    
    def test_builder_chaining(self, tmp_path: Path):
        """Test that builder methods can be chained."""
        pcap_file = (
            PcapBuilder()
            .add_tcp_packet("192.168.1.1", "10.0.0.1", 1234, 80)
            .add_tcp_packet("192.168.1.2", "10.0.0.1", 1235, 80)
            .add_udp_packet("192.168.1.3", "8.8.8.8", 1236, 53)
            .build(tmp_path / "chained.pcap")
        )
        
        assert pcap_file.exists()
        assert pcap_file.stat().st_size > 24


class TestTcpConnectionPcap:
    """Test the TCP connection PCAP creator."""
    
    def test_create_tcp_connection(self, tmp_path: Path):
        """Test creating a complete TCP connection."""
        pcap_file = create_tcp_connection_pcap(tmp_path / "connection.pcap")
        
        assert pcap_file.exists()
        assert pcap_file.stat().st_size > 24
    
    def test_tcp_connection_with_custom_packets(self, tmp_path: Path):
        """Test creating TCP connection with custom packet count."""
        pcap_file = create_tcp_connection_pcap(
            tmp_path / "connection_20.pcap",
            num_packets=20
        )
        
        assert pcap_file.exists()
        # More packets = larger file
        assert pcap_file.stat().st_size > 1000


@pytest.mark.integration
class TestPcapValidation:
    """Test that created PCAPs are valid using tshark."""
    
    def test_pcap_readable_by_tshark(self, tmp_path: Path):
        """Test that created PCAP can be read by tshark."""
        builder = PcapBuilder()
        builder.add_tcp_packet("192.168.1.100", "10.0.0.1", 54321, 80)
        pcap_file = builder.build(tmp_path / "test.pcap")
        
        # Try to read with tshark
        result = subprocess.run(
            ["tshark", "-r", str(pcap_file), "-c", "1"],
            capture_output=True,
            text=True,
        )
        
        # Should succeed (exit code 0) even if no packets
        assert result.returncode == 0
    
    def test_tcp_connection_readable_by_tshark(self, tmp_path: Path):
        """Test that TCP connection PCAP can be read by tshark."""
        pcap_file = create_tcp_connection_pcap(tmp_path / "connection.pcap")
        
        # Count packets with tshark
        result = subprocess.run(
            ["tshark", "-r", str(pcap_file), "-T", "fields", "-e", "frame.number"],
            capture_output=True,
            text=True,
        )
        
        assert result.returncode == 0
        # Should have multiple packets
        packet_count = len([line for line in result.stdout.strip().split('\n') if line])
        assert packet_count >= 10


class TestConfTestFixtures:
    """Test fixtures from conftest.py."""
    
    def test_test_pcap_fixture(self, test_pcap: Path):
        """Test that test_pcap fixture creates a valid file."""
        assert test_pcap.exists()
        assert test_pcap.suffix == ".pcap"
        assert test_pcap.stat().st_size >= 24  # At least PCAP header
    
    def test_test_pcap_with_packets_fixture(self, test_pcap_with_packets: Path):
        """Test that test_pcap_with_packets fixture creates packets."""
        assert test_pcap_with_packets.exists()
        assert test_pcap_with_packets.stat().st_size > 24  # More than just header
    
    def test_test_dir_fixture(self, test_dir: Path):
        """Test that test_dir fixture creates multiple files."""
        assert test_dir.exists()
        assert test_dir.is_dir()
        
        pcap_files = list(test_dir.glob("*.pcap"))
        assert len(pcap_files) == 3
        
        for pcap_file in pcap_files:
            assert pcap_file.stat().st_size >= 24
    
    def test_temp_output_fixture(self, temp_output: Path):
        """Test that temp_output fixture creates a directory."""
        assert temp_output.exists()
        assert temp_output.is_dir()

