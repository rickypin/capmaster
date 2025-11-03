"""Tests for ProtocolDetector."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from capmaster.core.protocol_detector import ProtocolDetector


class TestProtocolDetector:
    """Test cases for ProtocolDetector."""

    def test_parse_protocol_hierarchy_basic(self) -> None:
        """Test parsing basic protocol hierarchy output."""
        output = """
===================================================================
Protocol Hierarchy Statistics
Filter: 

eth                                      frames:100 bytes:50000
  ip                                     frames:95 bytes:48000
    tcp                                  frames:80 bytes:40000
      http                               frames:20 bytes:10000
    udp                                  frames:15 bytes:8000
      dns                                frames:10 bytes:5000
===================================================================
"""
        mock_tshark = MagicMock()
        detector = ProtocolDetector(mock_tshark)

        protocols = detector._parse_protocol_hierarchy(output)

        assert protocols == {"eth", "ip", "tcp", "http", "udp", "dns"}

    def test_parse_protocol_hierarchy_with_ssl_tls(self) -> None:
        """Test parsing with SSL/TLS protocols."""
        output = """
eth                                      frames:50 bytes:25000
  ip                                     frames:50 bytes:25000
    tcp                                  frames:50 bytes:25000
      tls                                frames:30 bytes:15000
      ssl                                frames:20 bytes:10000
"""
        mock_tshark = MagicMock()
        detector = ProtocolDetector(mock_tshark)

        protocols = detector._parse_protocol_hierarchy(output)

        assert "tls" in protocols
        assert "ssl" in protocols

    def test_parse_protocol_hierarchy_empty(self) -> None:
        """Test parsing empty output."""
        output = """
===================================================================
Protocol Hierarchy Statistics
Filter: 
===================================================================
"""
        mock_tshark = MagicMock()
        detector = ProtocolDetector(mock_tshark)

        protocols = detector._parse_protocol_hierarchy(output)

        assert protocols == set()

    def test_parse_protocol_hierarchy_with_underscores(self) -> None:
        """Test parsing protocols with underscores."""
        output = """
eth                                      frames:10 bytes:5000
  ip                                     frames:10 bytes:5000
    tcp                                  frames:10 bytes:5000
      some_protocol                      frames:5 bytes:2500
"""
        mock_tshark = MagicMock()
        detector = ProtocolDetector(mock_tshark)

        protocols = detector._parse_protocol_hierarchy(output)

        assert "some_protocol" in protocols

    def test_parse_protocol_hierarchy_case_insensitive(self) -> None:
        """Test parsing converts protocols to lowercase."""
        output = """
ETH                                      frames:10 bytes:5000
  IP                                     frames:10 bytes:5000
    TCP                                  frames:10 bytes:5000
      HTTP                               frames:5 bytes:2500
"""
        mock_tshark = MagicMock()
        detector = ProtocolDetector(mock_tshark)

        protocols = detector._parse_protocol_hierarchy(output)

        assert protocols == {"eth", "ip", "tcp", "http"}

    def test_detect_success(self, tmp_path: Path) -> None:
        """Test successful protocol detection."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.touch()

        mock_tshark = MagicMock()
        mock_tshark.execute.return_value = MagicMock(
            stdout="""
eth                                      frames:100 bytes:50000
  ip                                     frames:95 bytes:48000
    tcp                                  frames:80 bytes:40000
      http                               frames:20 bytes:10000
""",
            returncode=0,
        )

        detector = ProtocolDetector(mock_tshark)
        protocols = detector.detect(pcap_file)

        assert protocols == {"eth", "ip", "tcp", "http"}
        mock_tshark.execute.assert_called_once_with(
            args=["-q", "-z", "io,phs"],
            input_file=pcap_file,
            timeout=60,
        )

    def test_detect_tshark_failure(self, tmp_path: Path) -> None:
        """Test protocol detection when tshark fails."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.touch()

        mock_tshark = MagicMock()
        mock_tshark.execute.side_effect = subprocess.CalledProcessError(1, "tshark")

        detector = ProtocolDetector(mock_tshark)

        with pytest.raises(subprocess.CalledProcessError):
            detector.detect(pcap_file)

    def test_detect_with_icmp(self, tmp_path: Path) -> None:
        """Test detection with ICMP protocol."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.touch()

        mock_tshark = MagicMock()
        mock_tshark.execute.return_value = MagicMock(
            stdout="""
eth                                      frames:50 bytes:25000
  ip                                     frames:50 bytes:25000
    icmp                                 frames:50 bytes:25000
""",
            returncode=0,
        )

        detector = ProtocolDetector(mock_tshark)
        protocols = detector.detect(pcap_file)

        assert "icmp" in protocols

    def test_detect_with_ftp(self, tmp_path: Path) -> None:
        """Test detection with FTP protocol."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.touch()

        mock_tshark = MagicMock()
        mock_tshark.execute.return_value = MagicMock(
            stdout="""
eth                                      frames:30 bytes:15000
  ip                                     frames:30 bytes:15000
    tcp                                  frames:30 bytes:15000
      ftp                                frames:15 bytes:7500
      ftp-data                           frames:15 bytes:7500
""",
            returncode=0,
        )

        detector = ProtocolDetector(mock_tshark)
        protocols = detector.detect(pcap_file)

        assert "ftp" in protocols
        assert "ftp-data" in protocols

