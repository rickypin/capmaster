"""Shared utility for extracting TCP connections from PCAP files."""

from __future__ import annotations

from pathlib import Path

from capmaster.plugins.match.connection import ConnectionBuilder, TcpConnection
from capmaster.plugins.match.extractor import TcpFieldExtractor


def extract_connections_from_pcap(pcap_file: Path) -> list[TcpConnection]:
    """
    Extract TCP connections from a PCAP file.
    
    This is a shared utility function used by both MatchPlugin and ComparePlugin
    to avoid code duplication.
    
    Args:
        pcap_file: Path to PCAP file
        
    Returns:
        List of TcpConnection objects
        
    Example:
        >>> from pathlib import Path
        >>> connections = extract_connections_from_pcap(Path("capture.pcap"))
        >>> print(f"Found {len(connections)} connections")
    """
    extractor = TcpFieldExtractor()
    builder = ConnectionBuilder()
    
    # Extract packets and build connections
    for packet in extractor.extract(pcap_file):
        builder.add_packet(packet)
    
    # Build and return connections
    return list(builder.build_connections())

