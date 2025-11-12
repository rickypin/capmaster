"""Shared utility for extracting TCP connections from PCAP files."""

from __future__ import annotations

from pathlib import Path

from capmaster.core.connection.models import (
    ConnectionBuilder,
    FiveTupleConnectionBuilder,
    TcpConnection,
)
from capmaster.core.connection.extractor import TcpFieldExtractor


def extract_connections_from_pcap(
    pcap_file: Path, merge_by_5tuple: bool = False
) -> list[TcpConnection]:
    """
    Extract TCP connections from a PCAP file.

    This is a shared utility function used by both MatchPlugin and ComparePlugin
    to avoid code duplication.

    Args:
        pcap_file: Path to PCAP file
        merge_by_5tuple: If True, merge connections by direction-independent 5-tuple
                        instead of by stream ID. This allows port reuse detection.

    Returns:
        List of TcpConnection objects

    Example:
        >>> from pathlib import Path
        >>> connections = extract_connections_from_pcap(Path("capture.pcap"))
        >>> print(f"Found {len(connections)} connections")

        >>> # Merge by 5-tuple for port reuse scenarios
        >>> connections = extract_connections_from_pcap(Path("capture.pcap"), merge_by_5tuple=True)
    """
    extractor = TcpFieldExtractor()

    # Choose builder based on merge_by_5tuple flag
    if merge_by_5tuple:
        builder = FiveTupleConnectionBuilder()
    else:
        builder = ConnectionBuilder()

    # Extract packets and build connections
    for packet in extractor.extract(pcap_file):
        builder.add_packet(packet)

    # Build and return connections
    return list(builder.build_connections())

