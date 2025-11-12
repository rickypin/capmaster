"""F5 Ethernet Trailer field extraction from PCAP files."""

from __future__ import annotations
import csv
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from capmaster.core.tshark_wrapper import TsharkWrapper


@dataclass(slots=True)
class F5TrailerInfo:
    """
    F5 Ethernet Trailer information for a TCP packet.
    
    F5 adds trailer information to each packet that records peer connection details.
    This allows direct correlation of TCP connections on both sides of F5.
    """
    
    frame_number: int
    """Frame number in the PCAP file"""
    
    stream_id: int
    """TCP stream ID"""
    
    src_ip: str
    """Source IP address"""
    
    src_port: int
    """Source port"""
    
    dst_ip: str
    """Destination IP address"""
    
    dst_port: int
    """Destination port"""
    
    flags: str
    """TCP flags (hex string)"""
    
    peer_addrs: list[str]
    """Peer IP addresses from f5ethtrailer.peeraddr (may be multiple)"""
    
    peer_ports: list[int]
    """Peer ports from f5ethtrailer.peerport (may be multiple)"""
    
    peer_local_addr: str
    """Peer local address from f5ethtrailer.peerlocaladdr"""
    
    peer_local_port: int
    """Peer local port from f5ethtrailer.peerlocalport"""


class F5EthTrailerExtractor:
    """
    Extract F5 Ethernet Trailer fields from PCAP files using tshark.
    
    This extractor focuses on F5-specific fields that enable direct
    TCP connection matching across F5 VIP and SNAT sides.
    """
    
    # Fields to extract from tshark
    FIELDS = [
        "frame.number",
        "tcp.stream",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.flags",
        "f5ethtrailer.peeraddr",      # Peer IP address(es)
        "f5ethtrailer.peerport",      # Peer port(s)
        "f5ethtrailer.peerlocaladdr", # Peer local address
        "f5ethtrailer.peerlocalport", # Peer local port
    ]
    
    def __init__(self) -> None:
        """Initialize the extractor with a tshark wrapper."""
        self.tshark = TsharkWrapper()
    
    def extract(self, pcap_file: Path) -> Iterator[F5TrailerInfo]:
        """
        Extract F5 trailer information from a PCAP file.
        
        Args:
            pcap_file: Path to the PCAP file
        
        Yields:
            F5TrailerInfo objects for each packet with F5 trailer
        
        Raises:
            RuntimeError: If tshark extraction fails
        """
        # Build tshark command
        args = [
            "-Y",
            "f5ethtrailer",  # Filter for packets with F5 trailer only
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "quote=d",
            "-E",
            "occurrence=a",  # All occurrences (for multiple peer addresses)
        ]
        
        # Add field extraction arguments
        for field in self.FIELDS:
            args.extend(["-e", field])
        
        # Execute tshark
        result = self.tshark.execute(args=args, input_file=pcap_file)
        
        # Parse the TSV output from stdout
        yield from self._parse_tsv_string(result.stdout)
    
    def _parse_tsv_string(self, tsv_content: str) -> Iterator[F5TrailerInfo]:
        """
        Parse TSV output from tshark.
        
        Args:
            tsv_content: TSV content as string
        
        Yields:
            F5TrailerInfo objects
        """
        # Split into lines and parse as CSV
        lines = tsv_content.strip().split('\n')
        if not lines or not lines[0]:
            return
        
        reader = csv.reader(lines, delimiter="\t")
        
        for row in reader:
            if len(row) < len(self.FIELDS):
                # Skip incomplete rows
                continue
            
            try:
                info = self._parse_row(row)
                if info:
                    yield info
            except (ValueError, IndexError):
                # Skip malformed rows
                continue

    def _parse_row(self, row: list[str]) -> F5TrailerInfo | None:
        """
        Parse a single TSV row into a F5TrailerInfo.

        Args:
            row: List of field values from TSV

        Returns:
            F5TrailerInfo object or None if parsing fails
        """
        try:
            # Extract fields (in the same order as FIELDS)
            frame_number = int(row[0]) if row[0] else 0
            stream_id = int(row[1]) if row[1] else 0
            src_ip = row[2] or ""
            dst_ip = row[3] or ""
            src_port = int(row[4]) if row[4] else 0
            dst_port = int(row[5]) if row[5] else 0
            flags = row[6] or "0x0000"

            # Parse peer addresses (comma-separated)
            peer_addrs_str = row[7] if len(row) > 7 else ""
            peer_addrs = [addr.strip() for addr in peer_addrs_str.split(',') if addr.strip()]

            # Parse peer ports (comma-separated)
            peer_ports_str = row[8] if len(row) > 8 else ""
            peer_ports = []
            if peer_ports_str:
                for port_str in peer_ports_str.split(','):
                    port_str = port_str.strip()
                    if port_str:
                        try:
                            peer_ports.append(int(port_str))
                        except ValueError:
                            pass

            # Parse peer local address and port
            peer_local_addr = row[9] if len(row) > 9 else ""
            peer_local_port = 0
            if len(row) > 10 and row[10]:
                try:
                    peer_local_port = int(row[10])
                except ValueError:
                    pass

            return F5TrailerInfo(
                frame_number=frame_number,
                stream_id=stream_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                flags=flags,
                peer_addrs=peer_addrs,
                peer_ports=peer_ports,
                peer_local_addr=peer_local_addr,
                peer_local_port=peer_local_port,
            )
        except (ValueError, IndexError):
            return None

