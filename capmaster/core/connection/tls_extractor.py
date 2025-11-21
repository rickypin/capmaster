"""TLS Client Hello information extraction from PCAP files."""

from __future__ import annotations
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from capmaster.core.tshark_wrapper import TsharkWrapper
from capmaster.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass(slots=True)
class TlsClientHelloInfo:
    """
    TLS Client Hello information for a TCP connection.
    
    This class stores TLS handshake fields that can be used to match
    the same TCP connection across different capture points.
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
    
    random: str
    """TLS Client Hello random field (32 bytes, hex string)"""
    
    session_id: str
    """TLS Client Hello session ID field (hex string, may be empty)"""
    
    def __str__(self) -> str:
        """String representation."""
        return (
            f"TlsClientHello(frame={self.frame_number}, stream={self.stream_id}, "
            f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}, "
            f"random={self.random[:16]}..., session_id={self.session_id[:16]}...)"
        )


class TlsClientHelloExtractor:
    """
    Extract TLS Client Hello fields from PCAP files using tshark.
    
    This extractor focuses on TLS handshake fields that enable direct
    TCP connection matching across different capture points.
    """
    
    # Fields to extract from tshark
    FIELDS = [
        "frame.number",
        "tcp.stream",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tls.handshake.random",      # Client Hello random (32 bytes)
        "tls.handshake.session_id",  # Client Hello session ID
    ]
    
    def __init__(self) -> None:
        """Initialize the extractor with a tshark wrapper."""
        self.tshark = TsharkWrapper()
    
    def extract(self, pcap_file: Path) -> Iterator[TlsClientHelloInfo]:
        """
        Extract TLS Client Hello information from a PCAP file.
        
        Args:
            pcap_file: Path to the PCAP file
        
        Yields:
            TlsClientHelloInfo objects for each TLS Client Hello packet
        
        Raises:
            RuntimeError: If tshark extraction fails
        """
        # Build tshark command
        args = [
            "-Y",
            "tls.handshake.type == 1",  # Filter for Client Hello only (type=1)
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",  # First occurrence only
        ]
        
        # Add field extraction arguments
        for field in self.FIELDS:
            args.extend(["-e", field])
        
        # Execute tshark
        result = self.tshark.execute(args=args, input_file=pcap_file)
        
        # Parse the TSV output from stdout
        yield from self._parse_tsv_string(result.stdout)
    
    def _parse_tsv_string(self, tsv_string: str) -> Iterator[TlsClientHelloInfo]:
        """
        Parse TSV string output from tshark.
        
        Args:
            tsv_string: TSV formatted string from tshark
        
        Yields:
            TlsClientHelloInfo objects
        """
        for line in tsv_string.strip().split("\n"):
            if not line:
                continue

            fields = line.split("\t")

            # Allow one specific schema variation: missing trailing session_id field.
            # In this case tshark may omit the last column entirely when Session ID
            # length is 0. Treat this as an empty session_id instead of malformed.
            if len(fields) == len(self.FIELDS) - 1:
                logger.debug(
                    "TLS TSV line missing trailing session_id field, treating "
                    "session_id as empty: %s",
                    line,
                )
                fields.append('""')

            if len(fields) != len(self.FIELDS):
                logger.warning(
                    "Skipping malformed TLS TSV line (field count=%d): %s",
                    len(fields),
                    line,
                )
                continue

            info = self._parse_fields(fields)
            if info:
                yield info
    
    def _parse_fields(self, fields: list[str]) -> TlsClientHelloInfo | None:
        """
        Parse TSV fields into TlsClientHelloInfo.
        
        Args:
            fields: List of field values from TSV
        
        Returns:
            TlsClientHelloInfo object or None if parsing fails
        """
        try:
            frame_number = int(fields[0].strip('"')) if fields[0] else 0
            stream_id = int(fields[1].strip('"')) if fields[1] else 0
            src_ip = fields[2].strip('"') if fields[2] else ""
            dst_ip = fields[3].strip('"') if fields[3] else ""
            src_port = int(fields[4].strip('"')) if fields[4] else 0
            dst_port = int(fields[5].strip('"')) if fields[5] else 0
            random = fields[6].strip('"') if fields[6] else ""
            session_id = fields[7].strip('"') if fields[7] else ""
            
            # Validate that we have at least the random field (required)
            if not random:
                logger.warning(f"Skipping Client Hello without random field: frame={frame_number}")
                return None
            
            return TlsClientHelloInfo(
                frame_number=frame_number,
                stream_id=stream_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                random=random,
                session_id=session_id,
            )
        except (ValueError, IndexError) as e:
            logger.warning(f"Error parsing TLS Client Hello fields: {e}")
            return None

