"""Packet extractor for TCP connections."""

from __future__ import annotations
import logging
from dataclasses import dataclass
from pathlib import Path

from capmaster.core.tshark_wrapper import TsharkWrapper

logger = logging.getLogger(__name__)


@dataclass
class TcpPacket:
    """
    TCP packet information for comparison.
    
    Contains the fields needed for packet-level comparison:
    - IP ID (ipid)
    - TCP flags
    - Sequence number
    - Acknowledgment number
    """
    
    frame_number: int
    """Frame number in the PCAP file"""
    
    ip_id: int
    """IP identification field"""
    
    tcp_flags: str
    """TCP flags (hex string)"""
    
    seq: int
    """TCP sequence number (absolute)"""
    
    ack: int
    """TCP acknowledgment number (absolute)"""
    
    timestamp: float
    """Packet timestamp"""
    
    def __str__(self) -> str:
        """String representation for display."""
        return (
            f"Frame {self.frame_number}: "
            f"IPID={self.ip_id:#06x} "
            f"Flags={self.tcp_flags} "
            f"Seq={self.seq} "
            f"Ack={self.ack}"
        )


class PacketExtractor:
    """
    Extract TCP packets from PCAP files based on 5-tuple filter.
    
    Uses tshark to extract packet-level information for a specific
    TCP connection identified by its 5-tuple (src_ip, src_port, dst_ip, dst_port, protocol).
    """
    
    # Fields to extract from tshark
    FIELDS = [
        "frame.number",      # Frame number
        "ip.id",            # IP identification
        "tcp.flags",        # TCP flags (hex)
        "tcp.seq",          # TCP sequence number (absolute)
        "tcp.ack",          # TCP acknowledgment number (absolute)
        "frame.time_epoch", # Timestamp
    ]
    
    def __init__(self, tshark: TsharkWrapper | None = None):
        """
        Initialize the packet extractor.
        
        Args:
            tshark: TsharkWrapper instance (creates new one if None)
        """
        self.tshark = tshark or TsharkWrapper()
    
    def extract_packets(
        self,
        pcap_file: Path,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> list[TcpPacket]:
        """
        Extract TCP packets for a specific connection.
        
        Args:
            pcap_file: Path to the PCAP file
            src_ip: Source IP address
            src_port: Source port
            dst_ip: Destination IP address
            dst_port: Destination port
        
        Returns:
            List of TcpPacket objects in chronological order
        """
        # Build display filter for the TCP connection (bidirectional)
        # Match packets in both directions of the connection
        filter_expr = (
            f"((ip.src=={src_ip} and tcp.srcport=={src_port} and "
            f"ip.dst=={dst_ip} and tcp.dstport=={dst_port}) or "
            f"(ip.src=={dst_ip} and tcp.srcport=={dst_port} and "
            f"ip.dst=={src_ip} and tcp.dstport=={src_port}))"
        )
        
        # Build tshark command
        args = [
            "-r", str(pcap_file),
            "-Y", filter_expr,
            "-o", "tcp.relative_sequence_numbers:false",  # Use absolute sequence numbers
            "-T", "fields",
            "-E", "separator=\t",
            "-E", "quote=d",
            "-E", "occurrence=f",  # First occurrence only
        ]
        
        # Add field extraction arguments
        for field in self.FIELDS:
            args.extend(["-e", field])
        
        # Execute tshark
        result = self.tshark.execute(args)
        
        if result.returncode != 0:
            raise RuntimeError(f"tshark extraction failed: {result.stderr}")
        
        # Parse output
        packets = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            
            fields = line.split("\t")
            if len(fields) != len(self.FIELDS):
                logger.warning(f"Skipping malformed line: {line}")
                continue
            
            try:
                # Strip quotes from fields (tshark adds quotes with -E quote=d)
                frame_number = int(fields[0].strip('"'))
                ip_id_str = fields[1].strip('"')
                tcp_flags = fields[2].strip('"') if fields[2] else "0x000"
                seq_str = fields[3].strip('"')
                ack_str = fields[4].strip('"')
                timestamp_str = fields[5].strip('"')

                packet = TcpPacket(
                    frame_number=frame_number,
                    ip_id=int(ip_id_str, 16) if ip_id_str else 0,  # Parse hex
                    tcp_flags=tcp_flags,
                    seq=int(seq_str) if seq_str else 0,
                    ack=int(ack_str) if ack_str else 0,
                    timestamp=float(timestamp_str) if timestamp_str else 0.0,
                )
                packets.append(packet)
            except (ValueError, IndexError) as e:
                logger.warning(f"Error parsing packet: {line}, error: {e}")
                continue
        
        logger.debug(f"Extracted {len(packets)} packets from {pcap_file}")
        return packets
    
    def extract_by_stream_id(
        self,
        pcap_file: Path,
        stream_id: int,
    ) -> list[TcpPacket]:
        """
        Extract TCP packets for a specific stream ID.
        
        Args:
            pcap_file: Path to the PCAP file
            stream_id: TCP stream ID from tshark
        
        Returns:
            List of TcpPacket objects in chronological order
        """
        # Build display filter for the TCP stream
        filter_expr = f"tcp.stream=={stream_id}"
        
        # Build tshark command
        args = [
            "-r", str(pcap_file),
            "-Y", filter_expr,
            "-o", "tcp.relative_sequence_numbers:false",  # Use absolute sequence numbers
            "-T", "fields",
            "-E", "separator=\t",
            "-E", "quote=d",
            "-E", "occurrence=f",  # First occurrence only
        ]
        
        # Add field extraction arguments
        for field in self.FIELDS:
            args.extend(["-e", field])
        
        # Execute tshark
        result = self.tshark.execute(args)
        
        if result.returncode != 0:
            raise RuntimeError(f"tshark extraction failed: {result.stderr}")
        
        # Parse output
        packets = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            
            fields = line.split("\t")
            if len(fields) != len(self.FIELDS):
                logger.warning(f"Skipping malformed line: {line}")
                continue
            
            try:
                # Strip quotes from fields (tshark adds quotes with -E quote=d)
                frame_number = int(fields[0].strip('"'))
                ip_id_str = fields[1].strip('"')
                tcp_flags = fields[2].strip('"') if fields[2] else "0x000"
                seq_str = fields[3].strip('"')
                ack_str = fields[4].strip('"')
                timestamp_str = fields[5].strip('"')

                packet = TcpPacket(
                    frame_number=frame_number,
                    ip_id=int(ip_id_str, 16) if ip_id_str else 0,  # Parse hex
                    tcp_flags=tcp_flags,
                    seq=int(seq_str) if seq_str else 0,
                    ack=int(ack_str) if ack_str else 0,
                    timestamp=float(timestamp_str) if timestamp_str else 0.0,
                )
                packets.append(packet)
            except (ValueError, IndexError) as e:
                logger.warning(f"Error parsing packet: {line}, error: {e}")
                continue

        logger.debug(f"Extracted {len(packets)} packets for stream {stream_id}")
        return packets

