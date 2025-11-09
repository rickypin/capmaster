"""PCAP file builder for creating test fixtures.

This module provides utilities to programmatically create PCAP files
for testing without relying on external test data.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import List, Tuple


class PcapBuilder:
    """Builder for creating PCAP files programmatically."""
    
    def __init__(self):
        """Initialize PCAP builder."""
        self.packets: List[Tuple[int, int, bytes]] = []
        
    def add_tcp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        flags: int = 0x02,  # SYN by default
        seq: int = 1000000,
        ack: int = 0,
        timestamp_sec: int = 1234567890,
        timestamp_usec: int = 0,
        payload: bytes = b"",
    ) -> PcapBuilder:
        """Add a TCP packet to the PCAP file.
        
        Args:
            src_ip: Source IP address (e.g., "192.168.1.1")
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            flags: TCP flags (0x02=SYN, 0x10=ACK, 0x12=SYN+ACK, 0x01=FIN, 0x04=RST)
            seq: Sequence number
            ack: Acknowledgment number
            timestamp_sec: Timestamp seconds
            timestamp_usec: Timestamp microseconds
            payload: TCP payload data
            
        Returns:
            Self for chaining
        """
        packet_data = self._create_tcp_packet(
            src_ip, dst_ip, src_port, dst_port, flags, seq, ack, payload
        )
        self.packets.append((timestamp_sec, timestamp_usec, packet_data))
        return self
    
    def add_udp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        timestamp_sec: int = 1234567890,
        timestamp_usec: int = 0,
        payload: bytes = b"",
    ) -> PcapBuilder:
        """Add a UDP packet to the PCAP file.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            timestamp_sec: Timestamp seconds
            timestamp_usec: Timestamp microseconds
            payload: UDP payload data
            
        Returns:
            Self for chaining
        """
        packet_data = self._create_udp_packet(
            src_ip, dst_ip, src_port, dst_port, payload
        )
        self.packets.append((timestamp_sec, timestamp_usec, packet_data))
        return self
    
    def add_icmp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        icmp_type: int = 8,  # Echo request
        icmp_code: int = 0,
        timestamp_sec: int = 1234567890,
        timestamp_usec: int = 0,
    ) -> PcapBuilder:
        """Add an ICMP packet to the PCAP file.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            icmp_type: ICMP type (8=Echo Request, 0=Echo Reply)
            icmp_code: ICMP code
            timestamp_sec: Timestamp seconds
            timestamp_usec: Timestamp microseconds
            
        Returns:
            Self for chaining
        """
        packet_data = self._create_icmp_packet(
            src_ip, dst_ip, icmp_type, icmp_code
        )
        self.packets.append((timestamp_sec, timestamp_usec, packet_data))
        return self
    
    def build(self, output_path: Path) -> Path:
        """Build and write the PCAP file.
        
        Args:
            output_path: Path where to write the PCAP file
            
        Returns:
            Path to the created PCAP file
        """
        # PCAP Global Header
        data = self._create_pcap_header()
        
        # Add all packets
        for timestamp_sec, timestamp_usec, packet_data in self.packets:
            packet_header = self._create_packet_header(
                timestamp_sec, timestamp_usec, len(packet_data)
            )
            data += packet_header + packet_data
        
        output_path.write_bytes(data)
        return output_path
    
    @staticmethod
    def _create_pcap_header() -> bytes:
        """Create PCAP global header."""
        return bytes.fromhex(
            "d4c3b2a1"  # Magic number (little-endian)
            "0200"      # Major version
            "0400"      # Minor version
            "00000000"  # Timezone
            "00000000"  # Timestamp accuracy
            "ffff0000"  # Snapshot length (65535)
            "01000000"  # Link-layer type (Ethernet)
        )
    
    @staticmethod
    def _create_packet_header(timestamp_sec: int, timestamp_usec: int, packet_len: int) -> bytes:
        """Create PCAP packet header."""
        return struct.pack('<IIII', timestamp_sec, timestamp_usec, packet_len, packet_len)
    
    @staticmethod
    def _create_ethernet_header() -> bytes:
        """Create Ethernet header."""
        return bytes.fromhex(
            "ffffffffffff"  # Destination MAC (broadcast)
            "000000000001"  # Source MAC
            "0800"          # EtherType (IPv4)
        )
    
    @staticmethod
    def _create_ip_header(src_ip: str, dst_ip: str, protocol: int, total_length: int) -> bytes:
        """Create IP header."""
        src_ip_bytes = bytes([int(x) for x in src_ip.split('.')])
        dst_ip_bytes = bytes([int(x) for x in dst_ip.split('.')])
        
        return bytes.fromhex(
            "45"    # Version (4) + IHL (5)
            "00"    # DSCP + ECN
        ) + struct.pack('>H', total_length) + bytes.fromhex(
            "0001"  # Identification
            "0000"  # Flags + Fragment offset
            "40"    # TTL (64)
        ) + bytes([protocol]) + bytes.fromhex(
            "0000"  # Checksum (placeholder)
        ) + src_ip_bytes + dst_ip_bytes
    
    def _create_tcp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        flags: int,
        seq: int,
        ack: int,
        payload: bytes,
    ) -> bytes:
        """Create a complete TCP packet."""
        # TCP header (20 bytes minimum)
        tcp_header = struct.pack(
            '>HHIIBBHHH',
            src_port,       # Source port
            dst_port,       # Destination port
            seq,            # Sequence number
            ack,            # Acknowledgment number
            0x50,           # Data offset (5) + Reserved
            flags,          # Flags
            8192,           # Window size
            0,              # Checksum (placeholder)
            0               # Urgent pointer
        )
        
        # IP header
        ip_total_length = 20 + len(tcp_header) + len(payload)
        ip_header = self._create_ip_header(src_ip, dst_ip, 6, ip_total_length)
        
        # Ethernet header
        eth_header = self._create_ethernet_header()
        
        return eth_header + ip_header + tcp_header + payload
    
    def _create_udp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        payload: bytes,
    ) -> bytes:
        """Create a complete UDP packet."""
        # UDP header (8 bytes)
        udp_length = 8 + len(payload)
        udp_header = struct.pack(
            '>HHHH',
            src_port,       # Source port
            dst_port,       # Destination port
            udp_length,     # Length
            0               # Checksum (placeholder)
        )
        
        # IP header
        ip_total_length = 20 + len(udp_header) + len(payload)
        ip_header = self._create_ip_header(src_ip, dst_ip, 17, ip_total_length)
        
        # Ethernet header
        eth_header = self._create_ethernet_header()
        
        return eth_header + ip_header + udp_header + payload
    
    def _create_icmp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        icmp_type: int,
        icmp_code: int,
    ) -> bytes:
        """Create a complete ICMP packet."""
        # ICMP header (8 bytes minimum)
        icmp_header = struct.pack(
            '>BBHHH',
            icmp_type,      # Type
            icmp_code,      # Code
            0,              # Checksum (placeholder)
            1,              # Identifier
            1               # Sequence number
        )
        
        # IP header
        ip_total_length = 20 + len(icmp_header)
        ip_header = self._create_ip_header(src_ip, dst_ip, 1, ip_total_length)
        
        # Ethernet header
        eth_header = self._create_ethernet_header()
        
        return eth_header + ip_header + icmp_header


# Convenience functions for common test scenarios

def create_tcp_connection_pcap(output_path: Path, num_packets: int = 10) -> Path:
    """Create a PCAP with a complete TCP connection.
    
    Args:
        output_path: Where to save the PCAP file
        num_packets: Number of packets in the connection
        
    Returns:
        Path to created PCAP file
    """
    builder = PcapBuilder()
    
    # SYN
    builder.add_tcp_packet(
        "192.168.1.100", "10.0.0.1", 54321, 80,
        flags=0x02, seq=1000000, timestamp_sec=1234567890, timestamp_usec=0
    )
    
    # SYN-ACK
    builder.add_tcp_packet(
        "10.0.0.1", "192.168.1.100", 80, 54321,
        flags=0x12, seq=2000000, ack=1000001, timestamp_sec=1234567890, timestamp_usec=10000
    )
    
    # ACK
    builder.add_tcp_packet(
        "192.168.1.100", "10.0.0.1", 54321, 80,
        flags=0x10, seq=1000001, ack=2000001, timestamp_sec=1234567890, timestamp_usec=20000
    )
    
    # Data packets
    for i in range(num_packets - 5):
        builder.add_tcp_packet(
            "192.168.1.100", "10.0.0.1", 54321, 80,
            flags=0x18, seq=1000001 + i * 100, ack=2000001,
            timestamp_sec=1234567890, timestamp_usec=30000 + i * 10000,
            payload=b"X" * 100
        )
    
    # FIN
    builder.add_tcp_packet(
        "192.168.1.100", "10.0.0.1", 54321, 80,
        flags=0x11, seq=1000001 + (num_packets - 5) * 100, ack=2000001,
        timestamp_sec=1234567891, timestamp_usec=0
    )
    
    # FIN-ACK
    builder.add_tcp_packet(
        "10.0.0.1", "192.168.1.100", 80, 54321,
        flags=0x11, seq=2000001, ack=1000002 + (num_packets - 5) * 100,
        timestamp_sec=1234567891, timestamp_usec=10000
    )
    
    return builder.build(output_path)

