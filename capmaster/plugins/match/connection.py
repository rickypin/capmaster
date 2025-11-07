"""TCP connection data structures and feature extraction."""

import hashlib
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass


@dataclass
class TcpConnection:
    """
    TCP connection feature representation.

    This class stores the key features of a TCP connection that are used
    for matching connections across different PCAP files.

    Features (8 total, matching original script):
    1. SYN options sequence (syn_options)
    2. Client ISN (client_isn)
    3. Server ISN (server_isn)
    4. TCP timestamp (tcp_timestamp_tsval, tcp_timestamp_tsecr)
    5. Client first payload MD5 (client_payload_md5)
    6. Server first payload MD5 (server_payload_md5)
    7. Length shape signature (length_signature)
    8. IPID (ipid_first)
    """

    stream_id: int
    """TCP stream ID from tshark"""

    client_ip: str
    """Client IP address"""

    client_port: int
    """Client port number"""

    server_ip: str
    """Server IP address"""

    server_port: int
    """Server port number"""

    syn_timestamp: float
    """Timestamp of the SYN packet"""

    syn_options: str
    """TCP options fingerprint from SYN packet (mss=X;ws=Y;sack=Z;ts=W)"""

    client_isn: int
    """Client initial sequence number"""

    server_isn: int
    """Server initial sequence number"""

    tcp_timestamp_tsval: str
    """TCP timestamp TSval from SYN packet (empty string if not present)"""

    tcp_timestamp_tsecr: str
    """TCP timestamp TSecr from SYN packet (empty string if not present)"""

    client_payload_md5: str
    """MD5 hash of first client payload packet (first 256 bytes)"""

    server_payload_md5: str
    """MD5 hash of first server payload packet (first 256 bytes)"""

    length_signature: str
    """Packet length signature (e.g., 'C:100 S:200 C:50...')"""

    is_header_only: bool
    """Whether this connection contains only header packets (no payload)"""

    ipid_first: int
    """First IP ID value (0 if not available)"""

    ipid_set: set[int]
    """Set of all unique IP ID values in the stream (for flexible IPID matching)"""

    first_packet_time: float
    """Timestamp of the earliest packet in the stream (Unix timestamp in seconds)"""

    last_packet_time: float
    """Timestamp of the latest packet in the stream (Unix timestamp in seconds)"""

    packet_count: int
    """Total number of packets in the stream"""

    def __str__(self) -> str:
        """String representation for debugging."""
        return (
            f"TcpConnection(stream={self.stream_id}, "
            f"{self.client_ip}:{self.client_port} <-> {self.server_ip}:{self.server_port}, "
            f"ipid={self.ipid_first}, "
            f"time=[{self.first_packet_time:.3f}, {self.last_packet_time:.3f}], "
            f"packets={self.packet_count})"
        )

    def get_normalized_5tuple(self) -> tuple[str, int, str, int]:
        """
        Get normalized 5-tuple for direction-independent matching.

        Returns the 5-tuple in a canonical form where the "smaller" endpoint
        (by IP:Port comparison) always comes first. This allows matching
        connections regardless of which side initiated the connection.

        Returns:
            Tuple of (ip1, port1, ip2, port2) where ip1:port1 <= ip2:port2
        """
        endpoint1 = (self.client_ip, self.client_port)
        endpoint2 = (self.server_ip, self.server_port)

        # Sort endpoints to get canonical order
        if endpoint1 <= endpoint2:
            return (self.client_ip, self.client_port, self.server_ip, self.server_port)
        else:
            return (self.server_ip, self.server_port, self.client_ip, self.client_port)


@dataclass
class TcpPacket:
    """
    Individual TCP packet data.

    Used during connection feature extraction.
    """

    frame_number: int
    """Frame number in the PCAP file"""

    stream_id: int
    """TCP stream ID"""

    src_ip: str
    """Source IP address"""

    dst_ip: str
    """Destination IP address"""

    src_port: int
    """Source port"""

    dst_port: int
    """Destination port"""

    flags: str
    """TCP flags (hex string)"""

    seq: int
    """Sequence number"""

    ack: int
    """Acknowledgment number"""

    options: str
    """TCP options (hex string)"""

    length: int
    """TCP payload length"""

    ip_id: int
    """IP identification field"""

    timestamp: float | None = None
    """Packet timestamp (if available)"""

    tcp_timestamp_tsval: str = ""
    """TCP timestamp TSval option"""

    tcp_timestamp_tsecr: str = ""
    """TCP timestamp TSecr option"""

    payload_data: str = ""
    """Payload data (hex string)"""

    def is_syn(self) -> bool:
        """Check if this is a SYN packet (SYN=1, ACK=0)."""
        try:
            flags_int = int(self.flags, 16) if isinstance(self.flags, str) else self.flags
            # SYN flag is bit 1 (0x02), ACK flag is bit 4 (0x10)
            return (flags_int & 0x02) != 0 and (flags_int & 0x10) == 0
        except (ValueError, TypeError):
            return False

    def is_syn_ack(self) -> bool:
        """Check if this is a SYN-ACK packet (SYN=1, ACK=1)."""
        try:
            flags_int = int(self.flags, 16) if isinstance(self.flags, str) else self.flags
            # SYN flag is bit 1 (0x02), ACK flag is bit 4 (0x10)
            return (flags_int & 0x02) != 0 and (flags_int & 0x10) != 0
        except (ValueError, TypeError):
            return False

    def __str__(self) -> str:
        """String representation for debugging."""
        return (
            f"TcpPacket(frame={self.frame_number}, stream={self.stream_id}, "
            f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}, "
            f"flags=0x{self.flags}, len={self.length})"
        )


class ConnectionBuilder:
    """
    Build TcpConnection objects from TCP packets.

    This class processes a stream of TCP packets and extracts connection
    features needed for matching.
    """

    def __init__(self, payload_bytes: int = 100):
        """
        Initialize the connection builder.

        Args:
            payload_bytes: Number of payload bytes to use for hashing
        """
        self.payload_bytes = payload_bytes
        self._streams: dict[int, list[TcpPacket]] = defaultdict(list)

    def add_packet(self, packet: TcpPacket) -> None:
        """
        Add a packet to the builder.

        Args:
            packet: TCP packet to add
        """
        self._streams[packet.stream_id].append(packet)

    def build_connections(self) -> Iterator[TcpConnection]:
        """
        Build TcpConnection objects from collected packets.

        Yields:
            TcpConnection objects for each TCP stream
        """
        for stream_id, packets in self._streams.items():
            connection = self._build_connection(stream_id, packets)
            if connection:
                yield connection

    def _build_connection(self, stream_id: int, packets: list[TcpPacket]) -> TcpConnection | None:
        """
        Build a TcpConnection from a list of packets.

        Args:
            stream_id: TCP stream ID
            packets: List of packets in the stream

        Returns:
            TcpConnection object or None if connection cannot be built
        """
        if not packets:
            return None

        # Sort packets by frame number
        packets = sorted(packets, key=lambda p: p.frame_number)

        # Find SYN packet
        syn_packet = None
        syn_ack_packet = None

        for packet in packets:
            if packet.is_syn():
                syn_packet = packet
            elif packet.is_syn_ack():
                syn_ack_packet = packet

            if syn_packet and syn_ack_packet:
                break

        # Determine client and server
        # If no SYN packet, use first packet direction (matching original script)
        if syn_packet:
            client_ip = syn_packet.src_ip
            client_port = syn_packet.src_port
            server_ip = syn_packet.dst_ip
            server_port = syn_packet.dst_port
            syn_timestamp = syn_packet.timestamp or 0.0
            syn_options = syn_packet.options
            client_isn = syn_packet.seq
            server_isn = syn_ack_packet.seq if syn_ack_packet else 0
            ipid_first = syn_packet.ip_id
        else:
            # No SYN packet - use first packet direction
            first_packet = packets[0]
            client_ip = first_packet.src_ip
            client_port = first_packet.src_port
            server_ip = first_packet.dst_ip
            server_port = first_packet.dst_port
            syn_timestamp = first_packet.timestamp or 0.0
            syn_options = ""  # No SYN options available
            client_isn = 0
            server_isn = 0
            ipid_first = first_packet.ip_id

        # Extract TCP timestamp from SYN packet (if available)
        if syn_packet:
            tcp_timestamp_tsval = syn_packet.tcp_timestamp_tsval
            tcp_timestamp_tsecr = syn_packet.tcp_timestamp_tsecr
        else:
            # No SYN packet - try to get timestamp from first packet
            tcp_timestamp_tsval = packets[0].tcp_timestamp_tsval if packets else ""
            tcp_timestamp_tsecr = packets[0].tcp_timestamp_tsecr if packets else ""

        # Check if header-only (all packets have zero payload)
        is_header_only = all(p.length == 0 for p in packets)

        # Compute payload hashes (client and server separately)
        client_payload_md5, server_payload_md5 = self._compute_payload_hashes(
            packets, client_ip, server_ip
        )

        # Compute length signature (with direction)
        length_signature = self._compute_length_signature(packets, client_ip, server_ip)

        # Compute time range (earliest and latest packet timestamps)
        timestamps = [p.timestamp for p in packets if p.timestamp is not None]
        if timestamps:
            first_packet_time = min(timestamps)
            last_packet_time = max(timestamps)
        else:
            # Fallback: use syn_timestamp if no timestamps available
            first_packet_time = syn_timestamp
            last_packet_time = syn_timestamp

        packet_count = len(packets)

        # Collect all unique IPID values from all packets
        ipid_set = {p.ip_id for p in packets if p.ip_id is not None and p.ip_id != 0}
        # If no valid IPIDs found, use the first IPID (even if 0)
        if not ipid_set and ipid_first is not None:
            ipid_set = {ipid_first}

        return TcpConnection(
            stream_id=stream_id,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            syn_timestamp=syn_timestamp,
            syn_options=syn_options,
            client_isn=client_isn,
            server_isn=server_isn,
            tcp_timestamp_tsval=tcp_timestamp_tsval,
            tcp_timestamp_tsecr=tcp_timestamp_tsecr,
            client_payload_md5=client_payload_md5,
            server_payload_md5=server_payload_md5,
            length_signature=length_signature,
            is_header_only=is_header_only,
            ipid_first=ipid_first,
            ipid_set=ipid_set,
            first_packet_time=first_packet_time,
            last_packet_time=last_packet_time,
            packet_count=packet_count,
        )

    def _compute_payload_hashes(
        self, packets: list[TcpPacket], client_ip: str, server_ip: str
    ) -> tuple[str, str]:
        """
        Compute MD5 hashes of first payload packets (client and server).

        Args:
            packets: List of packets
            client_ip: Client IP address
            server_ip: Server IP address

        Returns:
            Tuple of (client_payload_md5, server_payload_md5)
        """
        client_payload_md5 = ""
        server_payload_md5 = ""

        for packet in packets:
            # Skip packets without payload
            if packet.length == 0 or not packet.payload_data:
                continue

            # Determine direction
            is_client = packet.src_ip == client_ip

            # Compute MD5 of first 256 bytes (512 hex chars)
            if is_client and not client_payload_md5:
                client_payload_md5 = self._md5_hex(packet.payload_data[:512])
            elif not is_client and not server_payload_md5:
                server_payload_md5 = self._md5_hex(packet.payload_data[:512])

            # Stop if we have both
            if client_payload_md5 and server_payload_md5:
                break

        return client_payload_md5, server_payload_md5

    def _md5_hex(self, hex_data: str) -> str:
        """
        Compute MD5 hash of hex string data.

        Args:
            hex_data: Hex string (e.g., "48656c6c6f")

        Returns:
            MD5 hash string (empty if invalid)
        """
        if not hex_data or hex_data == "-":
            return ""

        try:
            # Convert hex string to bytes
            data_bytes = bytes.fromhex(hex_data.replace(":", ""))
            # Compute MD5
            return hashlib.md5(data_bytes).hexdigest()
        except (ValueError, TypeError):
            return ""

    def _compute_length_signature(
        self, packets: list[TcpPacket], client_ip: str, server_ip: str, max_packets: int = 20
    ) -> str:
        """
        Compute packet length signature with direction.

        Args:
            packets: List of packets
            client_ip: Client IP address
            server_ip: Server IP address
            max_packets: Maximum number of packets to include

        Returns:
            Length signature string (e.g., "C:100 S:200 C:50...")
        """
        signature_parts = []

        for packet in packets[:max_packets]:
            # Only include packets with payload
            if packet.length > 0:
                direction = "C" if packet.src_ip == client_ip else "S"
                signature_parts.append(f"{direction}:{packet.length}")

        return " ".join(signature_parts)
