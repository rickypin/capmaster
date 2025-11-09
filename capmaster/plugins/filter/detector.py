"""
TCP one-way connection detector.

This module implements the detection logic for identifying one-way TCP connections
that are likely caused by packet capture loss.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from capmaster.utils.logger import get_logger

logger = get_logger(__name__)


# Maximum value for 32-bit sequence/ack numbers
MAX_SEQ_ACK = 2**32


@dataclass
class TcpPacketInfo:
    """Information about a TCP packet needed for one-way detection."""

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

    ack: int
    """ACK number"""

    tcp_len: int
    """TCP payload length"""


@dataclass
class DirectionStats:
    """Statistics for one direction of a TCP stream."""

    packet_count: int = 0
    """Number of packets in this direction"""

    first_ack: int = 0
    """First ACK number seen"""

    last_ack: int = 0
    """Last ACK number seen"""

    has_pure_ack: bool = False
    """Whether this direction has pure ACK packets (tcp.len==0)"""

    prev_ack: int = 0
    """Previous ACK number (for pure ACK detection)"""


@dataclass
class StreamAnalysis:
    """Analysis result for a TCP stream."""

    stream_id: int
    """TCP stream ID"""

    is_one_way: bool
    """Whether this is a one-way stream"""

    active_direction: str
    """Active direction (e.g., "192.168.1.1:1234->10.0.0.1:80")"""

    ack_delta: int
    """ACK increment in the active direction"""

    has_pure_ack: bool
    """Whether the active direction has pure ACK packets"""


class OneWayDetector:
    """
    Detector for one-way TCP connections.

    This class analyzes TCP packets to identify one-way connections that are
    likely caused by packet capture loss. A connection is considered one-way if:
    1. Only one direction has packets
    2. The ACK increment exceeds the threshold
    3. The direction has pure ACK packets (tcp.len==0)
    """

    def __init__(self, ack_threshold: int = 20):
        """
        Initialize the detector.

        Args:
            ack_threshold: Minimum ACK increment to consider as one-way (default: 20)
        """
        self.ack_threshold = ack_threshold
        self._streams: dict[int, dict[str, DirectionStats]] = {}
        self._stream_first_direction: dict[int, str] = {}

    def add_packet(self, packet: TcpPacketInfo) -> None:
        """
        Add a packet to the detector.

        Args:
            packet: TCP packet information
        """
        # Build direction key
        direction = f"{packet.src_ip}:{packet.src_port}->{packet.dst_ip}:{packet.dst_port}"

        # Initialize stream if needed
        if packet.stream_id not in self._streams:
            self._streams[packet.stream_id] = {}
            self._stream_first_direction[packet.stream_id] = direction

        # Initialize direction stats if needed
        if direction not in self._streams[packet.stream_id]:
            self._streams[packet.stream_id][direction] = DirectionStats()

        stats = self._streams[packet.stream_id][direction]
        stats.packet_count += 1

        # Record ACK information
        if packet.ack > 0:
            if stats.first_ack == 0:
                stats.first_ack = packet.ack
            stats.last_ack = packet.ack

            # Check for pure ACK (tcp.len == 0)
            if packet.tcp_len == 0:
                if stats.prev_ack > 0 and packet.ack > stats.prev_ack:
                    stats.has_pure_ack = True

            stats.prev_ack = packet.ack

    def analyze(self) -> Iterator[StreamAnalysis]:
        """
        Analyze collected packets and yield one-way streams.

        Yields:
            StreamAnalysis objects for one-way streams
        """
        for stream_id, directions in self._streams.items():
            # Get forward and reverse directions
            first_dir = self._stream_first_direction[stream_id]

            # Build reverse direction
            reverse_dir = self._get_reverse_direction(first_dir)

            # Get stats for both directions
            forward_stats = directions.get(first_dir, DirectionStats())
            reverse_stats = directions.get(reverse_dir, DirectionStats())

            # Check if one-way
            if forward_stats.packet_count == 0 or reverse_stats.packet_count == 0:
                # Determine active direction
                if forward_stats.packet_count > 0:
                    active_dir = first_dir
                    active_stats = forward_stats
                else:
                    active_dir = reverse_dir
                    active_stats = reverse_stats

                # Skip if no ACK information
                if active_stats.first_ack == 0 or active_stats.last_ack == 0:
                    continue

                # Calculate ACK delta (handle wraparound)
                ack_delta = self._calculate_ack_delta(
                    active_stats.first_ack,
                    active_stats.last_ack,
                )

                # Check threshold and pure ACK
                if ack_delta > self.ack_threshold and active_stats.has_pure_ack:
                    yield StreamAnalysis(
                        stream_id=stream_id,
                        is_one_way=True,
                        active_direction=active_dir,
                        ack_delta=ack_delta,
                        has_pure_ack=active_stats.has_pure_ack,
                    )

    def _get_reverse_direction(self, direction: str) -> str:
        """
        Get the reverse direction of a connection.

        Args:
            direction: Direction string (e.g., "192.168.1.1:1234->10.0.0.1:80")

        Returns:
            Reverse direction string (e.g., "10.0.0.1:80->192.168.1.1:1234")
        """
        parts = direction.split("->")
        if len(parts) != 2:
            return direction
        return f"{parts[1]}->{parts[0]}"

    def _calculate_ack_delta(self, first_ack: int, last_ack: int) -> int:
        """
        Calculate ACK increment, handling 32-bit wraparound.

        Args:
            first_ack: First ACK number
            last_ack: Last ACK number

        Returns:
            ACK increment
        """
        if last_ack >= first_ack:
            return last_ack - first_ack
        else:
            # Handle wraparound
            return MAX_SEQ_ACK + last_ack - first_ack
