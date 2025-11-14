"""F5-based TCP connection matching."""

from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from capmaster.core.connection.f5_extractor import F5EthTrailerExtractor, F5TrailerInfo
from capmaster.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class F5ConnectionPair:
    """
    A matched pair of TCP connections using F5 trailer information.
    """

    snat_stream_id: int
    """TCP stream ID from SNAT side PCAP"""

    vip_stream_id: int
    """TCP stream ID from VIP side PCAP"""

    client_ip: str
    """Client IP address"""

    client_port: int
    """Client port"""

    snat_src_ip: str = ""
    """SNAT side source IP (for 5-tuple matching)"""

    snat_src_port: int = 0
    """SNAT side source port (for 5-tuple matching)"""

    snat_dst_ip: str = ""
    """SNAT side destination IP (for 5-tuple matching)"""

    snat_dst_port: int = 0
    """SNAT side destination port (for 5-tuple matching)"""

    vip_src_ip: str = ""
    """VIP side source IP (for 5-tuple matching)"""

    vip_src_port: int = 0
    """VIP side source port (for 5-tuple matching)"""

    vip_dst_ip: str = ""
    """VIP side destination IP (for 5-tuple matching)"""

    vip_dst_port: int = 0
    """VIP side destination port (for 5-tuple matching)"""

    match_method: str = "F5_TRAILER"
    """Matching method (always F5_TRAILER)"""

    def __str__(self) -> str:
        """String representation."""
        return (
            f"F5Match(SNAT_Stream={self.snat_stream_id}, "
            f"VIP_Stream={self.vip_stream_id}, "
            f"Client={self.client_ip}:{self.client_port})"
        )

    def get_snat_5tuple(self) -> tuple[str, int, str, int]:
        """
        Get SNAT side 5-tuple for connection matching.

        Returns:
            Tuple of (src_ip, src_port, dst_ip, dst_port)
        """
        return (self.snat_src_ip, self.snat_src_port, self.snat_dst_ip, self.snat_dst_port)

    def get_vip_5tuple(self) -> tuple[str, int, str, int]:
        """
        Get VIP side 5-tuple for connection matching.

        Returns:
            Tuple of (src_ip, src_port, dst_ip, dst_port)
        """
        return (self.vip_src_ip, self.vip_src_port, self.vip_dst_ip, self.vip_dst_port)


class F5Matcher:
    """
    Match TCP connections using F5 Ethernet Trailer information.
    
    Matching Logic:
    1. SNAT side: Extract peer information (VIP side client) from f5ethtrailer.peeraddr[0]:peerport[0]
    2. VIP side: Extract actual client information from ip.src:tcp.srcport
    3. Match: SNAT peer info == VIP client info
    
    This provides 100% accurate matching when F5 trailers are present.
    """
    
    def __init__(self) -> None:
        """Initialize the F5 matcher."""
        self.extractor = F5EthTrailerExtractor()
    
    def detect_f5_trailer(self, pcap_file: Path) -> bool:
        """
        Detect if a PCAP file contains F5 Ethernet Trailer.
        
        Args:
            pcap_file: Path to the PCAP file
        
        Returns:
            True if F5 trailer is present, False otherwise
        """
        try:
            # Try to extract at least one F5 trailer packet
            for _ in self.extractor.extract(pcap_file):
                return True
            return False
        except Exception:
            return False
    
    def match(
        self,
        snat_pcap: Path,
        vip_pcap: Path,
    ) -> list[F5ConnectionPair]:
        """
        Match TCP connections between SNAT and VIP side PCAPs using F5 trailers.
        
        Args:
            snat_pcap: Path to SNAT side PCAP file (F5 -> Server)
            vip_pcap: Path to VIP side PCAP file (Client -> F5)
        
        Returns:
            List of matched connection pairs
        """
        logger.info("Extracting F5 trailer information from SNAT side...")
        snat_peers = self._extract_snat_peers(snat_pcap)
        logger.info(f"Found {len(snat_peers)} SNAT streams with F5 trailer")
        
        logger.info("Extracting client information from VIP side...")
        vip_clients = self._extract_vip_clients(vip_pcap)
        logger.info(f"Found {len(vip_clients)} VIP streams with F5 trailer")
        
        logger.info("Matching connections...")
        matches = self._match_connections(snat_peers, vip_clients)
        logger.info(f"Found {len(matches)} F5-based matches")
        
        return matches
    
    def _extract_snat_peers(self, pcap_file: Path) -> dict[int, tuple[str, int, str, int, str, int]]:
        """
        Extract peer information from SNAT side PCAP.

        For SNAT side (F5 -> Server):
        - f5ethtrailer.peeraddr[0] = VIP side client IP
        - f5ethtrailer.peerport[0] = VIP side client port

        Args:
            pcap_file: Path to SNAT side PCAP file

        Returns:
            Dict mapping stream_id -> (peer_client_ip, peer_client_port, src_ip, src_port, dst_ip, dst_port)
        """
        peers: dict[int, tuple[str, int, str, int, str, int]] = {}

        for info in self.extractor.extract(pcap_file):
            # Only process SYN packets for connection establishment
            if not self._is_syn_packet(info.flags):
                continue

            # Extract peer client info (first IP:Port in the peer lists)
            if info.peer_addrs and info.peer_ports:
                peer_client_ip = info.peer_addrs[0]
                peer_client_port = info.peer_ports[0]

                # Store the mapping with 5-tuple info
                peers[info.stream_id] = (
                    peer_client_ip,
                    peer_client_port,
                    info.src_ip,
                    info.src_port,
                    info.dst_ip,
                    info.dst_port,
                )

        return peers

    def _extract_vip_clients(self, pcap_file: Path) -> dict[int, tuple[str, int, str, int, str, int]]:
        """
        Extract client information from VIP side PCAP.

        For VIP side (Client -> F5):
        - ip.src = actual client IP
        - tcp.srcport = actual client port

        Args:
            pcap_file: Path to VIP side PCAP file

        Returns:
            Dict mapping stream_id -> (client_ip, client_port, src_ip, src_port, dst_ip, dst_port)
        """
        clients: dict[int, tuple[str, int, str, int, str, int]] = {}

        for info in self.extractor.extract(pcap_file):
            # Only process SYN packets for connection establishment
            if not self._is_syn_packet(info.flags):
                continue

            # Extract actual client info from packet headers
            client_ip = info.src_ip
            client_port = info.src_port

            # Store the mapping with 5-tuple info
            clients[info.stream_id] = (
                client_ip,
                client_port,
                info.src_ip,
                info.src_port,
                info.dst_ip,
                info.dst_port,
            )

        return clients

    def _match_connections(
        self,
        snat_peers: dict[int, tuple[str, int, str, int, str, int]],
        vip_clients: dict[int, tuple[str, int, str, int, str, int]],
    ) -> list[F5ConnectionPair]:
        """
        Match connections by comparing peer info with client info.

        Matching logic:
        - SNAT peer info (from F5 trailer) == VIP client info (from packet header)

        Args:
            snat_peers: SNAT stream_id -> (peer_client_ip, peer_client_port, src_ip, src_port, dst_ip, dst_port)
            vip_clients: VIP stream_id -> (client_ip, client_port, src_ip, src_port, dst_ip, dst_port)

        Returns:
            List of matched connection pairs
        """
        matches: list[F5ConnectionPair] = []

        # Build reverse index: (client_ip, client_port) -> (vip_stream_id, src_ip, src_port, dst_ip, dst_port)
        client_to_vip_stream: dict[tuple[str, int], list[tuple[int, str, int, str, int]]] = defaultdict(list)
        for vip_stream, (client_ip, client_port, src_ip, src_port, dst_ip, dst_port) in vip_clients.items():
            client_to_vip_stream[(client_ip, client_port)].append((vip_stream, src_ip, src_port, dst_ip, dst_port))

        # Match SNAT peers with VIP clients
        for snat_stream, (peer_ip, peer_port, snat_src_ip, snat_src_port, snat_dst_ip, snat_dst_port) in snat_peers.items():
            # Look up matching VIP streams
            vip_stream_infos = client_to_vip_stream.get((peer_ip, peer_port), [])

            for vip_stream, vip_src_ip, vip_src_port, vip_dst_ip, vip_dst_port in vip_stream_infos:
                match = F5ConnectionPair(
                    snat_stream_id=snat_stream,
                    vip_stream_id=vip_stream,
                    client_ip=peer_ip,
                    client_port=peer_port,
                    snat_src_ip=snat_src_ip,
                    snat_src_port=snat_src_port,
                    snat_dst_ip=snat_dst_ip,
                    snat_dst_port=snat_dst_port,
                    vip_src_ip=vip_src_ip,
                    vip_src_port=vip_src_port,
                    vip_dst_ip=vip_dst_ip,
                    vip_dst_port=vip_dst_port,
                )
                matches.append(match)

        return matches

    @staticmethod
    def _is_syn_packet(flags: str) -> bool:
        """
        Check if TCP flags indicate a SYN packet (SYN=1, ACK=0).

        Args:
            flags: TCP flags as hex string (e.g., "0x0002")

        Returns:
            True if SYN packet, False otherwise
        """
        try:
            flags_int = int(flags, 16)
            syn = (flags_int & 0x02) != 0  # SYN flag
            ack = (flags_int & 0x10) != 0  # ACK flag
            return syn and not ack
        except (ValueError, TypeError):
            return False

