"""TLS-based TCP connection matching using Client Hello fields."""

from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from capmaster.core.connection.tls_extractor import TlsClientHelloExtractor, TlsClientHelloInfo
from capmaster.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class TlsConnectionPair:
    """
    A matched pair of TCP connections using TLS Client Hello information.
    """

    stream_id_1: int
    """TCP stream ID from first PCAP"""

    stream_id_2: int
    """TCP stream ID from second PCAP"""

    random: str
    """TLS Client Hello random field (used for matching)"""

    session_id: str
    """TLS Client Hello session ID field (used for matching)"""

    src_ip_1: str = ""
    """First PCAP source IP (for 5-tuple matching)"""

    src_port_1: int = 0
    """First PCAP source port (for 5-tuple matching)"""

    dst_ip_1: str = ""
    """First PCAP destination IP (for 5-tuple matching)"""

    dst_port_1: int = 0
    """First PCAP destination port (for 5-tuple matching)"""

    src_ip_2: str = ""
    """Second PCAP source IP (for 5-tuple matching)"""

    src_port_2: int = 0
    """Second PCAP source port (for 5-tuple matching)"""

    dst_ip_2: str = ""
    """Second PCAP destination IP (for 5-tuple matching)"""

    dst_port_2: int = 0
    """Second PCAP destination port (for 5-tuple matching)"""

    match_method: str = "TLS_CLIENT_HELLO"
    """Matching method (always TLS_CLIENT_HELLO)"""

    def __str__(self) -> str:
        """String representation."""
        return (
            f"TlsMatch(Stream1={self.stream_id_1}, "
            f"Stream2={self.stream_id_2}, "
            f"random={self.random[:16]}..., session_id={self.session_id[:16]}...)"
        )

    def get_5tuple_1(self) -> tuple[str, int, str, int]:
        """
        Get first PCAP 5-tuple for connection matching.

        Returns:
            Tuple of (src_ip, src_port, dst_ip, dst_port)
        """
        return (self.src_ip_1, self.src_port_1, self.dst_ip_1, self.dst_port_1)

    def get_5tuple_2(self) -> tuple[str, int, str, int]:
        """
        Get second PCAP 5-tuple for connection matching.

        Returns:
            Tuple of (src_ip, src_port, dst_ip, dst_port)
        """
        return (self.src_ip_2, self.src_port_2, self.dst_ip_2, self.dst_port_2)


class TlsMatcher:
    """
    Match TCP connections using TLS Client Hello information.
    
    Matching Logic:
    1. Extract TLS Client Hello random and session_id from both PCAPs
    2. Match connections where both random AND session_id are identical
    3. Random field (32 bytes) provides strong uniqueness
    4. Session ID provides additional validation (may be empty for new sessions)
    
    This provides high-accuracy matching when TLS handshakes are present.
    """
    
    def __init__(self) -> None:
        """Initialize the TLS matcher."""
        self.extractor = TlsClientHelloExtractor()
    
    def detect_tls_client_hello(self, pcap_file: Path) -> bool:
        """
        Detect if a PCAP file contains TLS Client Hello packets.
        
        Args:
            pcap_file: Path to the PCAP file
        
        Returns:
            True if TLS Client Hello is present, False otherwise
        """
        try:
            # Try to extract at least one TLS Client Hello packet
            for _ in self.extractor.extract(pcap_file):
                return True
            return False
        except Exception:
            return False
    
    def match(
        self,
        pcap1: Path,
        pcap2: Path,
    ) -> list[TlsConnectionPair]:
        """
        Match TCP connections between two PCAPs using TLS Client Hello fields.
        
        Args:
            pcap1: Path to first PCAP file
            pcap2: Path to second PCAP file
        
        Returns:
            List of matched connection pairs
        """
        logger.info("Extracting TLS Client Hello from first PCAP...")
        hello_map_1 = self._extract_client_hellos(pcap1)
        logger.info(f"Found {len(hello_map_1)} TLS Client Hello packets in first PCAP")
        
        logger.info("Extracting TLS Client Hello from second PCAP...")
        hello_map_2 = self._extract_client_hellos(pcap2)
        logger.info(f"Found {len(hello_map_2)} TLS Client Hello packets in second PCAP")
        
        logger.info("Matching connections...")
        matches = self._match_connections(hello_map_1, hello_map_2)
        logger.info(f"Found {len(matches)} TLS-based matches")
        
        return matches
    
    def _extract_client_hellos(self, pcap_file: Path) -> dict[int, TlsClientHelloInfo]:
        """
        Extract TLS Client Hello information from a PCAP file.
        
        Args:
            pcap_file: Path to the PCAP file
        
        Returns:
            Dict mapping stream_id -> TlsClientHelloInfo
        """
        hellos: dict[int, TlsClientHelloInfo] = {}
        
        for info in self.extractor.extract(pcap_file):
            # Store the first Client Hello for each stream
            # (in case of retransmissions, we only need one)
            if info.stream_id not in hellos:
                hellos[info.stream_id] = info
        
        return hellos
    
    def _match_connections(
        self,
        hello_map_1: dict[int, TlsClientHelloInfo],
        hello_map_2: dict[int, TlsClientHelloInfo],
    ) -> list[TlsConnectionPair]:
        """
        Match connections by comparing TLS Client Hello fields.
        
        Matching logic:
        - Both random AND session_id must match
        - Random field is required (32 bytes, highly unique)
        - Session ID may be empty (for new sessions) but must still match
        
        Args:
            hello_map_1: stream_id -> TlsClientHelloInfo from first PCAP
            hello_map_2: stream_id -> TlsClientHelloInfo from second PCAP
        
        Returns:
            List of matched connection pairs
        """
        matches: list[TlsConnectionPair] = []

        # Build reverse index: (random, session_id) -> (stream_id, TlsClientHelloInfo)
        hello_key_to_streams: dict[tuple[str, str], list[tuple[int, TlsClientHelloInfo]]] = defaultdict(list)
        for stream_id, info in hello_map_2.items():
            key = (info.random, info.session_id)
            hello_key_to_streams[key].append((stream_id, info))

        # Match Client Hellos from PCAP 1 with PCAP 2
        for stream_id_1, info_1 in hello_map_1.items():
            key = (info_1.random, info_1.session_id)

            # Look up matching streams in PCAP 2
            matching_stream_infos = hello_key_to_streams.get(key, [])

            for stream_id_2, info_2 in matching_stream_infos:
                match = TlsConnectionPair(
                    stream_id_1=stream_id_1,
                    stream_id_2=stream_id_2,
                    random=info_1.random,
                    session_id=info_1.session_id,
                    src_ip_1=info_1.src_ip,
                    src_port_1=info_1.src_port,
                    dst_ip_1=info_1.dst_ip,
                    dst_port_1=info_1.dst_port,
                    src_ip_2=info_2.src_ip,
                    src_port_2=info_2.src_port,
                    dst_ip_2=info_2.dst_ip,
                    dst_port_2=info_2.dst_port,
                )
                matches.append(match)

        return matches

