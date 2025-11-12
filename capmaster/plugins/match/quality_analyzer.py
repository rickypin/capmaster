"""Network quality analyzer for TCP connections."""

from __future__ import annotations

import csv
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from capmaster.core.tshark_wrapper import TsharkWrapper
from capmaster.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class QualityMetrics:
    """Network quality metrics for a service."""

    server_ip: str
    """Server IP address"""

    server_port: int
    """Server port number"""

    # Client-to-Server metrics
    client_total_packets: int = 0
    """Total packets from client to server"""

    client_retransmissions: int = 0
    """Retransmitted packets from client"""

    client_duplicate_acks: int = 0
    """Duplicate ACKs from client"""

    client_lost_segments: int = 0
    """Lost segments detected on client side"""

    # Server-to-Client metrics
    server_total_packets: int = 0
    """Total packets from server to client"""

    server_retransmissions: int = 0
    """Retransmitted packets from server"""

    server_duplicate_acks: int = 0
    """Duplicate ACKs from server"""

    server_lost_segments: int = 0
    """Lost segments detected on server side"""

    @property
    def client_retransmission_rate(self) -> float:
        """Calculate client-to-server retransmission rate."""
        if self.client_total_packets == 0:
            return 0.0
        return (self.client_retransmissions / self.client_total_packets) * 100

    @property
    def client_duplicate_ack_rate(self) -> float:
        """Calculate client-to-server duplicate ACK rate."""
        if self.client_total_packets == 0:
            return 0.0
        return (self.client_duplicate_acks / self.client_total_packets) * 100

    @property
    def client_loss_rate(self) -> float:
        """Calculate client-to-server packet loss rate."""
        if self.client_total_packets == 0:
            return 0.0
        return (self.client_lost_segments / self.client_total_packets) * 100

    @property
    def server_retransmission_rate(self) -> float:
        """Calculate server-to-client retransmission rate."""
        if self.server_total_packets == 0:
            return 0.0
        return (self.server_retransmissions / self.server_total_packets) * 100

    @property
    def server_duplicate_ack_rate(self) -> float:
        """Calculate server-to-client duplicate ACK rate."""
        if self.server_total_packets == 0:
            return 0.0
        return (self.server_duplicate_acks / self.server_total_packets) * 100

    @property
    def server_loss_rate(self) -> float:
        """Calculate server-to-client packet loss rate."""
        if self.server_total_packets == 0:
            return 0.0
        return (self.server_lost_segments / self.server_total_packets) * 100


@dataclass
class ConnectionPair:
    """Represents a matched connection pair."""

    pair_id: int
    """Pair ID number"""

    stream_a: int
    """Stream ID in file A"""

    connection_a: str
    """Connection string in file A (e.g., "10.93.137.244:43803 <-> 10.93.75.130:8443")"""

    stream_b: int
    """Stream ID in file B"""

    connection_b: str
    """Connection string in file B (e.g., "172.68.164.118:51891 <-> 10.93.136.244:443")"""

    confidence: float
    """Matching confidence score"""


@dataclass
class ConnectionPairMetrics:
    """Network quality metrics for a matched connection pair."""

    pair: ConnectionPair
    """The connection pair"""

    metrics_a: QualityMetrics
    """Quality metrics for connection in file A"""

    metrics_b: QualityMetrics
    """Quality metrics for connection in file B"""


@dataclass
class TcpAnalysisPacket:
    """TCP packet with analysis information."""

    stream_id: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    has_retransmission: bool
    has_duplicate_ack: bool
    has_lost_segment: bool


class QualityAnalyzer:
    """Analyze network quality metrics from PCAP files."""

    def __init__(self, tshark: TsharkWrapper | None = None):
        """
        Initialize quality analyzer.

        Args:
            tshark: TsharkWrapper instance (creates new one if None)
        """
        self.tshark = tshark or TsharkWrapper()

    def extract_tcp_analysis(self, pcap_file: Path) -> Iterator[TcpAnalysisPacket]:
        """
        Extract TCP analysis information from PCAP file.

        Args:
            pcap_file: Path to PCAP file

        Yields:
            TcpAnalysisPacket objects
        """
        # Build tshark command to extract TCP analysis fields
        args = [
            "-Y", "tcp",  # Filter for TCP packets
            "-T", "fields",
            "-E", "separator=\t",
            "-e", "tcp.stream",
            "-e", "ip.src",
            "-e", "tcp.srcport",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
            "-e", "tcp.analysis.retransmission",
            "-e", "tcp.analysis.duplicate_ack",
            "-e", "tcp.analysis.lost_segment",
        ]

        # Execute tshark
        result = self.tshark.execute(args=args, input_file=pcap_file)

        if result.returncode != 0:
            logger.error(f"tshark failed with return code {result.returncode}")
            return

        # Parse output
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue

            parts = line.split('\t')
            if len(parts) < 8:
                continue

            try:
                stream_id = int(parts[0]) if parts[0] else 0
                src_ip = parts[1]
                src_port = int(parts[2]) if parts[2] else 0
                dst_ip = parts[3]
                dst_port = int(parts[4]) if parts[4] else 0
                has_retransmission = bool(parts[5])
                has_duplicate_ack = bool(parts[6])
                has_lost_segment = bool(parts[7])

                yield TcpAnalysisPacket(
                    stream_id=stream_id,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    has_retransmission=has_retransmission,
                    has_duplicate_ack=has_duplicate_ack,
                    has_lost_segment=has_lost_segment,
                )
            except (ValueError, IndexError) as e:
                logger.debug(f"Failed to parse line: {line}, error: {e}")
                continue

    def analyze_service_quality(
        self,
        pcap_file1: Path,
        pcap_file2: Path,
        services: list[tuple[str, int]],
    ) -> dict[tuple[str, int], tuple[QualityMetrics, QualityMetrics]]:
        """
        Analyze network quality for specified services.

        Args:
            pcap_file1: Path to first PCAP file
            pcap_file2: Path to second PCAP file
            services: List of (server_ip, server_port) tuples

        Returns:
            Dictionary mapping (server_ip, server_port) to (metrics1, metrics2)
        """
        results: dict[tuple[str, int], tuple[QualityMetrics, QualityMetrics]] = {}

        # Convert services list to set for faster lookup
        service_set = set(services)

        # Analyze both PCAP files
        metrics1 = self._analyze_pcap(pcap_file1, service_set)
        metrics2 = self._analyze_pcap(pcap_file2, service_set)

        # Combine results
        all_services = set(metrics1.keys()) | set(metrics2.keys())
        for service in all_services:
            m1 = metrics1.get(service, QualityMetrics(server_ip=service[0], server_port=service[1]))
            m2 = metrics2.get(service, QualityMetrics(server_ip=service[0], server_port=service[1]))
            results[service] = (m1, m2)

        return results

    def analyze_connection_pairs(
        self,
        pcap_file1: Path,
        pcap_file2: Path,
        connection_pairs: list[ConnectionPair],
    ) -> list[ConnectionPairMetrics]:
        """
        Analyze network quality for matched connection pairs.

        Args:
            pcap_file1: Path to first PCAP file
            pcap_file2: Path to second PCAP file
            connection_pairs: List of ConnectionPair objects

        Returns:
            List of ConnectionPairMetrics with quality metrics for each pair
        """
        results: list[ConnectionPairMetrics] = []

        # Analyze both PCAP files and get per-stream metrics
        stream_metrics_a = self._analyze_pcap_by_stream(pcap_file1)
        stream_metrics_b = self._analyze_pcap_by_stream(pcap_file2)

        # Match metrics for each connection pair
        for pair in connection_pairs:
            # Get metrics for stream A (default to empty if not found)
            metrics_a = stream_metrics_a.get(
                pair.stream_a,
                QualityMetrics(server_ip="", server_port=0)
            )

            # Get metrics for stream B (default to empty if not found)
            metrics_b = stream_metrics_b.get(
                pair.stream_b,
                QualityMetrics(server_ip="", server_port=0)
            )

            pair_metrics = ConnectionPairMetrics(
                pair=pair,
                metrics_a=metrics_a,
                metrics_b=metrics_b,
            )
            results.append(pair_metrics)

        return results

    def _analyze_pcap_by_stream(
        self,
        pcap_file: Path,
    ) -> dict[int, QualityMetrics]:
        """
        Analyze PCAP file and return metrics grouped by stream ID.

        Args:
            pcap_file: Path to PCAP file

        Returns:
            Dictionary mapping stream_id to QualityMetrics
        """
        metrics: dict[int, QualityMetrics] = {}

        logger.info(f"Analyzing PCAP file by stream: {pcap_file.name}")

        # Extract TCP analysis data
        for packet in self.extract_tcp_analysis(pcap_file):
            stream_id = packet.stream_id

            # Initialize metrics for this stream if not exists
            if stream_id not in metrics:
                # Use destination as server (this is a simplification)
                metrics[stream_id] = QualityMetrics(
                    server_ip=packet.dst_ip,
                    server_port=packet.dst_port,
                )

            metric = metrics[stream_id]

            # Determine direction based on server IP/port
            # Packets going TO the server IP:port are client->server
            is_client_to_server = (
                packet.dst_ip == metric.server_ip and
                packet.dst_port == metric.server_port
            )

            # Update metrics based on direction
            if is_client_to_server:
                metric.client_total_packets += 1
                if packet.has_retransmission:
                    metric.client_retransmissions += 1
                if packet.has_duplicate_ack:
                    metric.client_duplicate_acks += 1
                if packet.has_lost_segment:
                    metric.client_lost_segments += 1
            else:
                metric.server_total_packets += 1
                if packet.has_retransmission:
                    metric.server_retransmissions += 1
                if packet.has_duplicate_ack:
                    metric.server_duplicate_acks += 1
                if packet.has_lost_segment:
                    metric.server_lost_segments += 1

        return metrics

    def _analyze_pcap(
        self,
        pcap_file: Path,
        services: set[tuple[str, int]],
    ) -> dict[tuple[str, int], QualityMetrics]:
        """
        Analyze a single PCAP file for service quality metrics.

        Args:
            pcap_file: Path to PCAP file
            services: Set of (server_ip, server_port) tuples to analyze

        Returns:
            Dictionary mapping (server_ip, server_port) to QualityMetrics
        """
        logger.info(f"Analyzing {pcap_file.name}...")

        # Initialize metrics for each service
        metrics: dict[tuple[str, int], QualityMetrics] = {}
        for server_ip, server_port in services:
            metrics[(server_ip, server_port)] = QualityMetrics(
                server_ip=server_ip,
                server_port=server_port,
            )

        # Extract and process packets
        for packet in self.extract_tcp_analysis(pcap_file):
            # Check if this packet belongs to any of our services
            # Try both directions (src and dst)
            service_key = None

            if (packet.dst_ip, packet.dst_port) in services:
                # Packet going TO server (client -> server)
                service_key = (packet.dst_ip, packet.dst_port)
                is_client_to_server = True
            elif (packet.src_ip, packet.src_port) in services:
                # Packet coming FROM server (server -> client)
                service_key = (packet.src_ip, packet.src_port)
                is_client_to_server = False
            else:
                # Not a service we're tracking
                continue

            metric = metrics[service_key]

            # Update metrics based on direction
            if is_client_to_server:
                metric.client_total_packets += 1
                if packet.has_retransmission:
                    metric.client_retransmissions += 1
                if packet.has_duplicate_ack:
                    metric.client_duplicate_acks += 1
                if packet.has_lost_segment:
                    metric.client_lost_segments += 1
            else:
                metric.server_total_packets += 1
                if packet.has_retransmission:
                    metric.server_retransmissions += 1
                if packet.has_duplicate_ack:
                    metric.server_duplicate_acks += 1
                if packet.has_lost_segment:
                    metric.server_lost_segments += 1

        return metrics


def parse_matched_connections(matched_file: Path) -> list[ConnectionPair]:
    """
    Parse matched_connections.txt file to extract connection pairs.
    Supports both old multi-line format and new table format.

    Args:
        matched_file: Path to matched_connections.txt file

    Returns:
        List of ConnectionPair objects
    """
    pairs = []

    try:
        with open(matched_file, 'r') as f:
            lines = f.readlines()

        # Try to detect format by looking for table header
        is_table_format = False
        for line in lines:
            if 'Stream A' in line and 'Stream B' in line and 'Client A' in line:
                is_table_format = True
                break

        if is_table_format:
            # Parse new table format
            # Table row format: No. Stream_A Client_A Server_A Stream_B Client_B Server_B Conf Evidence
            for line in lines:
                line = line.strip()
                # Skip headers, separators, and empty lines
                if not line or line.startswith('=') or line.startswith('-') or \
                   line.startswith('TCP Connection') or line.startswith('Statistics') or \
                   line.startswith('Matched Connections') or line.startswith('Total') or \
                   line.startswith('No.') or 'Stream A' in line:
                    continue

                # Parse table row
                parts = line.split()
                if len(parts) >= 8:
                    try:
                        pair_id = int(parts[0])
                        stream_a = int(parts[1])
                        client_a = parts[2]
                        server_a = parts[3]
                        stream_b = int(parts[4])
                        client_b = parts[5]
                        server_b = parts[6]
                        confidence = float(parts[7])

                        # Reconstruct connection strings
                        connection_a = f"{client_a} <-> {server_a}"
                        connection_b = f"{client_b} <-> {server_b}"

                        pair = ConnectionPair(
                            pair_id=pair_id,
                            stream_a=stream_a,
                            connection_a=connection_a,
                            stream_b=stream_b,
                            connection_b=connection_b,
                            confidence=confidence,
                        )
                        pairs.append(pair)
                    except (ValueError, IndexError):
                        # Skip malformed lines
                        continue
        else:
            # Parse old multi-line format
            # Pattern to match connection pair entries like:
            # [1] A (stream 7): 10.93.137.244:43803 <-> 10.93.75.130:8443
            #     B (stream 33): 172.68.164.118:51891 <-> 10.93.136.244:443
            #     Confidence: 1.00 | Evidence: ...

            pair_pattern = re.compile(r'\[(\d+)\]\s+A\s+\(stream\s+(\d+)\):\s+(.+)')
            stream_b_pattern = re.compile(r'\s+B\s+\(stream\s+(\d+)\):\s+(.+)')
            confidence_pattern = re.compile(r'\s+Confidence:\s+([\d.]+)')

            i = 0
            while i < len(lines):
                line = lines[i]

                # Look for pair start
                match_a = pair_pattern.match(line)
                if match_a:
                    pair_id = int(match_a.group(1))
                    stream_a = int(match_a.group(2))
                    connection_a = match_a.group(3).strip()

                    # Next line should be stream B
                    if i + 1 < len(lines):
                        match_b = stream_b_pattern.match(lines[i + 1])
                        if match_b:
                            stream_b = int(match_b.group(1))
                            connection_b = match_b.group(2).strip()

                            # Next line should be confidence
                            confidence = 1.0  # Default
                            if i + 2 < len(lines):
                                match_conf = confidence_pattern.match(lines[i + 2])
                                if match_conf:
                                    confidence = float(match_conf.group(1))

                            pair = ConnectionPair(
                                pair_id=pair_id,
                                stream_a=stream_a,
                                connection_a=connection_a,
                                stream_b=stream_b,
                                connection_b=connection_b,
                                confidence=confidence,
                            )
                            pairs.append(pair)
                            i += 3  # Skip the lines we just processed
                            continue

                i += 1

        logger.info(f"Extracted {len(pairs)} connection pairs from matched connections file")
        return pairs

    except Exception as e:
        logger.error(f"Failed to parse matched connections file: {e}")
        raise


def parse_topology_services(topology_file: Path) -> list[tuple[str, int]]:
    """
    Parse topology.txt file to extract services (serverIP:serverPort).

    Args:
        topology_file: Path to topology.txt file

    Returns:
        List of (server_ip, server_port) tuples

    Example:
        Input line: "Server (10.93.75.130:8443)"
        Output: [("10.93.75.130", 8443)]
    """
    services = []

    with open(topology_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Look for server IP:port patterns
    # Pattern: IP:port where IP is x.x.x.x and port is a number
    import re
    pattern = r'(\d+\.\d+\.\d+\.\d+):(\d+)'

    for match in re.finditer(pattern, content):
        ip = match.group(1)
        port = int(match.group(2))
        services.append((ip, port))

    # Remove duplicates while preserving order
    seen = set()
    unique_services = []
    for service in services:
        if service not in seen:
            seen.add(service)
            unique_services.append(service)

    return unique_services


def format_quality_report(
    results: dict[tuple[str, int], tuple[QualityMetrics, QualityMetrics]],
    file1_name: str,
    file2_name: str,
) -> str:
    """
    Format quality analysis results as a table report.

    Args:
        results: Dictionary mapping services to (metrics1, metrics2)
        file1_name: Name of first PCAP file
        file2_name: Name of second PCAP file

    Returns:
        Formatted report string
    """
    lines = []
    lines.append("")
    lines.append("=" * 180)
    lines.append("Network Quality Analysis Report")
    lines.append("=" * 180)
    lines.append("")
    lines.append(f"File A: {file1_name}")
    lines.append(f"File B: {file2_name}")
    lines.append("")

    if not results:
        lines.append("No services found for analysis.")
        return '\n'.join(lines)

    # Summary statistics
    lines.append("Summary:")
    lines.append("-" * 180)
    lines.append(f"Total services analyzed: {len(results)}")
    lines.append("")

    # Service Quality Metrics Table
    lines.append("Service Quality Metrics:")
    lines.append("-" * 180)

    # Table header
    header = (
        f"{'Service':<22} "
        f"{'File':<6} "
        f"{'Direction':<15} "
        f"{'Packets':<10} "
        f"{'Retrans':<12} "
        f"{'Dup ACK':<12} "
        f"{'Lost Seg':<12}"
    )
    lines.append(header)
    lines.append("-" * 180)

    # Table rows
    for service, (metrics1, metrics2) in sorted(results.items()):
        server_ip, server_port = service
        service_str = f"{server_ip}:{server_port}"

        # Check if metrics have data
        has_metrics1_data = (metrics1.client_total_packets > 0 or metrics1.server_total_packets > 0)
        has_metrics2_data = (metrics2.client_total_packets > 0 or metrics2.server_total_packets > 0)

        if not has_metrics1_data and not has_metrics2_data:
            # No data for this service
            row = f"{service_str:<22} {'N/A':<6} {'No traffic':<15} {'-':<10} {'-':<12} {'-':<12} {'-':<12}"
            lines.append(row)
            continue

        # File A metrics
        if has_metrics1_data:
            # Client -> Server
            row = (
                f"{service_str:<22} "
                f"{'A':<6} "
                f"{'Client->Server':<15} "
                f"{metrics1.client_total_packets:<10,} "
                f"{metrics1.client_retransmissions:>6,} ({metrics1.client_retransmission_rate:>4.1f}%) "
                f"{metrics1.client_duplicate_acks:>6,} ({metrics1.client_duplicate_ack_rate:>4.1f}%) "
                f"{metrics1.client_lost_segments:>6,} ({metrics1.client_loss_rate:>4.1f}%)"
            )
            lines.append(row)

            # Server -> Client
            row = (
                f"{'':<22} "
                f"{'':<6} "
                f"{'Server->Client':<15} "
                f"{metrics1.server_total_packets:<10,} "
                f"{metrics1.server_retransmissions:>6,} ({metrics1.server_retransmission_rate:>4.1f}%) "
                f"{metrics1.server_duplicate_acks:>6,} ({metrics1.server_duplicate_ack_rate:>4.1f}%) "
                f"{metrics1.server_lost_segments:>6,} ({metrics1.server_loss_rate:>4.1f}%)"
            )
            lines.append(row)

        # File B metrics
        if has_metrics2_data:
            # Client -> Server
            row = (
                f"{service_str if not has_metrics1_data else '':<22} "
                f"{'B':<6} "
                f"{'Client->Server':<15} "
                f"{metrics2.client_total_packets:<10,} "
                f"{metrics2.client_retransmissions:>6,} ({metrics2.client_retransmission_rate:>4.1f}%) "
                f"{metrics2.client_duplicate_acks:>6,} ({metrics2.client_duplicate_ack_rate:>4.1f}%) "
                f"{metrics2.client_lost_segments:>6,} ({metrics2.client_loss_rate:>4.1f}%)"
            )
            lines.append(row)

            # Server -> Client
            row = (
                f"{'':<22} "
                f"{'':<6} "
                f"{'Server->Client':<15} "
                f"{metrics2.server_total_packets:<10,} "
                f"{metrics2.server_retransmissions:>6,} ({metrics2.server_retransmission_rate:>4.1f}%) "
                f"{metrics2.server_duplicate_acks:>6,} ({metrics2.server_duplicate_ack_rate:>4.1f}%) "
                f"{metrics2.server_lost_segments:>6,} ({metrics2.server_loss_rate:>4.1f}%)"
            )
            lines.append(row)

        # Add separator between services
        if len(results) > 1:
            lines.append("-" * 180)

    lines.append("=" * 180)

    return '\n'.join(lines)

def calculate_performance_score(metrics: QualityMetrics) -> float:
    """
    Calculate a performance score for quality metrics.
    Lower score means worse performance.

    Args:
        metrics: QualityMetrics object

    Returns:
        Performance score (0-100, lower is worse)
    """
    # Calculate weighted penalty based on different metrics
    # Weights: retransmission (40%), duplicate ACK (30%), packet loss (30%)
    total_packets = metrics.client_total_packets + metrics.server_total_packets
    if total_packets == 0:
        return 100.0  # No traffic, perfect score

    # Calculate average rates across both directions
    avg_retrans_rate = (metrics.client_retransmission_rate + metrics.server_retransmission_rate) / 2
    avg_dup_ack_rate = (metrics.client_duplicate_ack_rate + metrics.server_duplicate_ack_rate) / 2
    avg_loss_rate = (metrics.client_loss_rate + metrics.server_loss_rate) / 2

    # Calculate penalty (0-100, higher is worse)
    penalty = (avg_retrans_rate * 0.4) + (avg_dup_ack_rate * 0.3) + (avg_loss_rate * 0.3)

    # Convert to score (100 - penalty, capped at 0)
    score = max(0.0, 100.0 - penalty)

    return score


def format_connection_pair_report(
    results: list[ConnectionPairMetrics],
    file1_name: str,
    file2_name: str,
    top_n: int | None = None,
) -> str:
    """
    Format connection pair quality analysis results as a table report.

    Args:
        results: List of ConnectionPairMetrics
        file1_name: Name of first PCAP file
        file2_name: Name of second PCAP file
        top_n: If specified, only show top N worst performing connection pairs

    Returns:
        Formatted report string
    """
    lines = []
    lines.append("")
    lines.append("=" * 200)
    lines.append("Connection Pair Quality Analysis Report")
    lines.append("=" * 200)
    lines.append("")
    lines.append(f"File A: {file1_name}")
    lines.append(f"File B: {file2_name}")
    lines.append("")

    if not results:
        lines.append("No connection pairs found for analysis.")
        return '\n'.join(lines)

    # Calculate performance scores for each pair
    scored_results = []
    for pair_metrics in results:
        # Calculate combined score from both files
        score_a = calculate_performance_score(pair_metrics.metrics_a)
        score_b = calculate_performance_score(pair_metrics.metrics_b)
        # Use the worse (lower) score
        combined_score = min(score_a, score_b)
        scored_results.append((combined_score, score_a, score_b, pair_metrics))

    # Sort by score (ascending, so worst performance first)
    scored_results.sort(key=lambda x: x[0])

    # Filter to top N if specified
    if top_n is not None and top_n > 0:
        scored_results = scored_results[:top_n]

    # Summary statistics
    lines.append("Summary:")
    lines.append("-" * 200)
    lines.append(f"Total connection pairs analyzed: {len(results)}")
    if top_n is not None and top_n > 0:
        lines.append(f"Showing top {len(scored_results)} worst performing connection pairs")
    lines.append("")

    # Connection Pair Quality Metrics Table
    if top_n is not None and top_n > 0:
        lines.append(f"Top {len(scored_results)} Worst Performing Connection Pairs:")
    else:
        lines.append("Connection Pair Quality Metrics:")
    lines.append("-" * 200)

    # Table header
    header = (
        f"{'Pair#':<7} "
        f"{'Stream':<8} "
        f"{'Connection':<45} "
        f"{'File':<6} "
        f"{'Dir':<15} "
        f"{'Pkts':<8} "
        f"{'Retrans':<12} "
        f"{'DupACK':<12} "
        f"{'LostSeg':<12} "
        f"{'Score':<8} "
        f"{'Conf':<6}"
    )
    lines.append(header)
    lines.append("-" * 200)

    # Table rows
    for combined_score, score_a, score_b, pair_metrics in scored_results:
        pair = pair_metrics.pair
        metrics_a = pair_metrics.metrics_a
        metrics_b = pair_metrics.metrics_b

        # Check if metrics have any data
        has_metrics_a_data = (metrics_a.client_total_packets > 0 or metrics_a.server_total_packets > 0)
        has_metrics_b_data = (metrics_b.client_total_packets > 0 or metrics_b.server_total_packets > 0)

        if not has_metrics_a_data and not has_metrics_b_data:
            # No data for this pair
            row = (
                f"{pair.pair_id:<7} "
                f"{pair.stream_a:<8} "
                f"{pair.connection_a[:45]:<45} "
                f"{'N/A':<6} "
                f"{'No traffic':<15} "
                f"{'-':<8} {'-':<12} {'-':<12} {'-':<12} {'-':<8} "
                f"{pair.confidence:<6.2f}"
            )
            lines.append(row)
            continue

        # File A metrics
        if has_metrics_a_data:
            # Client -> Server
            row = (
                f"{pair.pair_id:<7} "
                f"{pair.stream_a:<8} "
                f"{pair.connection_a[:45]:<45} "
                f"{'A':<6} "
                f"{'C->S':<15} "
                f"{metrics_a.client_total_packets:<8,} "
                f"{metrics_a.client_retransmissions:>5,}({metrics_a.client_retransmission_rate:>4.1f}%) "
                f"{metrics_a.client_duplicate_acks:>5,}({metrics_a.client_duplicate_ack_rate:>4.1f}%) "
                f"{metrics_a.client_lost_segments:>5,}({metrics_a.client_loss_rate:>4.1f}%) "
                f"{score_a:<8.1f} "
                f"{pair.confidence:<6.2f}"
            )
            lines.append(row)

            # Server -> Client
            row = (
                f"{'':<7} "
                f"{'':<8} "
                f"{'':<45} "
                f"{'':<6} "
                f"{'S->C':<15} "
                f"{metrics_a.server_total_packets:<8,} "
                f"{metrics_a.server_retransmissions:>5,}({metrics_a.server_retransmission_rate:>4.1f}%) "
                f"{metrics_a.server_duplicate_acks:>5,}({metrics_a.server_duplicate_ack_rate:>4.1f}%) "
                f"{metrics_a.server_lost_segments:>5,}({metrics_a.server_loss_rate:>4.1f}%) "
                f"{'':<8} "
                f"{'':<6}"
            )
            lines.append(row)

        # File B metrics
        if has_metrics_b_data:
            # Client -> Server
            row = (
                f"{pair.pair_id if not has_metrics_a_data else '':<7} "
                f"{pair.stream_b:<8} "
                f"{pair.connection_b[:45]:<45} "
                f"{'B':<6} "
                f"{'C->S':<15} "
                f"{metrics_b.client_total_packets:<8,} "
                f"{metrics_b.client_retransmissions:>5,}({metrics_b.client_retransmission_rate:>4.1f}%) "
                f"{metrics_b.client_duplicate_acks:>5,}({metrics_b.client_duplicate_ack_rate:>4.1f}%) "
                f"{metrics_b.client_lost_segments:>5,}({metrics_b.client_loss_rate:>4.1f}%) "
                f"{score_b:<8.1f} "
                f"{pair.confidence if not has_metrics_a_data else '':<6}"
            )
            lines.append(row)

            # Server -> Client
            row = (
                f"{'':<7} "
                f"{'':<8} "
                f"{'':<45} "
                f"{'':<6} "
                f"{'S->C':<15} "
                f"{metrics_b.server_total_packets:<8,} "
                f"{metrics_b.server_retransmissions:>5,}({metrics_b.server_retransmission_rate:>4.1f}%) "
                f"{metrics_b.server_duplicate_acks:>5,}({metrics_b.server_duplicate_ack_rate:>4.1f}%) "
                f"{metrics_b.server_lost_segments:>5,}({metrics_b.server_loss_rate:>4.1f}%) "
                f"{'':<8} "
                f"{'':<6}"
            )
            lines.append(row)

        # Add separator between pairs
        lines.append("-" * 200)

    lines.append(f"Total: {len(scored_results)} connection pairs shown")
    lines.append("=" * 200)

    return '\n'.join(lines)


