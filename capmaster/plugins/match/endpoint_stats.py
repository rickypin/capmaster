"""Endpoint statistics collector for matched connections."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from capmaster.plugins.match.matcher import ConnectionMatch
from capmaster.plugins.match.server_detector import ServerDetector, ServerInfo


@dataclass(frozen=True)
class EndpointTuple:
    """
    Endpoint tuple (client IP, server IP, server port).

    Client port is intentionally excluded for aggregation.
    """

    client_ip: str
    """Client IP address"""

    server_ip: str
    """Server IP address"""

    server_port: int
    """Server port number"""

    def __str__(self) -> str:
        """String representation."""
        return f"Client {self.client_ip} → Server {self.server_ip}:{self.server_port}"


@dataclass
class EndpointPairStats:
    """Paired endpoint statistics for files A and B."""

    tuple_a: EndpointTuple
    """Endpoint tuple from file A"""

    tuple_b: EndpointTuple
    """Endpoint tuple from file B"""

    count: int
    """Number of matched connections"""

    confidence: str
    """Average confidence level"""

    def __str__(self) -> str:
        """String representation."""
        return (
            f"Count: {self.count} | Confidence: {self.confidence}\n"
            f"  File A: {self.tuple_a}\n"
            f"  File B: {self.tuple_b}"
        )


class EndpointStatsCollector:
    """
    Collect and aggregate endpoint statistics for matched connections.

    This collector processes matched connection pairs and aggregates them
    by endpoint tuples (client IP, server IP, server port), showing the
    paired relationship between files A and B.
    """

    def __init__(self, detector: ServerDetector):
        """
        Initialize the collector.

        Args:
            detector: Server detector for determining server/client roles
        """
        self.detector = detector

        # Key: (tuple_a, tuple_b), Value: count
        self.pair_stats: dict[tuple[EndpointTuple, EndpointTuple], int] = defaultdict(int)

        # Track confidences for averaging
        self.confidences: dict[tuple[EndpointTuple, EndpointTuple], list[str]] = defaultdict(list)

        # Store all matches for cardinality analysis
        self.matches: list[ConnectionMatch] = []

    def add_match(self, match: ConnectionMatch) -> None:
        """
        Add a matched connection pair.

        Args:
            match: Matched connection pair from files A and B
        """
        # Store match for later processing
        self.matches.append(match)

    def finalize(self) -> None:
        """
        Finalize statistics collection.

        This performs cardinality analysis and then processes all matches
        with the enhanced server detection.
        """
        # Step 1: Collect all connections for cardinality analysis
        for match in self.matches:
            self.detector.collect_connection(match.conn1)
            self.detector.collect_connection(match.conn2)

        # Step 2: Finalize cardinality analysis
        self.detector.finalize_cardinality()

        # Step 3: Process all matches with enhanced detection
        for match in self.matches:
            self._process_match(match)

    def _process_match(self, match: ConnectionMatch) -> None:
        """
        Process a single match with server detection.

        Args:
            match: Matched connection pair from files A and B
        """
        # Detect server for both connections
        info_a = self.detector.detect(match.conn1)
        info_b = self.detector.detect(match.conn2)

        # Create endpoint tuples (client port is excluded)
        tuple_a = EndpointTuple(
            client_ip=info_a.client_ip,
            server_ip=info_a.server_ip,
            server_port=info_a.server_port,
        )
        tuple_b = EndpointTuple(
            client_ip=info_b.client_ip,
            server_ip=info_b.server_ip,
            server_port=info_b.server_port,
        )

        # Use ordered pair as key (tuple_a, tuple_b)
        pair_key = (tuple_a, tuple_b)

        # Increment count
        self.pair_stats[pair_key] += 1

        # Track confidence (use the lower of the two)
        confidence = self._min_confidence(info_a.confidence, info_b.confidence)
        self.confidences[pair_key].append(confidence)

        # For VERY_LOW confidence, also add the reversed interpretation
        # This helps avoid missing connections due to incorrect server detection
        if confidence == "VERY_LOW":
            # Create reversed tuples (swap server/client roles)
            tuple_a_reversed = EndpointTuple(
                client_ip=info_a.server_ip,
                server_ip=info_a.client_ip,
                server_port=info_a.client_port,
            )
            tuple_b_reversed = EndpointTuple(
                client_ip=info_b.server_ip,
                server_ip=info_b.client_ip,
                server_port=info_b.client_port,
            )

            # Add reversed pair
            pair_key_reversed = (tuple_a_reversed, tuple_b_reversed)
            self.pair_stats[pair_key_reversed] += 1
            self.confidences[pair_key_reversed].append(confidence)

    def get_stats(self) -> list[EndpointPairStats]:
        """
        Get aggregated statistics.

        Returns:
            List of EndpointPairStats sorted by count (descending)
        """
        results = []
        for (tuple_a, tuple_b), count in self.pair_stats.items():
            # Calculate average confidence
            confs = self.confidences[(tuple_a, tuple_b)]
            avg_conf = self._average_confidence(confs)

            results.append(
                EndpointPairStats(
                    tuple_a=tuple_a,
                    tuple_b=tuple_b,
                    count=count,
                    confidence=avg_conf,
                )
            )

        # Sort by count (descending)
        results.sort(key=lambda x: x.count, reverse=True)
        return results

    def _min_confidence(self, conf1: str, conf2: str) -> str:
        """
        Get the minimum (more conservative) confidence level.

        Args:
            conf1: First confidence level
            conf2: Second confidence level

        Returns:
            The lower confidence level
        """
        conf_order = ["HIGH", "MEDIUM", "LOW", "VERY_LOW", "UNKNOWN"]
        idx1 = conf_order.index(conf1) if conf1 in conf_order else len(conf_order)
        idx2 = conf_order.index(conf2) if conf2 in conf_order else len(conf_order)

        # Higher index = lower confidence
        return conf_order[max(idx1, idx2)] if max(idx1, idx2) < len(conf_order) else "UNKNOWN"

    def _average_confidence(self, confidences: list[str]) -> str:
        """
        Calculate average confidence level.

        Args:
            confidences: List of confidence levels

        Returns:
            Average confidence level
        """
        if not confidences:
            return "UNKNOWN"

        # Map confidence to numeric values
        conf_map = {
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "VERY_LOW": 1,
            "UNKNOWN": 0,
        }

        # Calculate average
        total = sum(conf_map.get(c, 0) for c in confidences)
        avg = total / len(confidences)

        # Map back to confidence level
        if avg >= 3.5:
            return "HIGH"
        elif avg >= 2.5:
            return "MEDIUM"
        elif avg >= 1.5:
            return "LOW"
        elif avg >= 0.5:
            return "VERY_LOW"
        else:
            return "UNKNOWN"


def format_endpoint_stats(
    stats: list[EndpointPairStats],
    file1_name: str,
    file2_name: str,
) -> str:
    """
    Format endpoint statistics for display.

    Args:
        stats: List of endpoint pair statistics
        file1_name: Name of file A
        file2_name: Name of file B

    Returns:
        Formatted string for display
    """
    lines = []

    # Header
    lines.append("=" * 80)
    lines.append("Endpoint Statistics (Matched Connections Only)")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"File A: {file1_name}")
    lines.append(f"File B: {file2_name}")
    lines.append("")
    lines.append(f"Total unique endpoint pairs: {len(stats)}")
    lines.append(f"Total matched connections: {sum(s.count for s in stats)}")
    lines.append("")

    # Endpoint pairs
    lines.append("Endpoint Pairs:")
    lines.append("-" * 80)
    lines.append("")

    for i, stat in enumerate(stats, 1):
        lines.append(f"[{i}] Count: {stat.count} | Confidence: {stat.confidence}")
        lines.append(f"    File A: {stat.tuple_a}")
        lines.append(f"    File B: {stat.tuple_b}")
        lines.append("")

    lines.append("=" * 80)

    return "\n".join(lines)


def format_endpoint_stats_table(
    stats: list[EndpointPairStats],
    file1_name: str,
    file2_name: str,
) -> str:
    """
    Format endpoint statistics as a compact table.

    Args:
        stats: List of endpoint pair statistics
        file1_name: Name of file A
        file2_name: Name of file B

    Returns:
        Formatted table string
    """
    lines = []

    # Header
    lines.append("=" * 140)
    lines.append("Endpoint Statistics Summary")
    lines.append("=" * 140)
    lines.append("")
    lines.append(f"File A: {file1_name}")
    lines.append(f"File B: {file2_name}")
    lines.append("")

    # Table header
    header = (
        f"{'Client IP (A)':<15} | {'Server IP (A)':<15} | {'Port (A)':<8} | "
        f"{'Client IP (B)':<15} | {'Server IP (B)':<15} | {'Port (B)':<8} | "
        f"{'Count':<6} | {'Conf':<8}"
    )
    lines.append(header)
    lines.append("-" * 140)

    # Table rows
    for stat in stats:
        row = (
            f"{stat.tuple_a.client_ip:<15} | {stat.tuple_a.server_ip:<15} | {stat.tuple_a.server_port:<8} | "
            f"{stat.tuple_b.client_ip:<15} | {stat.tuple_b.server_ip:<15} | {stat.tuple_b.server_port:<8} | "
            f"{stat.count:<6} | {stat.confidence:<8}"
        )
        lines.append(row)

    lines.append("")
    lines.append("=" * 140)

    return "\n".join(lines)

