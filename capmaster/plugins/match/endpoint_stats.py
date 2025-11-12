"""Endpoint statistics collector for matched connections."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from capmaster.core.connection.matcher import ConnectionMatch
from capmaster.plugins.match.server_detector import ServerDetector, ServerInfo
from capmaster.plugins.match.ttl_utils import most_common_hops


@dataclass(frozen=True)
class EndpointTuple:
    """
    Endpoint tuple (client IP, server IP, server port, protocol).

    Client port is intentionally excluded for aggregation.
    """

    client_ip: str
    """Client IP address"""

    server_ip: str
    """Server IP address"""

    server_port: int
    """Server port number"""

    protocol: int
    """IP protocol number (6=TCP, 17=UDP, etc.)"""

    def __str__(self) -> str:
        """String representation."""
        proto_str = f"TCP" if self.protocol == 6 else f"UDP" if self.protocol == 17 else f"Proto{self.protocol}"
        return f"Client {self.client_ip} → Server {self.server_ip}:{self.server_port} ({proto_str})"


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

    client_ttl_a: int = 0
    """Most common client TTL from file A"""

    server_ttl_a: int = 0
    """Most common server TTL from file A"""

    client_ttl_b: int = 0
    """Most common client TTL from file B"""

    server_ttl_b: int = 0
    """Most common server TTL from file B"""

    client_hops_a: int = 0
    """Number of network hops for client in file A (calculated from TTL)"""

    server_hops_a: int = 0
    """Number of network hops for server in file A (calculated from TTL)"""

    client_hops_b: int = 0
    """Number of network hops for client in file B (calculated from TTL)"""

    server_hops_b: int = 0
    """Number of network hops for server in file B (calculated from TTL)"""

    total_bytes_a: int = 0
    """Total bytes (sum of frame lengths) for all matched connections in file A"""

    total_bytes_b: int = 0
    """Total bytes (sum of frame lengths) for all matched connections in file B"""

    def __str__(self) -> str:
        """String representation."""
        ttl_info = ""
        if self.client_ttl_a or self.server_ttl_a or self.client_ttl_b or self.server_ttl_b:
            ttl_info = (
                f"\n  TTL A: Client={self.client_ttl_a} (hops={self.client_hops_a}), "
                f"Server={self.server_ttl_a} (hops={self.server_hops_a})"
                f"\n  TTL B: Client={self.client_ttl_b} (hops={self.client_hops_b}), "
                f"Server={self.server_ttl_b} (hops={self.server_hops_b})"
            )
        return (
            f"Count: {self.count} | Confidence: {self.confidence}\n"
            f"  File A: {self.tuple_a}\n"
            f"  File B: {self.tuple_b}"
            f"{ttl_info}"
        )


@dataclass(frozen=True)
class ServiceKey:
    """
    Service identifier based on server port and protocol.

    A service is defined by its server port and protocol, aggregating
    all endpoint pairs that share these characteristics.
    """

    server_port: int
    """Server port number"""

    protocol: int
    """IP protocol number (6=TCP, 17=UDP, etc.)"""

    def __str__(self) -> str:
        """String representation."""
        proto_str = f"TCP" if self.protocol == 6 else f"UDP" if self.protocol == 17 else f"Proto{self.protocol}"
        return f"Port {self.server_port} ({proto_str})"


@dataclass
class ServiceStats:
    """
    Statistics for a service (aggregated by server port and protocol).

    A service groups multiple endpoint pairs that share the same server port
    and protocol, representing different client/server IP combinations accessing
    the same service.
    """

    service_key: ServiceKey
    """Service identifier (port + protocol)"""

    endpoint_pairs: list[EndpointPairStats]
    """List of endpoint pairs belonging to this service"""

    total_connections: int
    """Total number of matched connections across all endpoint pairs"""

    unique_server_ips_a: set[str]
    """Unique server IPs in file A"""

    unique_server_ips_b: set[str]
    """Unique server IPs in file B"""

    unique_client_ips_a: set[str]
    """Unique client IPs in file A"""

    unique_client_ips_b: set[str]
    """Unique client IPs in file B"""

    def __str__(self) -> str:
        """String representation."""
        return (
            f"Service: {self.service_key}\n"
            f"  Total connections: {self.total_connections}\n"
            f"  Endpoint pairs: {len(self.endpoint_pairs)}\n"
            f"  Server IPs: A={len(self.unique_server_ips_a)}, B={len(self.unique_server_ips_b)}\n"
            f"  Client IPs: A={len(self.unique_client_ips_a)}, B={len(self.unique_client_ips_b)}"
        )


class EndpointStatsCollector:
    """
    Collect and aggregate endpoint statistics for matched connections.

    This collector processes matched connection pairs and aggregates them
    by endpoint tuples (client IP, server IP, server port), showing the
    paired relationship between files A and B.
    """

    def __init__(self, detector: ServerDetector, disable_very_low_dual_output: bool = False):
        """
        Initialize the collector.

        Args:
            detector: Server detector for determining server/client roles
            disable_very_low_dual_output: If True, disable dual output for VERY_LOW confidence pairs
        """
        self.detector = detector
        self.disable_very_low_dual_output = disable_very_low_dual_output

        # Key: (tuple_a, tuple_b), Value: count
        self.pair_stats: dict[tuple[EndpointTuple, EndpointTuple], int] = defaultdict(int)

        # Track confidences for averaging
        self.confidences: dict[tuple[EndpointTuple, EndpointTuple], list[str]] = defaultdict(list)

        # Track TTL values for averaging
        self.client_ttls_a: dict[tuple[EndpointTuple, EndpointTuple], list[int]] = defaultdict(list)
        self.server_ttls_a: dict[tuple[EndpointTuple, EndpointTuple], list[int]] = defaultdict(list)
        self.client_ttls_b: dict[tuple[EndpointTuple, EndpointTuple], list[int]] = defaultdict(list)
        self.server_ttls_b: dict[tuple[EndpointTuple, EndpointTuple], list[int]] = defaultdict(list)

        # Track total bytes for each endpoint pair
        self.total_bytes_a: dict[tuple[EndpointTuple, EndpointTuple], int] = defaultdict(int)
        self.total_bytes_b: dict[tuple[EndpointTuple, EndpointTuple], int] = defaultdict(int)

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
        # Use the client/server roles from the connections directly
        # (these may have been aligned by the matcher to ensure port consistency)
        # But still detect to get confidence levels
        info_a = self.detector.detect(match.conn1)
        info_b = self.detector.detect(match.conn2)

        # Get protocol from connections
        protocol_a = match.conn1.protocol
        protocol_b = match.conn2.protocol

        # Create endpoint tuples using the connection's client/server roles
        # (not the detector's results, which may differ after alignment)
        tuple_a = EndpointTuple(
            client_ip=match.conn1.client_ip,
            server_ip=match.conn1.server_ip,
            server_port=match.conn1.server_port,
            protocol=protocol_a,
        )
        tuple_b = EndpointTuple(
            client_ip=match.conn2.client_ip,
            server_ip=match.conn2.server_ip,
            server_port=match.conn2.server_port,
            protocol=protocol_b,
        )

        # Use ordered pair as key (tuple_a, tuple_b)
        pair_key = (tuple_a, tuple_b)

        # Increment count
        self.pair_stats[pair_key] += 1

        # Track confidence (use the lower of the two)
        confidence = self._min_confidence(info_a.confidence, info_b.confidence)
        self.confidences[pair_key].append(confidence)

        # Track TTL values
        if match.conn1.client_ttl > 0:
            self.client_ttls_a[pair_key].append(match.conn1.client_ttl)
        if match.conn1.server_ttl > 0:
            self.server_ttls_a[pair_key].append(match.conn1.server_ttl)
        if match.conn2.client_ttl > 0:
            self.client_ttls_b[pair_key].append(match.conn2.client_ttl)
        if match.conn2.server_ttl > 0:
            self.server_ttls_b[pair_key].append(match.conn2.server_ttl)

        # Track total bytes
        self.total_bytes_a[pair_key] += match.conn1.total_bytes
        self.total_bytes_b[pair_key] += match.conn2.total_bytes

        # For VERY_LOW confidence, also add the reversed interpretation
        # This helps avoid missing connections due to incorrect server detection
        # Can be disabled with disable_very_low_dual_output flag
        if confidence == "VERY_LOW" and not self.disable_very_low_dual_output:
            # Create reversed tuples (swap server/client roles)
            tuple_a_reversed = EndpointTuple(
                client_ip=info_a.server_ip,
                server_ip=info_a.client_ip,
                server_port=info_a.client_port,
                protocol=protocol_a,
            )
            tuple_b_reversed = EndpointTuple(
                client_ip=info_b.server_ip,
                server_ip=info_b.client_ip,
                server_port=info_b.client_port,
                protocol=protocol_b,
            )

            # Add reversed pair
            pair_key_reversed = (tuple_a_reversed, tuple_b_reversed)
            self.pair_stats[pair_key_reversed] += 1
            self.confidences[pair_key_reversed].append(confidence)

            # Track TTL values for reversed pair (swap client/server TTLs)
            if match.conn1.server_ttl > 0:
                self.client_ttls_a[pair_key_reversed].append(match.conn1.server_ttl)
            if match.conn1.client_ttl > 0:
                self.server_ttls_a[pair_key_reversed].append(match.conn1.client_ttl)
            if match.conn2.server_ttl > 0:
                self.client_ttls_b[pair_key_reversed].append(match.conn2.server_ttl)
            if match.conn2.client_ttl > 0:
                self.server_ttls_b[pair_key_reversed].append(match.conn2.client_ttl)

            # Track total bytes for reversed pair
            self.total_bytes_a[pair_key_reversed] += match.conn1.total_bytes
            self.total_bytes_b[pair_key_reversed] += match.conn2.total_bytes

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

            # Calculate most common TTL values
            client_ttl_a = self._most_common_ttl(self.client_ttls_a[(tuple_a, tuple_b)])
            server_ttl_a = self._most_common_ttl(self.server_ttls_a[(tuple_a, tuple_b)])
            client_ttl_b = self._most_common_ttl(self.client_ttls_b[(tuple_a, tuple_b)])
            server_ttl_b = self._most_common_ttl(self.server_ttls_b[(tuple_a, tuple_b)])

            # Calculate network hops from TTL values
            client_hops_a = most_common_hops(self.client_ttls_a[(tuple_a, tuple_b)])
            server_hops_a = most_common_hops(self.server_ttls_a[(tuple_a, tuple_b)])
            client_hops_b = most_common_hops(self.client_ttls_b[(tuple_a, tuple_b)])
            server_hops_b = most_common_hops(self.server_ttls_b[(tuple_a, tuple_b)])

            # Get total bytes for this endpoint pair
            total_bytes_a = self.total_bytes_a[(tuple_a, tuple_b)]
            total_bytes_b = self.total_bytes_b[(tuple_a, tuple_b)]

            results.append(
                EndpointPairStats(
                    tuple_a=tuple_a,
                    tuple_b=tuple_b,
                    count=count,
                    confidence=avg_conf,
                    client_ttl_a=client_ttl_a,
                    server_ttl_a=server_ttl_a,
                    client_ttl_b=client_ttl_b,
                    server_ttl_b=server_ttl_b,
                    client_hops_a=client_hops_a,
                    server_hops_a=server_hops_a,
                    client_hops_b=client_hops_b,
                    server_hops_b=server_hops_b,
                    total_bytes_a=total_bytes_a,
                    total_bytes_b=total_bytes_b,
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

    def _most_common_ttl(self, ttls: list[int]) -> int:
        """
        Get the most common TTL value from a list.

        Args:
            ttls: List of TTL values

        Returns:
            Most common TTL value (0 if list is empty)
        """
        if not ttls:
            return 0

        from collections import Counter

        return Counter(ttls).most_common(1)[0][0]


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

        # Add TTL and hops info for File A if available
        if stat.client_ttl_a or stat.server_ttl_a:
            lines.append(
                f"            TTL: Client={stat.client_ttl_a} (hops={stat.client_hops_a}), "
                f"Server={stat.server_ttl_a} (hops={stat.server_hops_a})"
            )

        lines.append(f"    File B: {stat.tuple_b}")

        # Add TTL and hops info for File B if available
        if stat.client_ttl_b or stat.server_ttl_b:
            lines.append(
                f"            TTL: Client={stat.client_ttl_b} (hops={stat.client_hops_b}), "
                f"Server={stat.server_ttl_b} (hops={stat.server_hops_b})"
            )

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
    lines.append("=" * 210)
    lines.append("Endpoint Statistics Summary")
    lines.append("=" * 210)
    lines.append("")
    lines.append(f"File A: {file1_name}")
    lines.append(f"File B: {file2_name}")
    lines.append("")

    # Table header
    header = (
        f"{'Client IP (A)':<15} | {'Server IP (A)':<15} | {'Port (A)':<8} | {'TTL A (C/S)':<12} | {'Hops A (C/S)':<13} | "
        f"{'Client IP (B)':<15} | {'Server IP (B)':<15} | {'Port (B)':<8} | {'TTL B (C/S)':<12} | {'Hops B (C/S)':<13} | "
        f"{'Count':<6} | {'Conf':<8}"
    )
    lines.append(header)
    lines.append("-" * 210)

    # Table rows
    for stat in stats:
        ttl_a = f"{stat.client_ttl_a}/{stat.server_ttl_a}"
        ttl_b = f"{stat.client_ttl_b}/{stat.server_ttl_b}"
        hops_a = f"{stat.client_hops_a}/{stat.server_hops_a}"
        hops_b = f"{stat.client_hops_b}/{stat.server_hops_b}"
        row = (
            f"{stat.tuple_a.client_ip:<15} | {stat.tuple_a.server_ip:<15} | {stat.tuple_a.server_port:<8} | {ttl_a:<12} | {hops_a:<13} | "
            f"{stat.tuple_b.client_ip:<15} | {stat.tuple_b.server_ip:<15} | {stat.tuple_b.server_port:<8} | {ttl_b:<12} | {hops_b:<13} | "
            f"{stat.count:<6} | {stat.confidence:<8}"
        )
        lines.append(row)

    lines.append("")
    lines.append("=" * 210)

    return "\n".join(lines)


def aggregate_by_service(
    endpoint_stats: list[EndpointPairStats],
) -> list[ServiceStats]:
    """
    Aggregate endpoint pairs by service (server port + protocol).

    This function groups endpoint pairs that share the same server port and protocol,
    treating them as different client/server IP combinations accessing the same service.

    Args:
        endpoint_stats: List of EndpointPairStats to aggregate

    Returns:
        List of ServiceStats, sorted by total connections (descending)

    Example:
        >>> # Multiple endpoint pairs with port 8000 will be grouped into one service
        >>> service_stats = aggregate_by_service(endpoint_pairs)
        >>> for service in service_stats:
        ...     print(f"Service on port {service.service_key.server_port}")
        ...     print(f"  Total connections: {service.total_connections}")
        ...     print(f"  Endpoint pairs: {len(service.endpoint_pairs)}")
    """
    # Group by service key (server port + protocol)
    service_map: dict[ServiceKey, list[EndpointPairStats]] = defaultdict(list)

    for stat in endpoint_stats:
        # Use file A's server port and protocol as the service identifier
        # (assuming both files represent the same service)
        service_key = ServiceKey(
            server_port=stat.tuple_a.server_port,
            protocol=stat.tuple_a.protocol,
        )
        service_map[service_key].append(stat)

    # Build ServiceStats for each service
    results = []
    for service_key, pairs in service_map.items():
        # Calculate total connections
        total_connections = sum(p.count for p in pairs)

        # Collect unique IPs
        unique_server_ips_a = {p.tuple_a.server_ip for p in pairs}
        unique_server_ips_b = {p.tuple_b.server_ip for p in pairs}
        unique_client_ips_a = {p.tuple_a.client_ip for p in pairs}
        unique_client_ips_b = {p.tuple_b.client_ip for p in pairs}

        # Sort endpoint pairs by count (descending)
        sorted_pairs = sorted(pairs, key=lambda p: p.count, reverse=True)

        results.append(
            ServiceStats(
                service_key=service_key,
                endpoint_pairs=sorted_pairs,
                total_connections=total_connections,
                unique_server_ips_a=unique_server_ips_a,
                unique_server_ips_b=unique_server_ips_b,
                unique_client_ips_a=unique_client_ips_a,
                unique_client_ips_b=unique_client_ips_b,
            )
        )

    # Sort by total connections (descending)
    results.sort(key=lambda x: x.total_connections, reverse=True)
    return results


def format_service_stats(
    service_stats: list[ServiceStats],
    file1_name: str,
    file2_name: str,
) -> str:
    """
    Format service statistics for display.

    Args:
        service_stats: List of service statistics
        file1_name: Name of file A
        file2_name: Name of file B

    Returns:
        Formatted string for display
    """
    lines = []

    # Header
    lines.append("=" * 80)
    lines.append("Service Statistics (Aggregated by Server Port)")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"File A: {file1_name}")
    lines.append(f"File B: {file2_name}")
    lines.append("")
    lines.append(f"Total services: {len(service_stats)}")
    lines.append(f"Total matched connections: {sum(s.total_connections for s in service_stats)}")
    lines.append("")

    # Services
    lines.append("Services:")
    lines.append("-" * 80)
    lines.append("")

    for idx, service in enumerate(service_stats, start=1):
        proto_str = "TCP" if service.service_key.protocol == 6 else "UDP" if service.service_key.protocol == 17 else f"Proto{service.service_key.protocol}"
        lines.append(f"[{idx}] Service: Port {service.service_key.server_port} ({proto_str})")
        lines.append(f"    Total connections: {service.total_connections}")
        lines.append(f"    Endpoint pairs: {len(service.endpoint_pairs)}")
        lines.append(f"    Server IPs: A={sorted(service.unique_server_ips_a)}, B={sorted(service.unique_server_ips_b)}")
        lines.append(f"    Client IPs: A={sorted(service.unique_client_ips_a)}, B={sorted(service.unique_client_ips_b)}")
        lines.append("")

        # Show each endpoint pair
        for pair_idx, pair in enumerate(service.endpoint_pairs, start=1):
            lines.append(f"      [{pair_idx}] Count: {pair.count} | Confidence: {pair.confidence}")
            lines.append(f"          A: {pair.tuple_a.client_ip} → {pair.tuple_a.server_ip}:{pair.tuple_a.server_port}")

            # Add TTL and hops info for File A if available
            if pair.client_ttl_a or pair.server_ttl_a:
                lines.append(
                    f"             TTL: Client={pair.client_ttl_a} (hops={pair.client_hops_a}), "
                    f"Server={pair.server_ttl_a} (hops={pair.server_hops_a})"
                )

            lines.append(f"          B: {pair.tuple_b.client_ip} → {pair.tuple_b.server_ip}:{pair.tuple_b.server_port}")

            # Add TTL and hops info for File B if available
            if pair.client_ttl_b or pair.server_ttl_b:
                lines.append(
                    f"             TTL: Client={pair.client_ttl_b} (hops={pair.client_hops_b}), "
                    f"Server={pair.server_ttl_b} (hops={pair.server_hops_b})"
                )

            lines.append("")

        lines.append("")

    lines.append("=" * 80)

    return "\n".join(lines)

