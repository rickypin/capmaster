from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Tuple, Optional

from capmaster.core.connection.matcher import ConnectionMatch
from capmaster.plugins.match.endpoint_stats import EndpointStatsCollector, aggregate_by_service
from capmaster.plugins.match.server_detector import ServerDetector


class TopologyAnalyzer:
    def __init__(self, matches: list[ConnectionMatch], file1: Path, file2: Path, service_list: Path | None = None):
        self.matches = matches
        self.file1 = file1
        self.file2 = file2
        self.service_list = service_list

    def analyze(self) -> TopologyInfo:
        """
        Analyze topology for dual capture points.

        Returns:
            TopologyInfo containing per-service topology information
        """
        # Create detector and collector for endpoint statistics
        detector = ServerDetector(service_list_path=self.service_list)
        collector = EndpointStatsCollector(detector)

        # Add all matches
        for match in self.matches:
            collector.add_match(match)

        # Finalize collection (performs cardinality analysis)
        collector.finalize()

        # Get aggregated statistics
        endpoint_stats = collector.get_stats()

        if not endpoint_stats:
            return TopologyInfo(
                file1_name=self.file1.name,
                file2_name=self.file2.name,
                services=[],
            )

        # Aggregate by service (server port + protocol)
        service_stats_list = aggregate_by_service(endpoint_stats)

        # Build ServiceTopologyInfoDual for each service
        services = []
        for service_stats in service_stats_list:
            # Calculate representative hops for this service across all endpoint
            # pairs. Using a small aggregation (median) guards against
            # outliers in multi-path scenarios while remaining stable for the
            # common case where all pairs share similar hops.
            client_hops_a_values = [p.client_hops_a for p in service_stats.endpoint_pairs if p.client_hops_a is not None]
            server_hops_a_values = [p.server_hops_a for p in service_stats.endpoint_pairs if p.server_hops_a is not None]
            client_hops_b_values = [p.client_hops_b for p in service_stats.endpoint_pairs if p.client_hops_b is not None]
            server_hops_b_values = [p.server_hops_b for p in service_stats.endpoint_pairs if p.server_hops_b is not None]

            def _median_or_none(values: list[int | None]) -> int | None:
                if not values:
                    return None
                sorted_vals = sorted(values)
                mid = len(sorted_vals) // 2
                return sorted_vals[mid]

            client_hops_a = _median_or_none(client_hops_a_values)
            server_hops_a = _median_or_none(server_hops_a_values)
            client_hops_b = _median_or_none(client_hops_b_values)
            server_hops_b = _median_or_none(server_hops_b_values)

            # Determine network position for this service
            position = self._determine_position(
                client_hops_a, server_hops_a, client_hops_b, server_hops_b
            )

            server_ports_a = {pair.tuple_a.server_port for pair in service_stats.endpoint_pairs}
            server_ports_b = {pair.tuple_b.server_port for pair in service_stats.endpoint_pairs}

            services.append(
                ServiceTopologyInfoDual(
                    server_port=service_stats.service_key.server_port,
                    protocol=service_stats.service_key.protocol,
                    client_ips_a=service_stats.unique_client_ips_a,
                    client_ips_b=service_stats.unique_client_ips_b,
                    server_ips_a=service_stats.unique_server_ips_a,
                    server_ips_b=service_stats.unique_server_ips_b,
                    client_hops_a=client_hops_a,
                    server_hops_a=server_hops_a,
                    client_hops_b=client_hops_b,
                    server_hops_b=server_hops_b,
                    position=position,
                    connection_count=service_stats.total_connections,
                    server_ports_a=server_ports_a,
                    server_ports_b=server_ports_b,
                )
            )

        # Sort services by port number
        services.sort(key=lambda s: s.server_port)

        return TopologyInfo(
            file1_name=self.file1.name,
            file2_name=self.file2.name,
            services=services,
        )

    def _determine_position(
        self,
        client_hops_a: int | None,
        server_hops_a: int | None,
        client_hops_b: int | None,
        server_hops_b: int | None,
    ) -> str:
        """Derive a coarse position label from hop-based capture sequence.

        This method is kept for backward-compatibility with existing
        expectations around the ``position`` field. The actual drawing order
        and textual descriptions are driven by
        :func:`_determine_capture_sequence_from_hops`, and this helper simply
        projects that ordering into a legacy enum
        (A_CLOSER_TO_CLIENT/B_CLOSER_TO_CLIENT/SAME_POSITION/UNKNOWN).
        """
        sequence = _determine_capture_sequence_from_hops(
            client_hops_a,
            server_hops_a,
            client_hops_b,
            server_hops_b,
        )

        if sequence == ("A", "B"):
            return "A_CLOSER_TO_CLIENT"
        if sequence == ("B", "A"):
            return "B_CLOSER_TO_CLIENT"

        # If we could not derive a sequence but all hop values are equal,
        # indicate SAME_POSITION, otherwise fall back to UNKNOWN.
        if (
            client_hops_a is not None
            and client_hops_b is not None
            and server_hops_a is not None
            and server_hops_b is not None
            and client_hops_a == client_hops_b
            and server_hops_a == server_hops_b
        ):
            return "SAME_POSITION"

        return "UNKNOWN"


@dataclass
class ServiceTopologyInfoDual:
    """Topology information for a single service in dual-capture scenario."""

    server_port: int
    """Server port number"""

    protocol: int
    """IP protocol number (6=TCP, 17=UDP, etc.)"""

    client_ips_a: set[str]
    """Set of client IP addresses in file A"""

    client_ips_b: set[str]
    """Set of client IP addresses in file B"""

    server_ips_a: set[str]
    """Set of server IP addresses in file A"""

    server_ips_b: set[str]
    """Set of server IP addresses in file B"""

    client_hops_a: int | None
    """Number of network hops from capture point A to client (None if unavailable)"""

    server_hops_a: int | None
    """Number of network hops from capture point A to server (None if unavailable)"""

    client_hops_b: int | None
    """Number of network hops from capture point B to client (None if unavailable)"""

    server_hops_b: int | None
    """Number of network hops from capture point B to server (None if unavailable)"""

    position: str
    """Relative position of capture points (A_CLOSER_TO_CLIENT, B_CLOSER_TO_CLIENT, SAME_POSITION, UNKNOWN)"""

    connection_count: int = 0
    """Number of matched connections for this service"""

    server_ports_a: set[int] = field(default_factory=set)
    """Set of server ports observed in file A for this service"""

    server_ports_b: set[int] = field(default_factory=set)
    """Set of server ports observed in file B for this service"""


@dataclass
class TopologyInfo:
    """Topology information for dual capture points with multiple services."""

    file1_name: str
    """Name of the first PCAP file (capture point A)"""

    file2_name: str
    """Name of the second PCAP file (capture point B)"""

    services: list[ServiceTopologyInfoDual]
    """List of services detected across both captures, sorted by port number"""


@dataclass
class ServiceTopologyInfo:
    """Topology information for a single service (identified by server port)."""

    server_port: int
    """Server port number"""

    protocol: int
    """IP protocol number (6=TCP, 17=UDP, etc.)"""

    client_ips: set[str]
    """Set of client IP addresses"""

    server_ips: set[str]
    """Set of server IP addresses"""

    client_hops: int | None
    """Number of network hops from capture point to client (None if unavailable)"""

    server_hops: int | None
    """Number of network hops from capture point to server (None if unavailable)"""

    connection_count: int = 0
    """Number of connections for this service"""


@dataclass
class SingleTopologyInfo:
    """Topology information for a single capture point with multiple services."""

    file_name: str
    """Name of the PCAP file"""

    services: list[ServiceTopologyInfo]
    """List of services detected in the capture, sorted by port number"""


def format_topology(topology: TopologyInfo) -> str:
    """
    Format topology information for dual capture points with multiple services.

    Each service (identified by server port) is displayed separately with its own
    communication path and topology description.
    """
    lines = []

    # Content in code block
    lines.append("```text")
    lines.append(f"Capture Point A: {topology.file1_name}")
    lines.append(f"Capture Point B: {topology.file2_name}")
    lines.append("")

    if not topology.services:
        lines.append("No matched connections detected.")
    else:
        # Display each service separately
        for idx, service in enumerate(topology.services, start=1):
            proto_str = _format_protocol(service.protocol)
            lines.append(f"=== Service {idx}: Port {service.server_port} ({proto_str}) ===")
            lines.append(
                "    (Service is keyed by the server port as observed at Capture Point A; "
                "per-capture server ports are shown below.)"
            )
            lines.append("")

            sequence = _determine_capture_sequence_from_hops(
                service.client_hops_a,
                service.server_hops_a,
                service.client_hops_b,
                service.server_hops_b,
            )
            lines.append(
                _build_dual_communication_path_for_service(
                    topology.file1_name,
                    topology.file2_name,
                    service,
                    sequence,
                )
            )
            lines.append("")

            description_lines = _build_capture_point_descriptions_for_service(
                service,
                sequence,
            )
            if description_lines:
                lines.extend(description_lines)
            lines.append("")



    lines.append("```")

    return "\n".join(lines)


def format_single_topology(topology: SingleTopologyInfo, *, capture_label: str = "A") -> str:
    """Format topology information for a single capture point with multiple services.

    Each service (identified by server port) is displayed separately with its own
    communication path and topology description.

    The ``capture_label`` parameter allows callers (such as the dual-capture
    fallback path) to render per-capture sections that are consistent with the
    surrounding "Capture Point A/B" headings.
    """
    lines: list[str] = []
    lines.append("```text")
    lines.append(f"Capture Point {capture_label}: {topology.file_name}")
    lines.append("")

    if not topology.services:
        lines.append("No TCP connections detected in this capture.")
    else:
        # Display each service separately
        for idx, service in enumerate(topology.services, start=1):
            proto_str = _format_protocol(service.protocol)
            lines.append(f"=== Service {idx}: Port {service.server_port} ({proto_str}) ===")

            client_list = _format_ip_list(service.client_ips)
            server_list = _format_server_list_single_port(service.server_ips, service.server_port)

            lines.append("")
            lines.append(
                _build_single_communication_path_for_service(
                    topology.file_name,
                    service,
                    client_list,
                    server_list,
                    capture_label=capture_label,
                )
            )
            lines.append("")
            lines.append(
                _describe_single_capture_position_for_service(
                    service,
                    client_list,
                    server_list,
                    capture_label=capture_label,
                )
            )
            lines.append("")

    lines.append("```")
    return "\n".join(lines)




def _format_ip_list(ips: set[str], max_display: int = 3) -> str:
    if not ips:
        return "N/A"

    sorted_ips = sorted(ips)
    if len(sorted_ips) <= max_display:
        return ", ".join(sorted_ips)
    else:
        displayed = ", ".join(sorted_ips[:max_display])
        return f"{displayed}, ... ({len(sorted_ips)} total)"


def _format_server_list(server_ips: set[str], server_ports: set[int]) -> str:
    if not server_ips or not server_ports:
        return "N/A"

    sorted_ips = sorted(server_ips)
    sorted_ports = sorted(server_ports)

    # If single IP and single port, show as IP:port
    if len(sorted_ips) == 1 and len(sorted_ports) == 1:
        return f"{sorted_ips[0]}:{sorted_ports[0]}"

    # If single IP but multiple ports
    if len(sorted_ips) == 1:
        ports_str = ", ".join(str(p) for p in sorted_ports[:3])
        if len(sorted_ports) > 3:
            ports_str += f", ... ({len(sorted_ports)} ports)"
        return f"{sorted_ips[0]}:{ports_str}"

    # Multiple IPs
    ip_str = _format_ip_list(server_ips)
    ports_str = ", ".join(str(p) for p in sorted_ports[:3])
    if len(sorted_ports) > 3:
        ports_str += f", ... ({len(sorted_ports)} ports)"
    return f"{ip_str}:{ports_str}"


@dataclass(frozen=True)
class _CapturePointMetrics:
    label: str
    client_hops: int | None
    server_hops: int | None


CaptureSequence = Tuple[str, str]


def _determine_capture_sequence_from_hops(
    client_hops_a: int | None,
    server_hops_a: int | None,
    client_hops_b: int | None,
    server_hops_b: int | None,
) -> CaptureSequence | None:
    """Determine capture-point ordering from TTL-derived hop counts.

    Returns a (client_side_label, server_side_label) pair or None if the
    ordering cannot be determined from the hop values (for example when both
    capture points observe identical hops to client and server).
    """
    # Special case: asymmetric hops with opposite zero values indicate that a
    # middle network device terminates and re-initiates TCP connections.
    # In this scenario, the capture point with zero hops to the *server* is
    # placed on the left, and the capture point with zero hops to the *client*
    # is placed on the right.
    # If any side completely lacks TTL information, we cannot derive a
    # reliable ordering from hops alone.
    if (
        client_hops_a is None
        or client_hops_b is None
        or server_hops_a is None
        or server_hops_b is None
    ):
        return None

    client_delta = client_hops_a - client_hops_b
    server_delta = server_hops_a - server_hops_b
    if client_delta != server_delta:
        if client_hops_a == 0 and server_hops_b == 0:
            return ("B", "A")
        if client_hops_b == 0 and server_hops_a == 0:
            return ("A", "B")

    # If both capture points see exactly the same hops, we cannot reliably
    # decide which one is closer to the client.
    if client_hops_a == client_hops_b and server_hops_a == server_hops_b:
        return None

    # Primary signal: fewer client hops means closer to the client.
    if client_hops_a < client_hops_b:
        return ("A", "B")
    if client_hops_b < client_hops_a:
        return ("B", "A")

    # If client hops are equal, fall back to server hops: more server hops
    # means further from the server and therefore closer to the client.
    if server_hops_a > server_hops_b:
        return ("A", "B")
    if server_hops_b > server_hops_a:
        return ("B", "A")

    # All hops equal – treat as unknown ordering.
    return None



def _determine_capture_sequence(position: str) -> CaptureSequence | None:
    if position == "A_CLOSER_TO_CLIENT":
        # Historical behavior: when A is closer to client, topology text shows B -> A.
        return ("B", "A")
    if position == "B_CLOSER_TO_CLIENT":
        return ("A", "B")
    return None




def _build_measurements(
    point: _CapturePointMetrics,
    *,
    role: Literal["client", "server"],
    balanced: bool,
) -> list[tuple[str, int]]:
    """Build (label, hops) pairs for textual description.

    None hop values indicate that TTL data was not available for that side and
    are omitted from the measurement list so that callers can render a
    dedicated "no TTL data available" message instead of printing a synthetic
    "0 hops" line.
    """
    measurements: list[tuple[str, int]] = []

    if role == "client":
        if point.client_hops is not None:
            measurements.append(("client", point.client_hops))
        second_label = "server" if balanced else "intermediate network device"
        if point.server_hops is not None:
            measurements.append((second_label, point.server_hops))
        return measurements

    # role == "server"
    first_label = "client" if balanced else "intermediate network device"
    if point.client_hops is not None:
        measurements.append((first_label, point.client_hops))
    if point.server_hops is not None:
        measurements.append(("server", point.server_hops))
    return measurements


def _format_measurements(measurements: list[tuple[str, int]]) -> str:
    parts = [f"{value} hops away from the {label}" for label, value in measurements]
    if not parts:
        return "no TTL data available"
    if len(parts) == 1:
        return parts[0]
    return " and ".join(parts)


def _build_adjacency_phrase(
    measurements: list[tuple[str, int]],
) -> str | None:
    for label, value in measurements:
        if value == 0:
            return f"directly adjacent to the {label}"
    return None




def _join_path_segments(nodes: list[str], edges_have_device: list[bool]) -> str:
    parts = [nodes[0]]
    for idx, node in enumerate(nodes[1:]):
        separator = " ->[Network Device]-> " if edges_have_device[idx] else " -> "
        parts.append(separator)
        parts.append(node)
    return "".join(parts)


# ============================================================================
# New helper functions for per-service topology formatting
# ============================================================================


def _format_protocol(protocol: int) -> str:
    """Format protocol number as human-readable string."""
    if protocol == 6:
        return "TCP"
    elif protocol == 17:
        return "UDP"
    else:
        return f"Proto{protocol}"


def _format_server_list_single_port(server_ips: set[str], server_port: int) -> str:
    """
    Format server list for a single port.

    Args:
        server_ips: Set of server IP addresses
        server_port: Server port number

    Returns:
        Formatted string like "20.0.0.1:80" or "20.0.0.1, 20.0.0.2:80"
    """
    if not server_ips:
        return "N/A"

    sorted_ips = sorted(server_ips)
    if len(sorted_ips) == 1:
        return f"{sorted_ips[0]}:{server_port}"
    else:
        ip_str = _format_ip_list(server_ips)
        return f"{ip_str}:{server_port}"


def _build_single_communication_path_for_service(
    file_name: str,
    service: ServiceTopologyInfo,
    client_list: str,
    server_list: str,
    *,
    capture_label: str,
) -> str:
    """Build communication path for a single service in single-capture scenario.

    The path intentionally uses generic "Client"/"Server" nodes so that IP:port
    details are shown in the capture point line, consistent with dual-capture
    output.
    """
    nodes = [
        "Client",
        f"Capture Point {capture_label}",
        "Server",
    ]
    edges = [
        service.client_hops is not None and service.client_hops > 0,
        service.server_hops is not None and service.server_hops > 0,
    ]
    return _join_path_segments(nodes, edges)


def _describe_single_capture_position_for_service(
    service: ServiceTopologyInfo,
    client_list: str,
    server_list: str,
    *,
    capture_label: str,
) -> str:
    """Summarize capture point distance for a single service using hops only."""
    client_hops = service.client_hops
    server_hops = service.server_hops

    if client_hops is not None and server_hops is not None:
        return (
            f"Capture Point {capture_label}: Clients {client_list} -> Servers {server_list}, "
            f"{client_hops} hops away from the client and {server_hops} hops away from the server."
        )

    if client_hops is None and server_hops is None:
        return (
            f"Capture Point {capture_label}: TTL data was unavailable to describe its distance "
            "to the client or the server."
        )
    if client_hops is None:
        return (
            f"Capture Point {capture_label}: Clients {client_list} -> Servers {server_list}, "
            f"{server_hops} hops away from the server; client TTL data was unavailable."
        )
    return (
        f"Capture Point {capture_label}: Clients {client_list} -> Servers {server_list}, "
        f"{client_hops} hops away from the client; server TTL data was unavailable."
    )


def _build_dual_communication_path_for_service(
    file1_name: str,
    file2_name: str,
    service: ServiceTopologyInfoDual,
    sequence: tuple[str, str] | None,
) -> str:
    """Build communication path for a single service in dual-capture scenario.

    The path intentionally uses generic "Client"/"Server" nodes so that
    per-capture client/server IP:port details can be shown in the capture
    point lines instead, matching the CLI output style.
    """
    order = sequence or ("A", "B")
    first_label, second_label = order

    nodes = [
        "Client",
        f"Capture Point {first_label}",
        f"Capture Point {second_label}",
        "Server",
    ]
    edges = [
        _has_client_device_for_service(service, first_label),
        True,
        _has_server_device_for_service(service, second_label),
    ]
    return _join_path_segments(nodes, edges)


def _has_client_device_for_service(service: ServiceTopologyInfoDual, label: str) -> bool:
    """Return True when hops suggest at least one device between client and capture.

    This helper is deliberately conservative: it only uses hop counts to infer
    whether there is *some* network infrastructure between the client and the
    capture point (``hops > 0``). It does **not** attempt to classify the type
    or number of devices.
    """
    hops = service.client_hops_a if label == "A" else service.client_hops_b
    return bool(hops and hops > 0)


def _has_server_device_for_service(service: ServiceTopologyInfoDual, label: str) -> bool:
    """Return True when hops suggest at least one device between capture and server.

    Similar to :func:`_has_client_device_for_service`, this only checks whether
    the hop count is strictly greater than zero and does not try to infer
    intermediate topology beyond that.
    """
    hops = service.server_hops_a if label == "A" else service.server_hops_b
    return bool(hops and hops > 0)


def _build_capture_point_descriptions_for_service(
    service: ServiceTopologyInfoDual,
    sequence: tuple[str, str] | None,
) -> list[str]:
    """Build capture point descriptions for a single service.

    The output is normalized as:

        Capture Point A: Clients ... -> Servers ..., <TTL description>.

    so that dual-capture and single-capture modes share the same style.
    """
    if sequence is None:
        return _build_unknown_descriptions_for_service(service)

    client_label, server_label = sequence

    balanced = abs(service.client_hops_a - service.client_hops_b) == abs(
        service.server_hops_a - service.server_hops_b
    )

    client_desc = _describe_capture_point_for_service(
        service, label=client_label, role="client", balanced=balanced
    )
    server_desc = _describe_capture_point_for_service(
        service, label=server_label, role="server", balanced=balanced
    )
    return [client_desc, server_desc]


def _describe_capture_point_for_service(
    service: ServiceTopologyInfoDual,
    *,
    label: str,
    role: str,
    balanced: bool,
) -> str:
    """Describe a capture point for a specific service including IP/port info."""
    metrics = _get_capture_point_metrics_for_service(service, label)
    measurements = _build_measurements(metrics, role=role, balanced=balanced)
    measurement_text = _format_measurements(measurements)

    if label == "A":
        clients = _format_ip_list(service.client_ips_a)
        ports = service.server_ports_a or {service.server_port}
        servers = _format_server_list(service.server_ips_a, ports)
    else:
        clients = _format_ip_list(service.client_ips_b)
        ports = service.server_ports_b or {service.server_port}
        servers = _format_server_list(service.server_ips_b, ports)

    return (
        f"Capture Point {label}: Clients {clients} -> Servers {servers}, "
        f"{measurement_text}."
    )


def _get_capture_point_metrics_for_service(
    service: ServiceTopologyInfoDual,
    label: str,
) -> _CapturePointMetrics:
    """Get capture point metrics for a service.

    Hop values may be None when TTL data was not available for that side. This
    is propagated into measurements so that the formatter can emit a clear
    "no TTL data available" message instead of fabricating 0-hop distances.
    """
    if label == "A":
        return _CapturePointMetrics(
            "A",
            service.client_hops_a,
            service.server_hops_a,
        )
    return _CapturePointMetrics(
        "B",
        service.client_hops_b,
        service.server_hops_b,
    )


def _build_unknown_descriptions_for_service(service: ServiceTopologyInfoDual) -> list[str]:
    """Build fallback descriptions when position cannot be determined for a service."""
    # Keep the high-level explanation line for users.
    lines = [
        "Topology: Cannot determine (same position or insufficient TTL data)",
    ]

    # Provide per-capture client/server view with observed hops to
    # match the new Capture Point style.
    clients_a = _format_ip_list(service.client_ips_a)
    ports_a = service.server_ports_a or {service.server_port}
    servers_a = _format_server_list(service.server_ips_a, ports_a)

    clients_b = _format_ip_list(service.client_ips_b)
    ports_b = service.server_ports_b or {service.server_port}
    servers_b = _format_server_list(service.server_ips_b, ports_b)

    def _format_unknown_hops(client_hops: int | None, server_hops: int | None) -> str:
        client_part = (
            f"observed {client_hops} client hops" if client_hops is not None else "client TTL data unavailable"
        )
        server_part = (
            f"{server_hops} server hops" if server_hops is not None else "server TTL data unavailable"
        )
        return f"{client_part} and {server_part}."

    lines.append(
        (
            f"Capture Point A: Clients {clients_a} -> Servers {servers_a}, "
            f"{_format_unknown_hops(service.client_hops_a, service.server_hops_a)}"
        )
    )
    lines.append(
        (
            f"Capture Point B: Clients {clients_b} -> Servers {servers_b}, "
            f"{_format_unknown_hops(service.client_hops_b, service.server_hops_b)}"
        )
    )
    return lines
