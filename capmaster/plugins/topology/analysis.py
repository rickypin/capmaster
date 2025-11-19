from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Tuple

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
            # Calculate most common hops for this service
            # Use the first endpoint pair's hops as representative
            # (all pairs in the same service should have similar hops)
            first_pair = service_stats.endpoint_pairs[0]
            client_hops_a = first_pair.client_hops_a
            server_hops_a = first_pair.server_hops_a
            client_hops_b = first_pair.client_hops_b
            server_hops_b = first_pair.server_hops_b

            # Determine network position for this service
            position = self._determine_position(
                client_hops_a, server_hops_a, client_hops_b, server_hops_b
            )

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
        self, client_hops_a: int, server_hops_a: int, client_hops_b: int, server_hops_b: int
    ) -> str:
        server_delta_diff = server_hops_a - server_hops_b

        if server_delta_diff > 0:
            return "A_CLOSER_TO_CLIENT"
        elif server_delta_diff < 0:
            return "B_CLOSER_TO_CLIENT"
        else:
            return "SAME_POSITION"


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

    client_hops_a: int
    """Number of network hops from capture point A to client"""

    server_hops_a: int
    """Number of network hops from capture point A to server"""

    client_hops_b: int
    """Number of network hops from capture point B to client"""

    server_hops_b: int
    """Number of network hops from capture point B to server"""

    position: str
    """Relative position of capture points (A_CLOSER_TO_CLIENT, B_CLOSER_TO_CLIENT, SAME_POSITION, UNKNOWN)"""

    connection_count: int = 0
    """Number of matched connections for this service"""


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

            sequence = _determine_capture_sequence(service.position)
            lines.append("Communication path:")
            lines.append(_build_dual_communication_path_for_service(topology.file1_name, topology.file2_name, service, sequence))
            lines.append("")

            if sequence is None:
                lines.append("Topology: Cannot determine (same position or insufficient TTL data)")
                lines.append("")
                lines.append(
                    f"File A: Clients {_format_ip_list(service.client_ips_a)} -> "
                    f"Servers {_format_server_list_single_port(service.server_ips_a, service.server_port)}"
                )
                lines.append(
                    f"File B: Clients {_format_ip_list(service.client_ips_b)} -> "
                    f"Servers {_format_server_list_single_port(service.server_ips_b, service.server_port)}"
                )
            else:
                description_lines = _build_capture_point_descriptions_for_service(service, sequence)
                if description_lines:
                    lines.extend(description_lines)

            lines.append("")

        # Summary
        if len(topology.services) > 1:
            total_connections = sum(svc.connection_count for svc in topology.services)
            lines.append("Summary:")
            lines.append(f"- Total services detected: {len(topology.services)}")
            for idx, service in enumerate(topology.services, start=1):
                proto_str = _format_protocol(service.protocol)
                lines.append(f"- Service {idx} (Port {service.server_port} {proto_str}): {service.connection_count} matched connections")

    lines.append("```")

    return "\n".join(lines)


def format_single_topology(topology: SingleTopologyInfo) -> str:
    """
    Format topology information for a single capture point with multiple services.

    Each service (identified by server port) is displayed separately with its own
    communication path and topology description.
    """
    lines: list[str] = []
    lines.append("```text")
    lines.append(f"Capture Point: {topology.file_name}")
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

            lines.append(f"Clients observed: {client_list}")
            lines.append(f"Servers observed: {server_list}")
            lines.append("")
            lines.append("Communication path:")
            lines.append(_build_single_communication_path_for_service(topology.file_name, service, client_list, server_list))
            lines.append("")
            lines.append(_describe_single_capture_position_for_service(service))
            lines.append("")

        # Summary
        if len(topology.services) > 1:
            total_clients = len({ip for svc in topology.services for ip in svc.client_ips})
            total_servers = len({ip for svc in topology.services for ip in svc.server_ips})
            total_connections = sum(svc.connection_count for svc in topology.services)

            lines.append("Summary:")
            lines.append(f"- Total services detected: {len(topology.services)}")
            lines.append(f"- Total unique client IPs: {total_clients}")
            lines.append(f"- Total unique server IPs: {total_servers}")
            lines.append(f"- Total connections: {total_connections}")

    lines.append("```")
    return "\n".join(lines)


def _describe_single_capture_position(topology: SingleTopologyInfo) -> str:
    client_hops = topology.client_hops
    server_hops = topology.server_hops

    if client_hops is not None and server_hops is not None:
        if client_hops == 0 and server_hops == 0:
            return "Capture Point A is directly adjacent to both the client and the server (no hops observed)."
        if client_hops == 0:
            return (
                "Capture Point A is directly adjacent to the client, 0 hops away from the client "
                f"and {server_hops} hops away from the server."
            )
        if server_hops == 0:
            return (
                "Capture Point A is directly adjacent to the server, "
                f"{client_hops} hops away from the client and 0 hops away from the server."
            )
        return (
            "Capture Point A is between client and server, "
            f"{client_hops} hops away from the client and {server_hops} hops away from the server."
        )

    if client_hops is None and server_hops is None:
        return "TTL data was unavailable to describe Capture Point A's distance to the client or the server."
    if client_hops is None:
        return f"Capture Point A recorded {server_hops} hops away from the server; client TTL data was unavailable."
    return f"Capture Point A recorded {client_hops} hops away from the client; server TTL data was unavailable."


def _build_single_communication_path(topology: SingleTopologyInfo, client_list: str, server_list: str) -> str:
    nodes = [
        f"Client({client_list})",
        f"Capture Point A ({topology.file_name})",
        f"Server({server_list})",
    ]
    edges = [
        topology.client_hops is not None and topology.client_hops > 0,
        topology.server_hops is not None and topology.server_hops > 0,
    ]
    return _join_path_segments(nodes, edges)


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
    client_hops: int
    server_hops: int


CaptureSequence = Tuple[str, str]


def _determine_capture_sequence(position: str) -> CaptureSequence | None:
    if position == "A_CLOSER_TO_CLIENT":
        # Historical behavior: when A is closer to client, topology text shows B -> A.
        return ("B", "A")
    if position == "B_CLOSER_TO_CLIENT":
        return ("A", "B")
    return None


def _build_capture_point_descriptions(
    topology: TopologyInfo,
    sequence: CaptureSequence | None,
) -> list[str]:
    if sequence is None:
        return _build_unknown_descriptions(topology)

    client_label, server_label = sequence
    client_point = _get_capture_point_metrics(topology, client_label)
    server_point = _get_capture_point_metrics(topology, server_label)

    balanced = abs(topology.client_hops_a - topology.client_hops_b) == abs(
        topology.server_hops_a - topology.server_hops_b
    )

    descriptions = [
        "There are two capture points between the client and the server, with a network device between them.",
        _describe_capture_point(client_point, role="client", balanced=balanced),
        _describe_capture_point(server_point, role="server", balanced=balanced),
    ]
    return descriptions


def _get_capture_point_metrics(
    topology: TopologyInfo,
    label: str,
) -> _CapturePointMetrics:
    if label == "A":
        return _CapturePointMetrics(
            "A",
            topology.client_hops_a,
            topology.server_hops_a,
        )
    return _CapturePointMetrics(
        "B",
        topology.client_hops_b,
        topology.server_hops_b,
    )


def _describe_capture_point(
    point: _CapturePointMetrics,
    *,
    role: Literal["client", "server"],
    balanced: bool,
) -> str:
    closer_text = "client" if role == "client" else "server"
    location_text = (
        "between the client and the intermediate network device"
        if role == "client"
        else "between the intermediate network device and the server"
    )

    measurements = _build_measurements(point, role=role, balanced=balanced)
    adjacency_phrase = _build_adjacency_phrase(measurements)
    measurement_text = _format_measurements(measurements)

    sentence = f"Capture Point {point.label} is closer to the {closer_text}, located {location_text}"
    if adjacency_phrase:
        sentence += f", {adjacency_phrase}"
    sentence += f", {measurement_text}."
    return sentence


def _build_measurements(
    point: _CapturePointMetrics,
    *,
    role: Literal["client", "server"],
    balanced: bool,
) -> list[tuple[str, int]]:
    if role == "client":
        second_label = "server" if balanced else "intermediate network device"
        return [("client", point.client_hops), (second_label, point.server_hops)]

    first_label = "client" if balanced else "intermediate network device"
    return [(first_label, point.client_hops), ("server", point.server_hops)]


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


def _build_unknown_descriptions(topology: TopologyInfo) -> list[str]:
    return [
        "TTL data is insufficient to determine capture point ordering.",
        (
            f"Capture Point A observed {topology.client_hops_a} client hops "
            f"and {topology.server_hops_a} server hops."
        ),
        (
            f"Capture Point B observed {topology.client_hops_b} client hops "
            f"and {topology.server_hops_b} server hops."
        ),
    ]


def _build_dual_communication_path(topology: TopologyInfo, sequence: CaptureSequence | None) -> str:
    order = sequence or ("A", "B")
    first_label, second_label = order

    client_ips = _format_ip_list(topology.client_ips_a if first_label == "A" else topology.client_ips_b)
    server_label = "A" if second_label == "A" else "B"
    server_ips = _format_server_list(
        topology.server_ips_a if server_label == "A" else topology.server_ips_b,
        topology.server_ports_a if server_label == "A" else topology.server_ports_b,
    )
    nodes = [
        f"Client({client_ips})",
        _format_capture_label(topology, first_label),
        _format_capture_label(topology, second_label),
        f"Server({server_ips})",
    ]
    edges = [
        _has_client_device(topology, first_label),
        True,
        _has_server_device(topology, second_label),
    ]
    return _join_path_segments(nodes, edges)


def _format_capture_label(topology: TopologyInfo, label: str) -> str:
    file_name = topology.file1_name if label == "A" else topology.file2_name
    return f"Capture Point {label} ({file_name})"


def _has_client_device(topology: TopologyInfo, label: str) -> bool:
    hops = topology.client_hops_a if label == "A" else topology.client_hops_b
    return bool(hops and hops > 0)


def _has_server_device(topology: TopologyInfo, label: str) -> bool:
    hops = topology.server_hops_a if label == "A" else topology.server_hops_b
    return bool(hops and hops > 0)


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
) -> str:
    """Build communication path for a single service in single-capture scenario."""
    nodes = [
        f"Client({client_list})",
        f"Capture Point A ({file_name})",
        f"Server({server_list})",
    ]
    edges = [
        service.client_hops is not None and service.client_hops > 0,
        service.server_hops is not None and service.server_hops > 0,
    ]
    return _join_path_segments(nodes, edges)


def _describe_single_capture_position_for_service(service: ServiceTopologyInfo) -> str:
    """Describe capture point position for a single service."""
    client_hops = service.client_hops
    server_hops = service.server_hops

    if client_hops is not None and server_hops is not None:
        if client_hops == 0 and server_hops == 0:
            return "Capture Point A is directly adjacent to both the client and the server (no hops observed)."
        if client_hops == 0:
            return (
                "Capture Point A is directly adjacent to the client, 0 hops away from the client "
                f"and {server_hops} hops away from the server."
            )
        if server_hops == 0:
            return (
                "Capture Point A is directly adjacent to the server, "
                f"{client_hops} hops away from the client and 0 hops away from the server."
            )
        return (
            "Capture Point A is between client and server, "
            f"{client_hops} hops away from the client and {server_hops} hops away from the server."
        )

    if client_hops is None and server_hops is None:
        return "TTL data was unavailable to describe Capture Point A's distance to the client or the server."
    if client_hops is None:
        return f"Capture Point A recorded {server_hops} hops away from the server; client TTL data was unavailable."
    return f"Capture Point A recorded {client_hops} hops away from the client; server TTL data was unavailable."


def _build_dual_communication_path_for_service(
    file1_name: str,
    file2_name: str,
    service: ServiceTopologyInfoDual,
    sequence: tuple[str, str] | None,
) -> str:
    """Build communication path for a single service in dual-capture scenario."""
    order = sequence or ("A", "B")
    first_label, second_label = order

    client_ips = _format_ip_list(service.client_ips_a if first_label == "A" else service.client_ips_b)
    server_label = "A" if second_label == "A" else "B"
    server_ips = _format_server_list_single_port(
        service.server_ips_a if server_label == "A" else service.server_ips_b,
        service.server_port,
    )

    nodes = [
        f"Client({client_ips})",
        f"Capture Point {first_label} ({file1_name if first_label == 'A' else file2_name})",
        f"Capture Point {second_label} ({file1_name if second_label == 'A' else file2_name})",
        f"Server({server_ips})",
    ]
    edges = [
        _has_client_device_for_service(service, first_label),
        True,
        _has_server_device_for_service(service, second_label),
    ]
    return _join_path_segments(nodes, edges)


def _has_client_device_for_service(service: ServiceTopologyInfoDual, label: str) -> bool:
    """Check if there's a network device between capture point and client for a service."""
    hops = service.client_hops_a if label == "A" else service.client_hops_b
    return bool(hops and hops > 0)


def _has_server_device_for_service(service: ServiceTopologyInfoDual, label: str) -> bool:
    """Check if there's a network device between capture point and server for a service."""
    hops = service.server_hops_a if label == "A" else service.server_hops_b
    return bool(hops and hops > 0)


def _build_capture_point_descriptions_for_service(
    service: ServiceTopologyInfoDual,
    sequence: tuple[str, str] | None,
) -> list[str]:
    """Build capture point descriptions for a single service."""
    if sequence is None:
        return _build_unknown_descriptions_for_service(service)

    client_label, server_label = sequence
    client_point = _get_capture_point_metrics_for_service(service, client_label)
    server_point = _get_capture_point_metrics_for_service(service, server_label)

    balanced = abs(service.client_hops_a - service.client_hops_b) == abs(
        service.server_hops_a - service.server_hops_b
    )

    descriptions = [
        "There are two capture points between the client and the server, with a network device between them.",
        _describe_capture_point(client_point, role="client", balanced=balanced),
        _describe_capture_point(server_point, role="server", balanced=balanced),
    ]
    return descriptions


def _get_capture_point_metrics_for_service(
    service: ServiceTopologyInfoDual,
    label: str,
) -> _CapturePointMetrics:
    """Get capture point metrics for a service."""
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
    """Build descriptions when position cannot be determined for a service."""
    return [
        "TTL data is insufficient to determine capture point ordering.",
        (
            f"Capture Point A observed {service.client_hops_a} client hops "
            f"and {service.server_hops_a} server hops."
        ),
        (
            f"Capture Point B observed {service.client_hops_b} client hops "
            f"and {service.server_hops_b} server hops."
        ),
    ]
