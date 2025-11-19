from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Tuple

from capmaster.core.connection.matcher import ConnectionMatch
from capmaster.plugins.match.endpoint_stats import EndpointStatsCollector
from capmaster.plugins.match.server_detector import ServerDetector


class TopologyAnalyzer:
    def __init__(self, matches: list[ConnectionMatch], file1: Path, file2: Path, service_list: Path | None = None):
        self.matches = matches
        self.file1 = file1
        self.file2 = file2
        self.service_list = service_list

    def analyze(self) -> TopologyInfo:
        # Create detector and collector for endpoint statistics
        detector = ServerDetector(service_list_path=self.service_list)
        collector = EndpointStatsCollector(detector)

        # Add all matches
        for match in self.matches:
            collector.add_match(match)

        # Finalize collection (performs cardinality analysis)
        collector.finalize()

        # Get aggregated statistics
        stats = collector.get_stats()

        if not stats:
            return TopologyInfo(
                file1_name=self.file1.name,
                file2_name=self.file2.name,
                client_ips_a=set(),
                client_ips_b=set(),
                server_ips_a=set(),
                server_ips_b=set(),
                server_ports_a=set(),
                server_ports_b=set(),
                client_hops_a=0,
                server_hops_a=0,
                client_hops_b=0,
                server_hops_b=0,
                position="UNKNOWN",
            )

        # Collect unique IPs and ports
        client_ips_a = {stat.tuple_a.client_ip for stat in stats}
        client_ips_b = {stat.tuple_b.client_ip for stat in stats}
        server_ips_a = {stat.tuple_a.server_ip for stat in stats}
        server_ips_b = {stat.tuple_b.server_ip for stat in stats}
        server_ports_a = {stat.tuple_a.server_port for stat in stats}
        server_ports_b = {stat.tuple_b.server_port for stat in stats}

        # Use the first stat for TTL/hops information (most common pattern)
        first_stat = stats[0]
        client_hops_a = first_stat.client_hops_a
        server_hops_a = first_stat.server_hops_a
        client_hops_b = first_stat.client_hops_b
        server_hops_b = first_stat.server_hops_b

        # Determine network position
        position = self._determine_position(
            client_hops_a, server_hops_a, client_hops_b, server_hops_b
        )

        return TopologyInfo(
            file1_name=self.file1.name,
            file2_name=self.file2.name,
            client_ips_a=client_ips_a,
            client_ips_b=client_ips_b,
            server_ips_a=server_ips_a,
            server_ips_b=server_ips_b,
            server_ports_a=server_ports_a,
            server_ports_b=server_ports_b,
            client_hops_a=client_hops_a,
            server_hops_a=server_hops_a,
            client_hops_b=client_hops_b,
            server_hops_b=server_hops_b,
            position=position,
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


class TopologyInfo:
    def __init__(
        self,
        file1_name: str,
        file2_name: str,
        client_ips_a: set[str],
        client_ips_b: set[str],
        server_ips_a: set[str],
        server_ips_b: set[str],
        server_ports_a: set[int],
        server_ports_b: set[int],
        client_hops_a: int,
        server_hops_a: int,
        client_hops_b: int,
        server_hops_b: int,
        position: str,
    ):
        self.file1_name = file1_name
        self.file2_name = file2_name
        self.client_ips_a = client_ips_a
        self.client_ips_b = client_ips_b
        self.server_ips_a = server_ips_a
        self.server_ips_b = server_ips_b
        self.server_ports_a = server_ports_a
        self.server_ports_b = server_ports_b
        self.client_hops_a = client_hops_a
        self.server_hops_a = server_hops_a
        self.client_hops_b = client_hops_b
        self.server_hops_b = server_hops_b
        self.position = position


@dataclass
class SingleTopologyInfo:
    file_name: str
    client_ips: set[str]
    server_ips: set[str]
    server_ports: set[int]
    client_hops: int | None
    server_hops: int | None


def format_topology(topology: TopologyInfo) -> str:
    """Format topology information as a human-readable string."""
    lines = []

    # Content in code block
    lines.append("```text")
    lines.append(f"Capture Point A: {topology.file1_name}")
    lines.append(f"Capture Point B: {topology.file2_name}")
    lines.append("")

    sequence = _determine_capture_sequence(topology.position)
    lines.append("Communication path:")
    lines.append(_build_dual_communication_path(topology, sequence))
    lines.append("")

    if sequence is None:
        lines.append("Topology: Cannot determine (same position or insufficient TTL data)")
        lines.append("")
        lines.append(f"File A: Clients {_format_ip_list(topology.client_ips_a)} -> Servers {_format_server_list(topology.server_ips_a, topology.server_ports_a)}")
        lines.append(f"File B: Clients {_format_ip_list(topology.client_ips_b)} -> Servers {_format_server_list(topology.server_ips_b, topology.server_ports_b)}")

    description_lines = _build_capture_point_descriptions(topology, sequence)
    if description_lines:
        lines.append("")
        lines.extend(description_lines)

    lines.append("```")

    return "\n".join(lines)


def format_single_topology(topology: SingleTopologyInfo) -> str:
    """Format topology information for a single capture point."""
    lines: list[str] = []
    lines.append("```text")
    lines.append(f"Capture Point: {topology.file_name}")
    lines.append("")

    if not topology.client_ips and not topology.server_ips:
        lines.append("No TCP connections detected in this capture.")
    else:
        client_list = _format_ip_list(topology.client_ips)
        server_list = _format_server_list(topology.server_ips, topology.server_ports)
        lines.append("Topology (single capture):")
        lines.append(f"Clients observed: {client_list}")
        lines.append(f"Servers observed: {server_list}")
        lines.append("")
        lines.append("Communication path:")
        lines.append(_build_single_communication_path(topology, client_list, server_list))
        lines.append("")
        lines.append(_describe_single_capture_position(topology))

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
