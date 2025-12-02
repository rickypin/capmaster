from __future__ import annotations

"""UDP extraction and aggregation helpers for single-capture topology.

This module intentionally keeps the UDP model lightweight:
- We do not build full UDP "connections".
- We only aggregate per server port (dst_port) into ServiceTopologyInfo-like
  structures that the topology.runner can merge with existing TCP services.

Implementation follows docs/TOPOLOGY_UDP_AND_ICMP_DESIGN.md.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from capmaster.core.tshark_wrapper import TsharkWrapper
from capmaster.plugins.compare_common.flow_hash import FlowSide, calculate_flow_hash
from capmaster.plugins.match.ttl_utils import most_common_hops
from capmaster.plugins.topology.analysis import ServiceTopologyInfo


@dataclass
class UdpPacket:
    """Lightweight representation of a single UDP packet for topology use."""

    frame_number: int
    timestamp: float
    protocol: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ttl: int | None
    stream_id: int | None


class UdpFieldExtractor:
    """Extract UDP packets from a PCAP using tshark.

    The goal is to provide just enough information for per-port aggregation
    without introducing a full UDP connection builder.
    """

    def __init__(self, wrapper: TsharkWrapper | None = None) -> None:
        self._wrapper = wrapper or TsharkWrapper()

    def extract(self, pcap_file: Path) -> Iterable[UdpPacket]:
        args = [
            "-Y",
            "udp",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.proto",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "udp.srcport",
            "-e",
            "udp.dstport",
            "-e",
            "ip.ttl",
            "-e",
            "udp.stream",
        ]
        result = self._wrapper.execute(args, input_file=pcap_file, output_file=None, timeout=None)
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 9:
                # Be tolerant to missing fields; skip malformed lines.
                continue
            try:
                frame_number = int(parts[0]) if parts[0] else 0
                timestamp = float(parts[1]) if parts[1] else 0.0
                proto = int(parts[2]) if parts[2] else 17
                src_ip = parts[3]
                dst_ip = parts[4]
                src_port = int(parts[5]) if parts[5] else 0
                dst_port = int(parts[6]) if parts[6] else 0
                ttl = int(parts[7]) if parts[7] else None
                stream_id = int(parts[8]) if parts[8] else None
            except ValueError:
                continue
            yield UdpPacket(
                frame_number=frame_number,
                timestamp=timestamp,
                protocol=proto,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                ttl=ttl,
                stream_id=stream_id,
            )


@dataclass
class UdpFlowEndpointStats:
    """Per-endpoint statistics within a UDP flow.

    These stats are intentionally simple – they are only used by the UDP
    server detector to guess which side behaves more like a server.
    """

    ip: str
    port: int
    packet_count: int = 0


@dataclass
class UdpFlow:
    """Bidirectional UDP flow identified by a normalized 5-tuple hash."""

    flow_hash: int
    protocol: int
    endpoint_a: UdpFlowEndpointStats
    endpoint_b: UdpFlowEndpointStats
    # TTL samples from both logical directions; used for hops estimation.
    a_ttls: List[int]
    b_ttls: List[int]

    def add_packet(self, packet: UdpPacket, side: FlowSide) -> None:
        """Add a packet to this flow and update endpoint statistics.

        Args:
            packet: Original UDP packet.
            side: Which side of the normalized flow the packet's (src_ip, src_port)
                pair corresponds to (LHS or RHS). This is derived from
                :func:`calculate_flow_hash`.
        """

        if side == FlowSide.LHS_GE_RHS:
            if packet.src_ip == self.endpoint_a.ip and packet.src_port == self.endpoint_a.port:
                self.endpoint_a.packet_count += 1
                if packet.ttl is not None and packet.ttl > 0:
                    self.a_ttls.append(packet.ttl)
            else:
                self.endpoint_b.packet_count += 1
                if packet.ttl is not None and packet.ttl > 0:
                    self.b_ttls.append(packet.ttl)
        else:
            if packet.src_ip == self.endpoint_b.ip and packet.src_port == self.endpoint_b.port:
                self.endpoint_b.packet_count += 1
                if packet.ttl is not None and packet.ttl > 0:
                    self.b_ttls.append(packet.ttl)
            else:
                self.endpoint_a.packet_count += 1
                if packet.ttl is not None and packet.ttl > 0:
                    self.a_ttls.append(packet.ttl)


@dataclass
class UdpServerInfo:
    """Server detection result for a single UDP flow."""

    server_ip: str
    server_port: int
    client_ip: str
    client_port: int


class UdpServerDetector:
    """Heuristic UDP server detector operating on :class:`UdpFlow`.

    Current strategy (kept deliberately simple and deterministic):

    1. If exactly one endpoint uses a well-known UDP port, that endpoint is
       treated as the server.
    2. Otherwise, fall back to the endpoint with the smaller port number.

    This is sufficient to fix DNS-style cases where responses to ephemeral
    client ports were previously misinterpreted as separate services, while
    remaining robust for generic client/server UDP traffic.
    """

    WELL_KNOWN_UDP_PORTS = {
        53,  # DNS
        67,
        68,  # DHCP
        69,  # TFTP
        123,  # NTP
        161,
        162,  # SNMP
        500,  # IKE
        514,  # Syslog
        1812,
        1813,  # RADIUS
    }

    def detect(self, flow: UdpFlow) -> UdpServerInfo:
        a = flow.endpoint_a
        b = flow.endpoint_b

        a_is_well_known = a.port in self.WELL_KNOWN_UDP_PORTS
        b_is_well_known = b.port in self.WELL_KNOWN_UDP_PORTS

        if a_is_well_known and not b_is_well_known:
            server, client = a, b
        elif b_is_well_known and not a_is_well_known:
            server, client = b, a
        else:
            # Fallback: smaller port is more likely to be the server.
            if a.port <= b.port:
                server, client = a, b
            else:
                server, client = b, a

        return UdpServerInfo(
            server_ip=server.ip,
            server_port=server.port,
            client_ip=client.ip,
            client_port=client.port,
        )


def _build_udp_flows(pcap_file: Path) -> Dict[int, UdpFlow]:
    """Group UDP packets from a PCAP into bidirectional flows.

    Flows are keyed by the bidirectional hash returned from
    :func:`calculate_flow_hash` so that packets from both directions share
    the same :class:`UdpFlow` instance.
    """

    extractor = UdpFieldExtractor()
    flows: Dict[int, UdpFlow] = {}

    for packet in extractor.extract(pcap_file):
        if packet.src_port <= 0 or packet.dst_port <= 0:
            # Ignore malformed packets with missing ports.
            continue

        flow_hash, side = calculate_flow_hash(
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            protocol=packet.protocol,
        )

        if flow_hash not in flows:
            # Determine normalized endpoint ordering based on flow side.
            if side == FlowSide.LHS_GE_RHS:
                endpoint_a = UdpFlowEndpointStats(ip=packet.src_ip, port=packet.src_port, packet_count=0)
                endpoint_b = UdpFlowEndpointStats(ip=packet.dst_ip, port=packet.dst_port, packet_count=0)
            else:
                endpoint_a = UdpFlowEndpointStats(ip=packet.dst_ip, port=packet.dst_port, packet_count=0)
                endpoint_b = UdpFlowEndpointStats(ip=packet.src_ip, port=packet.src_port, packet_count=0)

            flows[flow_hash] = UdpFlow(
                flow_hash=flow_hash,
                protocol=packet.protocol,
                endpoint_a=endpoint_a,
                endpoint_b=endpoint_b,
                a_ttls=[],
                b_ttls=[],
            )

        flows[flow_hash].add_packet(packet, side)

    return flows



def extract_udp_services_for_topology(pcap_file: Path) -> List[ServiceTopologyInfo]:
    """Extract UDP services from a PCAP for single-capture topology.

    This implementation first groups packets into bidirectional 5-tuple flows
    and then runs a UDP-specific server detector per flow to decide which
    endpoint is the server. The final aggregation is done per
    ``(server_port, protocol=17)`` so that DNS-like traffic only produces a
    single ``Port 53 (UDP)`` service instead of additional ephemeral-port
    services.
    """

    flows = _build_udp_flows(pcap_file)
    detector = UdpServerDetector()

    # key: (server_port, protocol)
    service_data: Dict[Tuple[int, int], dict] = {}

    for flow in flows.values():
        info = detector.detect(flow)
        key = (info.server_port, flow.protocol)
        if key not in service_data:
            service_data[key] = {
                "client_ips": set(),
                "server_ips": set(),
                "client_ttls": [],
                "server_ttls": [],
                "count": 0,
            }

        bucket = service_data[key]
        bucket["client_ips"].add(info.client_ip)
        bucket["server_ips"].add(info.server_ip)
        bucket["count"] += 1

        # Map TTL samples from flow endpoints into client/server hops.
        if info.client_ip == flow.endpoint_a.ip and info.client_port == flow.endpoint_a.port:
            bucket["client_ttls"].extend(flow.a_ttls)
            bucket["server_ttls"].extend(flow.b_ttls)
        else:
            bucket["client_ttls"].extend(flow.b_ttls)
            bucket["server_ttls"].extend(flow.a_ttls)

    services: List[ServiceTopologyInfo] = []
    for (server_port, protocol), data in service_data.items():
        services.append(
            ServiceTopologyInfo(
                server_port=server_port,
                protocol=protocol,
                client_ips=data["client_ips"],
                server_ips=data["server_ips"],
                client_hops=most_common_hops(data["client_ttls"]) if data["client_ttls"] else None,
                server_hops=most_common_hops(data["server_ttls"]) if data["server_ttls"] else None,
                connection_count=data["count"],
            )
        )

    services.sort(key=lambda s: (s.protocol, s.server_port))
    return services
