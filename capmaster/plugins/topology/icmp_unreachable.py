from __future__ import annotations

"""ICMP type 3 (Destination Unreachable) helpers for single-capture topology.

This module extracts ICMP type 3 messages and aggregates them into
IcmpUnreachableEvent structures for use by the topology single-capture
pipeline, as described in docs/TOPOLOGY_UDP_AND_ICMP_DESIGN.md.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from capmaster.core.tshark_wrapper import TsharkWrapper
from capmaster.plugins.match.ttl_utils import most_common_hops


@dataclass
class IcmpUnreachablePacket:
    """Raw ICMP unreachable observation parsed from tshark output.

    Combines inner (embedded original IP/TCP/UDP 5-tuple) and outer
    (ICMP message carrier) information for topology analysis. Outer
    fields may be None when they cannot be reliably extracted.
    """

    client_ip: str
    reporter_ip: str | None
    reported_to_ip: str | None
    icmp_code: int
    inner_dst_ip: str
    inner_protocol: int
    inner_dst_port: int
    reporter_ttl: int | None


@dataclass
class IcmpUnreachableEvent:
    """Aggregated ICMP unreachable event for topology output."""

    client_ip: str
    reporter_ip: str | None
    reported_to_ip: str | None
    icmp_code: int
    inner_dst_ip: str
    inner_protocol: int
    inner_dst_port: int
    count: int
    hops_from_reporter: int | None


class IcmpUnreachableExtractor:
    """Extract ICMP type 3 unreachable packets using tshark.

    Field selection is intentionally aligned with IcmpStatsModule to avoid
    relying on icmp.ip.* derived fields that may not exist in all tshark
    versions.
    """

    def __init__(self, wrapper: TsharkWrapper | None = None) -> None:
        self._wrapper = wrapper or TsharkWrapper()

    def _build_tshark_args(self) -> list[str]:
        """Build tshark args for ICMP unreachable extraction.

        We request both the embedded (inner) 5-tuple and the outer ICMP
        carrier header in a single pass, relying on multi-valued ip.* fields
        (``-E occurrence=a``) and protocol semantics (1 = ICMP, 6 = TCP,
        17 = UDP) to distinguish the layers.
        """

        return [
            "-Y",
            "icmp",
            "-T",
            "fields",
            # Protocol stack (may contain values like "1,6" for ICMP + embedded TCP)
            "-e",
            "ip.proto",
            # All observed IPv4 src/dst/ttl values (outer + inner)
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "ip.ttl",
            # Transport-layer ports from the embedded original packet
            "-e",
            "tcp.srcport",
            "-e",
            "udp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.dstport",
            "-e",
            "icmp.type",
            "-e",
            "icmp.code",
            "-E",
            "occurrence=a",
            "-E",
            "separator=\t",
        ]

    def extract(self, pcap_file: Path) -> Iterable[IcmpUnreachablePacket]:
        args = self._build_tshark_args()
        result = self._wrapper.execute(args, input_file=pcap_file, output_file=None, timeout=None)

        for line in result.stdout.splitlines():
            if not line.strip():
                continue

            parts = line.split("\t")
            # Expect at least: proto, ip.src, ip.dst, ip.ttl, ports, icmp.type, icmp.code
            if len(parts) < 8:
                continue

            try:
                proto_field = parts[0]
                src_field = parts[1]
                dst_field = parts[2]
                ttl_field = parts[3]
                tcp_sport_field = parts[4]
                udp_sport_field = parts[5]
                tcp_dport_field = parts[6]
                udp_dport_field = parts[7]
                icmp_type_field = parts[8] if len(parts) > 8 else ""
                icmp_code_field = parts[9] if len(parts) > 9 else ""

                # Only keep type 3 (Destination Unreachable) here; other ICMP
                # types are out of scope for this topology view.
                icmp_type_vals = (icmp_type_field or "").split(",") if icmp_type_field else [""]
                if not any(v == "3" for v in icmp_type_vals):
                    continue

                # icmp.code should normally have a single value; if multiple
                # values appear we conservatively take the last one.
                icmp_code = int((icmp_code_field or "0").split(",")[-1] or 0)

                # Multi-valued IP fields use comma as the occurrence separator.
                proto_vals = (proto_field or "").split(",") if proto_field else []
                src_vals = (src_field or "").split(",") if src_field else []
                dst_vals = (dst_field or "").split(",") if dst_field else []
                ttl_vals = (ttl_field or "").split(",") if ttl_field else []

                # Identify outer (ICMP) and inner (TCP/UDP) indices by protocol
                outer_index = next((i for i, v in enumerate(proto_vals) if v == "1"), None)
                inner_index = next((i for i, v in enumerate(proto_vals) if v in {"6", "17"}), None)

                if outer_index is None or inner_index is None:
                    # Cannot confidently distinguish layers; skip this packet to
                    # avoid fabricating incorrect topology.
                    continue

                # Bounds check for safety
                def _safe_get(values: list[str], idx: int) -> str | None:
                    return values[idx] if 0 <= idx < len(values) and values[idx] else None

                outer_src_ip = _safe_get(src_vals, outer_index)
                outer_dst_ip = _safe_get(dst_vals, outer_index)
                inner_src_ip = _safe_get(src_vals, inner_index)
                inner_dst_ip = _safe_get(dst_vals, inner_index)

                outer_ttl_raw = _safe_get(ttl_vals, outer_index)
                reporter_ttl = int(outer_ttl_raw) if outer_ttl_raw and outer_ttl_raw.isdigit() else None

                # Sanity check: for a "normal" ICMP unreachable, the outer
                # destination should be the original sender (inner src).
                if not outer_dst_ip or not inner_src_ip or outer_dst_ip != inner_src_ip:
                    # If this invariant does not hold, we treat outer header as
                    # unreliable and skip the packet.
                    continue

                tcp_sport_vals = (tcp_sport_field or "").split(",") if tcp_sport_field else []
                udp_sport_vals = (udp_sport_field or "").split(",") if udp_sport_field else []
                tcp_dport_vals = (tcp_dport_field or "").split(",") if tcp_dport_field else []
                udp_dport_vals = (udp_dport_field or "").split(",") if udp_dport_field else []

                def _safe_int_from(vals: list[str], idx: int) -> int:
                    if 0 <= idx < len(vals) and vals[idx]:
                        try:
                            return int(vals[idx])
                        except ValueError:
                            return 0
                    return 0

                proto = int(proto_vals[inner_index]) if proto_vals[inner_index].isdigit() else 0
                tcp_sport = _safe_int_from(tcp_sport_vals, 1 if len(tcp_sport_vals) > 1 else 0)
                udp_sport = _safe_int_from(udp_sport_vals, 1 if len(udp_sport_vals) > 1 else 0)
                tcp_dport = _safe_int_from(tcp_dport_vals, 1 if len(tcp_dport_vals) > 1 else 0)
                udp_dport = _safe_int_from(udp_dport_vals, 1 if len(udp_dport_vals) > 1 else 0)

                if not inner_src_ip or not inner_dst_ip:
                    continue

            except Exception:
                # Be conservative: on any unexpected parsing issue, skip the
                # packet rather than emitting potentially misleading topology.
                continue

            client_ip = inner_src_ip
            inner_protocol = proto
            inner_dst_port = tcp_dport or udp_dport or 0

            yield IcmpUnreachablePacket(
                client_ip=client_ip,
                reporter_ip=outer_src_ip,
                reported_to_ip=outer_dst_ip,
                icmp_code=icmp_code,
                inner_dst_ip=inner_dst_ip,
                inner_protocol=inner_protocol,
                inner_dst_port=inner_dst_port,
                reporter_ttl=reporter_ttl,
            )


def extract_icmp_unreachable_events(pcap_file: Path) -> List[IcmpUnreachableEvent]:
    """Aggregate ICMP unreachable packets into events for topology.

    Events are keyed by (client_ip, reporter_ip, icmp_code, inner_dst_ip,
    inner_protocol, inner_dst_port) as specified in the design doc. Outer
    destination IP and TTL samples are aggregated as attributes of the
    resulting event rather than additional key dimensions.
    """

    extractor = IcmpUnreachableExtractor()
    # Keep reporter_ip in the aggregation key so that future scenarios with
    # multiple reporters for the same inner flow can be distinguished.
    agg: Dict[Tuple[str, str | None, int, str, int, int], Dict[str, object]] = {}

    for pkt in extractor.extract(pcap_file):
        key = (
            pkt.client_ip,
            pkt.reporter_ip,
            pkt.icmp_code,
            pkt.inner_dst_ip,
            pkt.inner_protocol,
            pkt.inner_dst_port,
        )
        if key not in agg:
            agg[key] = {"count": 0, "ttls": [], "reported_to_ips": []}
        bucket = agg[key]
        bucket["count"] = int(bucket["count"]) + 1
        if pkt.reporter_ttl is not None and pkt.reporter_ttl > 0:
            bucket["ttls"].append(pkt.reporter_ttl)
        if pkt.reported_to_ip:
            bucket["reported_to_ips"].append(pkt.reported_to_ip)

    events: List[IcmpUnreachableEvent] = []
    for (client_ip, reporter_ip, icmp_code, inner_dst_ip, inner_protocol, inner_dst_port), data in agg.items():
        ttls = data["ttls"]  # type: ignore[assignment]
        hops = most_common_hops(ttls) if ttls else None
        reported_to_ips = data["reported_to_ips"]  # type: ignore[assignment]
        reported_to_ip: str | None
        if reported_to_ips:
            # Use the most frequently observed destination as representative.
            # This guards against noise while remaining stable for the common
            # case where all ICMP messages share the same outer destination.
            freq: Dict[str, int] = {}
            for ip in reported_to_ips:
                freq[ip] = freq.get(ip, 0) + 1
            reported_to_ip = max(freq.items(), key=lambda kv: kv[1])[0]
        else:
            reported_to_ip = None

        events.append(
            IcmpUnreachableEvent(
                client_ip=client_ip,
                reporter_ip=reporter_ip,
                reported_to_ip=reported_to_ip,
                icmp_code=icmp_code,
                inner_dst_ip=inner_dst_ip,
                inner_protocol=inner_protocol,
                inner_dst_port=inner_dst_port,
                count=int(data["count"]),
                hops_from_reporter=hops,
            )
        )

    events.sort(
        key=lambda e: (
            e.client_ip,
            e.inner_dst_ip,
            e.inner_protocol,
            e.inner_dst_port,
            e.icmp_code,
        )
    )
    return events

