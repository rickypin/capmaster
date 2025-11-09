"""TCP completeness statistics module."""

from __future__ import annotations
import re
from collections import defaultdict
from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class TcpCompletenessModule(AnalysisModule):
    """Generate TCP completeness statistics.

    Uses two-pass analysis to extract tcp.completeness.str flags,
    then decodes and categorizes TCP connections:
    - Status: Complete, Established, Half-open, Unknown
    - Data: WITH_DATA, NO_DATA
    - Closure: CLOSED, NOT_CLOSED

    Uses defaultdict for grouping and custom flag decoding logic.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "tcp_completeness"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "tcp-completeness.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"tcp"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Uses two-pass analysis (-2) to extract tcp.completeness.str

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for TCP completeness analysis
        """
        return [
            "-2",  # Two-pass analysis
            "-Y",
            "tcp",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "tcp.stream",
            "-e",
            "tcp.completeness.str",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "ipv6.src",
            "-e",
            "ipv6.dst",
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process TCP completeness data to categorize connections.

        Decodes tcp.completeness.str flags and categorizes connections.

        Args:
            tshark_output: Raw tshark output (tab-separated fields)
            output_format: Output format ("txt" or "md", default: "txt")

        Returns:
            Formatted output with connections grouped by status/data/closure
        """
        # Storage: {(status, flags, count): [connection_list]}
        categories: dict[tuple[str, str], list[str]] = defaultdict(list)
        seen_streams: set[int] = set()
        stream_data: dict[int, tuple[str, str]] = {}  # stream_id -> (completeness, direction)

        for line in tshark_output.strip().split('\n'):
            if not line.strip():
                continue

            parts = line.split('\t')
            if len(parts) < 8:
                continue

            stream_id = int(parts[0]) if parts[0] else -1
            completeness = parts[1] if parts[1] else ""
            ip_src = parts[2] if parts[2] else parts[6]  # IPv4 or IPv6
            src_port = parts[3] if parts[3] else ""
            ip_dst = parts[4] if parts[4] else parts[7]  # IPv4 or IPv6
            dst_port = parts[5] if parts[5] else ""

            if stream_id < 0 or stream_id in seen_streams:
                continue

            seen_streams.add(stream_id)
            direction = f"{ip_src}:{src_port} -> {ip_dst}:{dst_port}"
            stream_data[stream_id] = (completeness, direction)

        # Decode completeness flags and categorize
        for stream_id, (comp, direction) in stream_data.items():
            status, data_type = self._decode_completeness(comp)
            # Combine status and data_type for the key
            status_label = f"{status}, {data_type}"
            key = (status_label, comp)
            categories[key].append(direction)

        # Generate output
        lines = []
        for (status_label, flags), connections in sorted(categories.items()):
            count = len(connections)
            lines.append(f"[Status: {status_label}] [Flags: {flags}] [Count: {count} connections]")
            for conn in connections:
                lines.append(conn)
            lines.append("")  # Empty line between categories

        return '\n'.join(lines)

    def _decode_completeness(self, flags: str) -> tuple[str, str]:
        """
        Decode tcp.completeness.str flags.

        Flags format: e.g., "RSN|A|D" where:
        - R: RST seen
        - F: FIN seen
        - D: Data seen
        - A: ACK seen
        - S (position 5): SYN from server
        - S (position 6): SYN from client

        Args:
            flags: tcp.completeness.str value

        Returns:
            Tuple of (status, data_closure_type)
            - status: Complete, Established, Half-open, Unknown
            - data_closure_type: WITH_DATA_CLOSED, NO_DATA_CLOSED, WITH_DATA, NO_DATA
        """
        has_rst = 'R' in flags
        has_fin = 'F' in flags
        has_data = 'D' in flags
        has_ack = 'A' in flags

        # Check SYN flags (positions 5 and 6 in original AWK)
        # Simplified: check if both SYN directions present
        syn_server = len(flags) > 4 and flags[4] == 'S'
        syn_client = len(flags) > 5 and flags[5] == 'S'

        # Determine status
        if syn_client and syn_server and has_ack:
            status = "Complete"
        elif syn_client and has_ack:
            status = "Established"
        elif syn_client:
            status = "Half-open"
        else:
            status = "Unknown"

        # Determine data/closure type
        is_closed = has_fin or has_rst
        if is_closed:
            data_type = "WITH_DATA_CLOSED" if has_data else "NO_DATA_CLOSED"
        else:
            data_type = "WITH_DATA" if has_data else "NO_DATA"

        return status, data_type
