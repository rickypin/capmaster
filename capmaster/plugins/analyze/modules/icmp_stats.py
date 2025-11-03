"""ICMP messages statistics module."""

from collections import defaultdict
from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class IcmpStatsModule(AnalysisModule):
    """Generate ICMP message statistics with type/code decoding.

    Extracts ICMP messages and decodes type/code combinations into
    human-readable descriptions. For error messages (type 3, 11, etc.),
    also extracts embedded protocol information (TCP/UDP 5-tuples).

    Uses a comprehensive ICMP_TYPES mapping dictionary and defaultdict
    for grouping messages by type.
    """

    # ICMP type/code descriptions
    ICMP_TYPES = {
        "0:0": "Echo Reply",
        "3:0": "Net Unreachable",
        "3:1": "Host Unreachable",
        "3:2": "Protocol Unreachable",
        "3:3": "Port Unreachable",
        "3:4": "Fragmentation Needed",
        "3:5": "Source Route Failed",
        "3:6": "Net Unknown",
        "3:7": "Host Unknown",
        "3:9": "Net Prohibited",
        "3:10": "Host Prohibited",
        "3:13": "Communication Prohibited",
        "4:0": "Source Quench",
        "5:0": "Redirect Network",
        "5:1": "Redirect Host",
        "8:0": "Echo Request",
        "9:0": "Router Advertisement",
        "10:0": "Router Solicitation",
        "11:0": "TTL Exceeded",
        "11:1": "Fragment Reassembly Timeout",
        "12:0": "IP Header Error",
        "13:0": "Timestamp Request",
        "14:0": "Timestamp Reply",
    }

    # ICMP types that have embedded protocol info
    TYPES_WITH_EMBED = {"3", "4", "5", "11", "12"}

    # Protocol numbers
    PROTO_NAMES = {
        "1": "ICMP",
        "6": "TCP",
        "17": "UDP",
    }

    @property
    def name(self) -> str:
        """Module name."""
        return "icmp_stats"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "icmp-messages.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"icmp"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for ICMP message extraction
        """
        return [
            "-Y",
            "icmp",
            "-T",
            "fields",
            "-e",
            "icmp.type",
            "-e",
            "icmp.code",
            "-e",
            "ip.proto",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "udp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.dstport",
            "-E",
            "occurrence=l",
            "-E",
            "separator=,",
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process ICMP messages to decode types/codes and extract embedded protocols.

        Categorizes ICMP messages into:
        - Error messages with embedded protocol info (Type 3, 4, 5, 11, 12)
        - Informational messages (Type 0, 8, 9, 10, 13, 14)

        Args:
            tshark_output: Raw tshark output (comma-separated fields)
            output_format: Output format ("txt" or "md", default: "txt")

        Returns:
            Formatted output with ICMP messages categorized and decoded
        """
        # Storage for error messages with embedded protocol
        error_msgs: dict[tuple[str, str, str, str], int] = defaultdict(int)

        # Storage for informational messages
        info_msgs: dict[str, int] = defaultdict(int)

        for line in tshark_output.strip().split('\n'):
            if not line.strip():
                continue

            parts = line.split(',')
            if len(parts) < 9:
                continue

            icmp_type = parts[0] if parts[0] else ""
            icmp_code = parts[1] if parts[1] else ""
            proto = parts[2] if parts[2] else ""
            src_ip = parts[3] if parts[3] else ""
            tcp_sport = parts[4] if parts[4] else ""
            udp_sport = parts[5] if parts[5] else ""
            dst_ip = parts[6] if parts[6] else ""
            tcp_dport = parts[7] if parts[7] else ""
            udp_dport = parts[8] if parts[8] else ""

            if not icmp_type:
                continue

            tc_key = f"{icmp_type}:{icmp_code}"

            # Check if this type has embedded protocol info
            if icmp_type in self.TYPES_WITH_EMBED:
                # Has embedded protocol
                sport = tcp_sport if tcp_sport else udp_sport
                dport = tcp_dport if tcp_dport else udp_dport

                if sport and dport:
                    proto_name = self.PROTO_NAMES.get(proto, f"Proto{proto}")
                    tuple_key = (tc_key, proto_name, f"{src_ip}:{sport}", f"{dst_ip}:{dport}")
                    error_msgs[tuple_key] += 1
            else:
                # Informational message
                info_msgs[tc_key] += 1

        # Generate output
        lines = []

        # Error messages section
        if error_msgs:
            lines.append("ICMP error messages with embedded protocol info:\n")
            lines.append(f"{'ICMP Type/Code':<30} {'Protocol':<8} {'Embedded 5-tuple':<40} Count")
            lines.append("-" * 92)

            for (tc_key, proto_name, src_tuple, dst_tuple), count in sorted(error_msgs.items()):
                desc = self.ICMP_TYPES.get(tc_key, f"Type {tc_key.split(':')[0]} Code {tc_key.split(':')[1]}")
                type_code = tc_key.split(':')
                label = f"[{type_code[0]}/{type_code[1]}] {desc}"
                tuple_str = f"{src_tuple} -> {dst_tuple}"
                lines.append(f"{label:<30} {proto_name:<8} {tuple_str:<40} {count}")

        # Informational messages section
        if info_msgs:
            if error_msgs:
                lines.append("")
            lines.append("ICMP informational messages:\n")
            lines.append(f"{'ICMP Type/Code':<30} Count")
            lines.append("-" * 43)

            for tc_key, count in sorted(info_msgs.items()):
                desc = self.ICMP_TYPES.get(tc_key, f"Type {tc_key.split(':')[0]} Code {tc_key.split(':')[1]}")
                type_code = tc_key.split(':')
                label = f"[{type_code[0]}/{type_code[1]}] {desc}"
                lines.append(f"{label:<30} {count}")

        return '\n'.join(lines)
