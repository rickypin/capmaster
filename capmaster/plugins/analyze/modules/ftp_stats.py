"""FTP statistics module."""

from collections import defaultdict
from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class FtpStatsModule(AnalysisModule):
    """Generate FTP response code statistics.

    Extracts FTP response codes and messages, then aggregates by
    (code, message) tuple. Uses defaultdict for grouping and set
    for deduplicating connections.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "ftp_stats"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "ftp-response-code.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"ftp"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for FTP response code extraction
        """
        return [
            "-Y",
            "ftp.response.code",
            "-o",
            "tcp.desegment_tcp_streams:TRUE",
            "-o",
            "tcp.reassemble_out_of_order:TRUE",
            "-T",
            "fields",
            "-e",
            "ip.src_host",
            "-e",
            "tcp.srcport",
            "-e",
            "ip.dst_host",
            "-e",
            "tcp.dstport",
            "-e",
            "ftp.response.code",
            "-e",
            "ftp.response.arg",
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process FTP response codes to aggregate by code and message.

        Groups responses by code and message, counts occurrences, and lists connections.

        Args:
            tshark_output: Raw tshark output (tab-separated fields)
            output_format: Output format ("txt" or "md", default: "txt")

        Returns:
            Formatted output with FTP responses grouped by code and message
        """
        # Storage: {(code, message): {count, connections}}
        responses: dict[tuple[str, str], dict[str, object]] = defaultdict(
            lambda: {"count": 0, "connections": set()}
        )

        for line in tshark_output.strip().split('\n'):
            if not line.strip():
                continue

            parts = line.split('\t')
            if len(parts) < 6:
                continue

            src_host = parts[0] if parts[0] else ""
            src_port = parts[1] if parts[1] else ""
            dst_host = parts[2] if parts[2] else ""
            dst_port = parts[3] if parts[3] else ""
            code = parts[4] if parts[4] else ""
            message = parts[5] if parts[5] else ""

            if not code:
                continue

            key = (code, message)
            connection = f"{src_host}:{src_port} -> {dst_host}:{dst_port}"

            responses[key]["count"] += 1  # type: ignore
            responses[key]["connections"].add(connection)  # type: ignore

        # Sort by code (numerically)
        sorted_responses = sorted(responses.items(), key=lambda x: (int(x[0][0]) if x[0][0].isdigit() else 999, x[0][1]))

        # Generate output
        lines = []
        for (code, message), data in sorted_responses:
            count = data["count"]
            connections = sorted(data["connections"])  # type: ignore

            lines.append(f"FTP {code} - {message} (count {count}):")
            for conn in connections:
                lines.append(f"  {conn}")
            lines.append("")  # Empty line between groups

        return '\n'.join(lines)
