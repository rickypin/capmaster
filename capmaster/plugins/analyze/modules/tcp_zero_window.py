"""TCP zero window statistics module."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class TcpZeroWindowModule(AnalysisModule):
    """Generate TCP zero window statistics.

    Extracts TCP zero window events, counts occurrences by connection 4-tuple,
    and sorts by frequency (descending). Uses Python Counter for aggregation.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "tcp_zero_window"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "tcp-zero-window.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"tcp"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for TCP zero window detection
        """
        # Extract the 4 fields needed for grouping
        return [
            "-Y",
            "tcp.analysis.zero_window",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process tshark output to count and format zero window packets.

        Uses Counter to aggregate by connection 4-tuple, then sorts by
        frequency (descending) for easy identification of problematic connections.

        Args:
            tshark_output: Raw tshark output (tab-separated fields)
            output_format: Output format ("txt" or "md", default: "txt")

        Returns:
            Formatted output with counts, sorted by count descending
        """
        if not tshark_output.strip():
            return "Zero Window Overview\nMetric,Value\nTotal Events,0\n"

        counter: Counter[str] = Counter()
        for line in tshark_output.strip().split('\n'):
            tuple_str = line.strip()
            if tuple_str:
                counter[tuple_str] += 1

        sorted_items = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
        total_events = sum(counter.values())

        def classify(count: int) -> str:
            if count >= 50:
                return "High"
            if count >= 10:
                return "Medium"
            return "Low"

        severity_counts: Counter[str] = Counter()
        severity_connections: dict[str, list[tuple[str, int]]] = {"High": [], "Medium": [], "Low": []}
        for tuple_str, count in sorted_items:
            severity = classify(count)
            severity_counts[severity] += count
            severity_connections[severity].append((tuple_str, count))

        lines: list[str] = []
        lines.append("Zero Window Overview")
        lines.append("Metric,Value")
        lines.append(f"Total Events,{total_events}")
        lines.append(f"Unique Connections,{len(sorted_items)}")
        lines.append("")

        lines.append("Severity Summary")
        lines.append("Severity,Events,Connections")
        for severity in ["High", "Medium", "Low"]:
            events = severity_counts.get(severity, 0)
            conn_count = len(severity_connections[severity])
            lines.append(f"{severity},{events},{conn_count}")

        highlights: list[tuple[str, int, str]] = []
        for severity in ["High", "Medium", "Low"]:
            for tuple_str, count in severity_connections[severity]:
                highlights.append((tuple_str, count, severity))
                if len(highlights) >= 5:
                    break
            if len(highlights) >= 5:
                break

        if highlights:
            lines.append("")
            lines.append("Highlighted Connections")
            lines.append("Connection,Count,Severity")
            for tuple_str, count, severity in highlights:
                lines.append(f"{tuple_str},{count},{severity}")

        return '\n'.join(lines) + '\n'
