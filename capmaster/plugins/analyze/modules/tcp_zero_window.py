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
            return "Zero Window Count\nCount\tSrcIP\tSrcPort\tDstIP\tDstPort\n"

        # Count occurrences of each unique 4-tuple
        counter: Counter[str] = Counter()
        for line in tshark_output.strip().split('\n'):
            if line.strip():
                counter[line.strip()] = counter.get(line.strip(), 0) + 1

        # Sort by count (descending), then by tuple (for stable output)
        sorted_items = sorted(counter.items(), key=lambda x: (-x[1], x[0]))

        # Format output with header
        lines = ["Zero Window Count", "Count\tSrcIP\tSrcPort\tDstIP\tDstPort"]
        for tuple_str, count in sorted_items:
            # tuple_str is already tab-separated from tshark
            lines.append(f"{count}\t{tuple_str}")

        return '\n'.join(lines) + '\n'
