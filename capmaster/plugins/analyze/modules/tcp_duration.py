"""TCP duration statistics module."""

from __future__ import annotations
import re
from collections import defaultdict
from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class TcpDurationModule(AnalysisModule):
    """Generate TCP connection duration statistics.

    Parses TCP conversation output and bins connections by duration:
    <1s, <5s, <10s, <30s, <60s, >=60s

    Uses regex parsing and defaultdict for efficient categorization.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "tcp_duration"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "tcp-connection-duration.txt"

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
            List of tshark arguments for TCP conversations (to extract duration)
        """
        return ["-q", "-z", "conv,tcp"]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process TCP conversations to bin by duration.

        Parses conv,tcp output and bins connections into duration buckets.

        Args:
            tshark_output: Raw tshark conv,tcp output
            output_format: Output format ("txt" or "md", default: "txt")

        Returns:
            Formatted output with connections binned by duration
        """
        # Duration bins (in seconds)
        bins = [1, 5, 10, 30, 60]

        # Storage for each bucket
        bucket_data: dict[str, list[str]] = defaultdict(list)

        # Parse TCP conversations
        # Format: "192.168.1.1:12345 <-> 192.168.1.2:80  ... Duration:123.456"
        # Regex to match conversation lines with duration
        pattern = r'^([^ ]+):([0-9]+)\s+<->\s+([^ ]+):([0-9]+).*\s+([0-9]+(?:\.[0-9]+)?)\s*$'

        for line in tshark_output.split('\n'):
            match = re.match(pattern, line.strip())
            if match:
                src_ip = match.group(1)
                src_port = match.group(2)
                dst_ip = match.group(3)
                dst_port = match.group(4)
                duration = float(match.group(5))

                # Determine bucket
                bucket_name = f">={bins[-1]}s"
                for bin_val in bins:
                    if duration < bin_val:
                        bucket_name = f"<{bin_val}s"
                        break

                # Format connection string
                conn_str = f"{src_ip},{src_port},{dst_ip},{dst_port},TCP,{duration:.3f}s"
                bucket_data[bucket_name].append(conn_str)

        # Generate output in reverse bin order (>=60s, <60s, <30s, ...)
        bucket_order = [f">={bins[-1]}s"]
        for i in range(len(bins) - 1, -1, -1):
            bucket_order.append(f"<{bins[i]}s")

        lines = []
        for bucket in bucket_order:
            count = len(bucket_data[bucket])
            lines.append(f"Bucket {bucket}: {count} connections")
            if count > 0:
                for conn in bucket_data[bucket]:
                    lines.append(conn)
            lines.append("")  # Empty line after each bucket

        return '\n'.join(lines)
