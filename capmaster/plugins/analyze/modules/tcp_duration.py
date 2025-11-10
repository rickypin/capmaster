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
        bins = [1, 5, 10, 30, 60]
        bucket_data: dict[str, list[str]] = defaultdict(list)
        pattern = r'^([^ ]+):([0-9]+)\s+<->\s+([^ ]+):([0-9]+).*\s+([0-9]+(?:\.[0-9]+)?)\s*$'

        for line in tshark_output.split('\n'):
            match = re.match(pattern, line.strip())
            if not match:
                continue

            src_ip = match.group(1)
            src_port = match.group(2)
            dst_ip = match.group(3)
            dst_port = match.group(4)
            duration = float(match.group(5))

            bucket_name = f">={bins[-1]}s"
            for bin_val in bins:
                if duration < bin_val:
                    bucket_name = f"<{bin_val}s"
                    break

            conn_str = f"{src_ip},{src_port},{dst_ip},{dst_port},TCP,{duration:.3f}s"
            bucket_data[bucket_name].append(conn_str)

        bucket_order = [f">={bins[-1]}s"]
        for i in range(len(bins) - 1, -1, -1):
            bucket_order.append(f"<{bins[i]}s")

        severity_map = {
            f">={bins[-1]}s": "High",
            f"<{bins[-1]}s": "High",
            "<30s": "Medium",
            "<10s": "Low",
            "<5s": "Low",
            "<1s": "Low",
        }

        bucket_counts = {bucket: len(bucket_data[bucket]) for bucket in bucket_order}
        total_connections = sum(bucket_counts.values())

        lines: list[str] = []
        lines.append("TCP Duration Buckets")
        lines.append("Bucket,Count,Share")
        for bucket in bucket_order:
            count = bucket_counts[bucket]
            share = (count / total_connections * 100) if total_connections else 0.0
            lines.append(f"{bucket},{count},{share:.1f}%")

        non_empty_buckets = [b for b in bucket_order if bucket_counts[b] > 0]
        severity_rank = {"High": 0, "Medium": 1, "Low": 2}
        non_empty_buckets.sort(
            key=lambda b: (
                severity_rank.get(severity_map.get(b, "Low"), 2),
                -bucket_counts[b],
            )
        )

        detailed_buckets = non_empty_buckets[:3]
        if detailed_buckets:
            lines.append("")
            lines.append("Highlighted Buckets (sampled)")
            for bucket in detailed_buckets:
                severity = severity_map.get(bucket, "Low")
                count = bucket_counts[bucket]
                samples = self.sample_items(bucket_data[bucket], limit=3)
                lines.append(f"{bucket} [{severity}] total={count}")
                for entry in samples:
                    lines.append(f"  sample: {entry}")
                remaining = count - len(samples)
                if remaining > 0:
                    lines.append(f"  ... {remaining} more")

        return '\n'.join(lines)
