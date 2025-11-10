"""RTP statistics module."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import re

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class RtpStatsModule(AnalysisModule):
    """Generate RTP stream statistics.
    
    Analyzes RTP (Real-time Transport Protocol) streams to extract:
    - Stream information (SSRC, payload type, packet count)
    - Quality metrics (packet loss, jitter, delta timing)
    - Source and destination endpoints
    
    This helps identify VoIP quality issues and network problems.
    """

    @dataclass
    class _StreamMetrics:
        endpoint: str
        packets: int
        lost: int
        loss_pct: float
        mean_jitter: float
        max_jitter: float
        severity: str
        issues: list[str]

    @property
    def name(self) -> str:
        """Module name."""
        return "rtp_stats"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "rtp-stats.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"rtp"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for RTP stream statistics
        """
        # Use tshark's built-in RTP stream analysis
        return ["-q", "-z", "rtp,streams"]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process RTP stream statistics.
        
        Parses tshark's RTP stream output and adds analysis for:
        - Quality assessment based on packet loss and jitter
        - Problem detection
        
        Args:
            tshark_output: Raw tshark output from rtp,streams command
            output_format: Output format ("txt" or "md", default: "txt")
            
        Returns:
            Enhanced output with quality analysis
        """
        if not tshark_output.strip():
            return "No RTP streams found\n"

        lines = tshark_output.strip().split('\n')

        header_idx = -1
        separator_idx = -1
        for idx, line in enumerate(lines):
            if "Start time" in line and "End time" in line:
                header_idx = idx
            elif line.strip().startswith("==="):
                separator_idx = idx

        if header_idx == -1:
            return tshark_output

        stream_lines: list[str] = []
        for raw in lines[header_idx + 1 :]:
            stripped = raw.strip()
            if stripped.startswith("==="):
                break
            if stripped and not stripped.startswith("="):
                stream_lines.append(stripped)

        if not stream_lines:
            return "No RTP streams found\n"

        streams: list[RtpStatsModule._StreamMetrics] = []
        total_packets = 0
        total_lost = 0
        max_jitter = 0.0

        for line in stream_lines:
            pkts_match = re.search(r"\s+(\d+)\s+\d+\s+\([\d.]+%\)", line)
            packets = int(pkts_match.group(1)) if pkts_match else 0
            total_packets += packets

            loss_match = re.search(r"\s+(\d+)\s+\(([\d.]+)%\)", line)
            lost = int(loss_match.group(1)) if loss_match else 0
            loss_pct = float(loss_match.group(2)) if loss_match else 0.0
            total_lost += lost

            jitter_matches = re.findall(r"([\d.]+)\s+ms", line)
            mean_jitter = float(jitter_matches[1]) if len(jitter_matches) > 1 else 0.0
            stream_max_jitter = float(jitter_matches[2]) if len(jitter_matches) > 2 else 0.0
            max_jitter = max(max_jitter, stream_max_jitter)

            ip_matches = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+(\d+)", line)
            if len(ip_matches) >= 2:
                src_ip, src_port = ip_matches[0]
                dst_ip, dst_port = ip_matches[1]
                endpoint = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            else:
                endpoint = "Unknown"

            issues: list[str] = []
            if loss_pct > 5.0:
                issues.append(f"High packet loss {loss_pct:.1f}%")
            elif loss_pct > 1.0:
                issues.append(f"Moderate packet loss {loss_pct:.1f}%")
            if mean_jitter > 30.0:
                issues.append(f"High jitter {mean_jitter:.1f} ms")
            elif mean_jitter > 20.0:
                issues.append(f"Moderate jitter {mean_jitter:.1f} ms")
            if stream_max_jitter > 50.0:
                issues.append(f"Jitter spikes {stream_max_jitter:.1f} ms")

            if loss_pct > 5.0 or mean_jitter > 30.0 or stream_max_jitter > 50.0:
                severity = "High"
            elif loss_pct > 1.0 or mean_jitter > 20.0:
                severity = "Medium"
            else:
                severity = "Low"

            streams.append(
                self._StreamMetrics(
                    endpoint=endpoint,
                    packets=packets,
                    lost=lost,
                    loss_pct=loss_pct,
                    mean_jitter=mean_jitter,
                    max_jitter=stream_max_jitter,
                    severity=severity,
                    issues=issues,
                )
            )

        stream_count = len(streams)
        severity_counts = Counter(stream.severity for stream in streams)
        severity_rank = {"High": 0, "Medium": 1, "Low": 2}

        output_lines: list[str] = []
        output_lines.append("RTP Stream Overview")
        output_lines.append("Metric,Value")
        output_lines.append(f"Total Streams,{stream_count}")
        output_lines.append(f"Total Packets,{total_packets}")
        output_lines.append(f"Lost Packets,{total_lost}")
        overall_loss = (total_lost / total_packets * 100) if total_packets else 0.0
        output_lines.append(f"Overall Loss %, {overall_loss:.2f}")
        output_lines.append(f"High Severity Streams,{severity_counts['High']}")
        output_lines.append(f"Medium Severity Streams,{severity_counts['Medium']}")
        output_lines.append(f"Low Severity Streams,{severity_counts['Low']}")
        output_lines.append(f"Peak Max Jitter,{max_jitter:.2f} ms")
        output_lines.append("")

        output_lines.append("Severity Breakdown")
        output_lines.append("Severity,Streams,Share")
        for severity in ["High", "Medium", "Low"]:
            count = severity_counts.get(severity, 0)
            share = (count / stream_count * 100) if stream_count else 0.0
            output_lines.append(f"{severity},{count},{share:.1f}%")

        if streams:
            output_lines.append("")
            output_lines.append("Highlighted Streams")
            output_lines.append("Index,Endpoint,Packets,Loss%,Mean Jitter ms,Max Jitter ms,Severity")
            sorted_streams = sorted(
                streams,
                key=lambda s: (
                    severity_rank[s.severity],
                    -s.loss_pct,
                    -s.mean_jitter,
                ),
            )
            for idx, stream in enumerate(sorted_streams[:5], 1):
                output_lines.append(
                    f"{idx},{stream.endpoint},{stream.packets},{stream.loss_pct:.1f},{stream.mean_jitter:.2f},{stream.max_jitter:.2f},{stream.severity}"
                )
                if stream.issues:
                    sampled = self.sample_items(stream.issues, limit=2)
                    output_lines.append(f"  Issues: {', '.join(sampled)}")
            remaining = stream_count - min(5, stream_count)
            if remaining > 0:
                output_lines.append(f"... {remaining} additional stream(s) hidden")

        return "\n".join(output_lines) + "\n"

