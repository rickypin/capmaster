"""VoIP quality assessment module."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class VoipQualityModule(AnalysisModule):
    """Generate VoIP quality assessment with MOS scores.
    
    Analyzes RTP streams to calculate Mean Opinion Score (MOS) based on:
    - Packet loss rate
    - Jitter (delay variation)
    - Codec type
    
    MOS Scale:
    - 5.0: Excellent (imperceptible impairment)
    - 4.0-4.9: Good (perceptible but not annoying)
    - 3.0-3.9: Fair (slightly annoying)
    - 2.0-2.9: Poor (annoying)
    - 1.0-1.9: Bad (very annoying)
    
    This provides a comprehensive VoIP quality assessment for troubleshooting.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "voip_quality"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "voip-quality.txt"

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
            List of tshark arguments for RTP stream analysis
        """
        return ["-q", "-z", "rtp,streams"]

    def _calculate_mos(self, packet_loss: float, mean_jitter: float, codec: str) -> tuple[float, str]:
        """
        Calculate MOS (Mean Opinion Score) based on network metrics.
        
        Uses E-Model (ITU-T G.107) simplified calculation.
        
        Args:
            packet_loss: Packet loss percentage (0-100)
            mean_jitter: Mean jitter in milliseconds
            codec: Codec name (e.g., 'g711U', 'g729', 'opus')
            
        Returns:
            Tuple of (MOS score, quality rating)
        """
        # Base R-factor (transmission rating)
        # Different codecs have different base quality
        codec_r_base = {
            'g711u': 93.2,
            'g711a': 93.2,
            'g722': 92.0,
            'g729': 83.0,
            'opus': 92.0,
            'ilbc': 82.0,
        }
        
        # Get base R-factor for codec (default to G.711)
        codec_lower = codec.lower()
        r_base = codec_r_base.get(codec_lower, 93.2)
        
        # Calculate impairment due to packet loss (Id)
        # Simplified formula: Id = 10 + 40 * packet_loss
        id_factor = 10 + (40 * packet_loss / 100)
        
        # Calculate impairment due to jitter (Ie-eff)
        # Jitter impact increases non-linearly
        if mean_jitter < 20:
            ie_eff = 0
        elif mean_jitter < 50:
            ie_eff = (mean_jitter - 20) * 0.5
        elif mean_jitter < 100:
            ie_eff = 15 + (mean_jitter - 50) * 0.8
        else:
            ie_eff = 55 + (mean_jitter - 100) * 1.0
        
        # Calculate R-factor
        r_factor = r_base - id_factor - ie_eff
        
        # Ensure R-factor is within valid range
        r_factor = max(0, min(100, r_factor))
        
        # Convert R-factor to MOS
        # MOS = 1 + 0.035*R + R*(R-60)*(100-R)*7*10^-6
        if r_factor < 0:
            mos = 1.0
        elif r_factor > 100:
            mos = 4.5
        else:
            mos = 1 + 0.035 * r_factor + r_factor * (r_factor - 60) * (100 - r_factor) * 7e-6
        
        # Ensure MOS is within valid range
        mos = max(1.0, min(5.0, mos))
        
        # Determine quality rating
        if mos >= 4.3:
            rating = "Excellent"
        elif mos >= 4.0:
            rating = "Good"
        elif mos >= 3.6:
            rating = "Fair"
        elif mos >= 3.1:
            rating = "Poor"
        else:
            rating = "Bad"
        
        return mos, rating

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process RTP streams to calculate VoIP quality metrics.

        Parses RTP stream statistics, computes MOS, and emits a concise
        severity-aware summary with sampled stream details.

        Args:
            tshark_output: Raw tshark RTP streams output
            output_format: Output format ("txt" or "md", default: "txt")

        Returns:
            Formatted output with VoIP quality assessment
        """
        if not tshark_output.strip():
            return "No RTP streams found for VoIP quality analysis\n"

        streams = []
        stream_pattern = re.compile(
            r"\s*(\d+\.\d+)\s+(\d+\.\d+)\s+"
            r"([\d.]+)\s+(\d+)\s+"
            r"([\d.]+)\s+(\d+)\s+"
            r"(0x[0-9A-Fa-f]+)\s+"
            r"(\S+)\s+"
            r"(\d+)\s+"
            r"(\d+)\s+\(([\d.]+)%\)\s+"
            r"([\d.]+)\s+"
            r"([\d.]+)\s+"
            r"([\d.]+)\s+"
            r"([\d.]+)\s+"
            r"([\d.]+)\s+"
            r"([\d.]+)"
        )

        for line in tshark_output.split("\n"):
            match = stream_pattern.search(line)
            if not match:
                continue

            start_time = float(match.group(1))
            end_time = float(match.group(2))
            src_ip = match.group(3)
            src_port = match.group(4)
            dst_ip = match.group(5)
            dst_port = match.group(6)
            ssrc = match.group(7)
            codec = match.group(8)
            packets = int(match.group(9))
            lost_packets = int(match.group(10))
            loss_percent = float(match.group(11))
            mean_jitter = float(match.group(16))
            max_jitter = float(match.group(17))

            mos, rating = self._calculate_mos(loss_percent, mean_jitter, codec)
            duration = end_time - start_time

            issues: list[str] = []
            if loss_percent > 5:
                issues.append(f"High packet loss {loss_percent:.1f}%")
            elif loss_percent > 1:
                issues.append(f"Moderate packet loss {loss_percent:.1f}%")

            if mean_jitter > 30:
                issues.append(f"High jitter {mean_jitter:.1f} ms")
            elif mean_jitter > 20:
                issues.append(f"Moderate jitter {mean_jitter:.1f} ms")

            if max_jitter > 50:
                issues.append(f"Jitter spikes {max_jitter:.1f} ms")

            streams.append(
                {
                    "src": f"{src_ip}:{src_port}",
                    "dst": f"{dst_ip}:{dst_port}",
                    "ssrc": ssrc,
                    "codec": codec,
                    "packets": packets,
                    "lost": lost_packets,
                    "loss_percent": loss_percent,
                    "mean_jitter": mean_jitter,
                    "max_jitter": max_jitter,
                    "duration": duration,
                    "mos": mos,
                    "rating": rating,
                    "issues": issues,
                }
            )

        if not streams:
            return "No valid RTP streams found for quality analysis\n"

        total_streams = len(streams)
        avg_mos = sum(s["mos"] for s in streams) / total_streams if total_streams else 0.0
        rating_counts = Counter(stream["rating"] for stream in streams)
        severity_map = {
            "Excellent": "Low",
            "Good": "Low",
            "Fair": "Medium",
            "Poor": "High",
            "Bad": "High",
        }
        severity_rank = {"High": 0, "Medium": 1, "Low": 2}
        severity_counts = Counter(severity_map.get(stream["rating"], "Low") for stream in streams)
        overall_severity = (
            "High"
            if severity_counts["High"]
            else ("Medium" if severity_counts["Medium"] else "Low")
        )

        lines: list[str] = []
        lines.append("VoIP Quality Overview")
        lines.append("Metric,Value")
        lines.append(f"Total Streams,{total_streams}")
        lines.append(f"Average MOS,{avg_mos:.2f}")
        lines.append(f"Overall Severity,{overall_severity}")
        lines.append(f"High-Severity Streams,{severity_counts['High']}")
        lines.append(f"Medium-Severity Streams,{severity_counts['Medium']}")
        lines.append("")

        lines.append("Quality Distribution")
        lines.append("Rating,Count,Share")
        for rating in ["Excellent", "Good", "Fair", "Poor", "Bad"]:
            count = rating_counts.get(rating, 0)
            share = (count / total_streams * 100) if total_streams else 0.0
            lines.append(f"{rating},{count},{share:.1f}%")

        lines.append("")
        highlight_candidates = sorted(
            streams,
            key=lambda stream: (
                severity_rank.get(severity_map.get(stream["rating"], "Low"), 2),
                stream["mos"],
            ),
        )
        highlight_limit = 5
        highlights = highlight_candidates[:highlight_limit]

        if highlights:
            lines.append("Highlighted Streams")
            lines.append("Index,Endpoints,Codec,MOS,Rating,Loss%,MeanJitter(ms),Severity")
            for idx, stream in enumerate(highlights, 1):
                severity = severity_map.get(stream["rating"], "Low")
                endpoint = f"{stream['src']} -> {stream['dst']}"
                lines.append(
                    f"{idx},{endpoint},{stream['codec']},{stream['mos']:.2f},{stream['rating']},"
                    f"{stream['loss_percent']:.1f},{stream['mean_jitter']:.2f},{severity}"
                )
                if stream["issues"]:
                    sampled = self.sample_items(stream["issues"], limit=2)
                    lines.append(f"  Issues: {', '.join(sampled)}")
            remaining = total_streams - len(highlights)
            if remaining > 0:
                lines.append(f"... {remaining} additional streams hidden")

        lines.append("")
        lines.append("Action Guidance")
        if severity_counts["High"]:
            lines.append(
                "Prioritize investigation of high severity streams to address packet loss and jitter."
            )
        elif severity_counts["Medium"]:
            lines.append(
                "Monitor medium severity streams for early signs of degradation."
            )
        else:
            lines.append("Quality metrics are stable; continue routine monitoring.")

        return "\n".join(lines) + "\n"

