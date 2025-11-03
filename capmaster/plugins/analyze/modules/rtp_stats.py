"""RTP statistics module."""

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
        
        # Find the header line and data lines
        header_idx = -1
        separator_idx = -1
        
        for i, line in enumerate(lines):
            if "Start time" in line and "End time" in line:
                header_idx = i
            elif line.strip().startswith("==="):
                separator_idx = i
        
        if header_idx == -1:
            # No RTP streams found or unexpected format
            return tshark_output
        
        # Extract stream data lines (between header and final separator)
        stream_lines = []
        for i in range(header_idx + 1, len(lines)):
            line = lines[i].strip()
            if line.startswith("==="):
                break
            if line and not line.startswith("="):
                stream_lines.append(line)
        
        if not stream_lines:
            return "No RTP streams found\n"
        
        # Parse and analyze streams
        output_lines = []
        output_lines.append("=" * 100)
        output_lines.append("RTP Stream Statistics")
        output_lines.append("=" * 100)
        output_lines.append("")
        
        # Add original tshark output
        output_lines.append("Stream Details:")
        output_lines.append("-" * 100)
        output_lines.extend(lines[header_idx:separator_idx + 1])
        output_lines.append("")
        
        # Analyze each stream
        output_lines.append("Quality Analysis:")
        output_lines.append("-" * 100)
        
        stream_count = 0
        total_packets = 0
        total_lost = 0
        max_jitter = 0.0
        
        for line in stream_lines:
            stream_count += 1
            
            # Parse stream information using regex
            # Expected format has fields separated by whitespace
            # We're interested in: Pkts, Lost, Mean Jitter, Max Jitter, Problems
            
            # Extract packet count (look for number followed by number in parentheses for loss)
            pkts_match = re.search(r'\s+(\d+)\s+\d+\s+\([\d.]+%\)', line)
            if pkts_match:
                pkts = int(pkts_match.group(1))
                total_packets += pkts
            else:
                pkts = 0
            
            # Extract packet loss
            loss_match = re.search(r'\s+(\d+)\s+\(([\d.]+)%\)', line)
            if loss_match:
                lost = int(loss_match.group(1))
                loss_pct = float(loss_match.group(2))
                total_lost += lost
            else:
                lost = 0
                loss_pct = 0.0
            
            # Extract jitter values (look for decimal numbers in ms)
            jitter_matches = re.findall(r'([\d.]+)\s+ms', line)
            if len(jitter_matches) >= 3:
                # Typically: Min Jitter, Mean Jitter, Max Jitter
                mean_jitter = float(jitter_matches[1]) if len(jitter_matches) > 1 else 0.0
                stream_max_jitter = float(jitter_matches[2]) if len(jitter_matches) > 2 else 0.0
                max_jitter = max(max_jitter, stream_max_jitter)
            else:
                mean_jitter = 0.0
                stream_max_jitter = 0.0
            
            # Extract source and destination
            ip_matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+(\d+)', line)
            if len(ip_matches) >= 2:
                src_ip, src_port = ip_matches[0]
                dst_ip, dst_port = ip_matches[1]
                endpoint = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            else:
                endpoint = "Unknown"
            
            # Quality assessment
            quality_issues = []
            
            if loss_pct > 5.0:
                quality_issues.append(f"HIGH packet loss ({loss_pct:.1f}%)")
            elif loss_pct > 1.0:
                quality_issues.append(f"Moderate packet loss ({loss_pct:.1f}%)")
            
            if mean_jitter > 30.0:
                quality_issues.append(f"HIGH jitter ({mean_jitter:.3f} ms)")
            elif mean_jitter > 20.0:
                quality_issues.append(f"Moderate jitter ({mean_jitter:.3f} ms)")
            
            if stream_max_jitter > 50.0:
                quality_issues.append(f"HIGH max jitter ({stream_max_jitter:.3f} ms)")
            
            # Output stream analysis
            output_lines.append(f"\nStream {stream_count}: {endpoint}")
            output_lines.append(f"  Packets: {pkts}, Lost: {lost} ({loss_pct:.1f}%)")
            output_lines.append(f"  Mean Jitter: {mean_jitter:.3f} ms, Max Jitter: {stream_max_jitter:.3f} ms")
            
            if quality_issues:
                output_lines.append(f"  ⚠ Quality Issues: {', '.join(quality_issues)}")
            else:
                output_lines.append(f"  ✓ Quality: Good")
        
        # Summary
        output_lines.append("")
        output_lines.append("=" * 100)
        output_lines.append("Summary:")
        output_lines.append(f"  Total RTP Streams:   {stream_count}")
        output_lines.append(f"  Total Packets:       {total_packets}")
        output_lines.append(f"  Total Lost Packets:  {total_lost}")
        if total_packets > 0:
            overall_loss_pct = (total_lost / total_packets) * 100
            output_lines.append(f"  Overall Packet Loss: {overall_loss_pct:.2f}%")
        output_lines.append(f"  Maximum Jitter:      {max_jitter:.3f} ms")
        
        # Overall quality assessment
        output_lines.append("")
        if total_packets > 0:
            overall_loss_pct = (total_lost / total_packets) * 100
            if overall_loss_pct > 5.0 or max_jitter > 30.0:
                output_lines.append("  Overall Quality: ⚠ POOR - Significant quality issues detected")
            elif overall_loss_pct > 1.0 or max_jitter > 20.0:
                output_lines.append("  Overall Quality: ⚠ FAIR - Some quality issues detected")
            else:
                output_lines.append("  Overall Quality: ✓ GOOD - No significant issues")
        
        output_lines.append("=" * 100)
        
        return '\n'.join(output_lines) + '\n'

