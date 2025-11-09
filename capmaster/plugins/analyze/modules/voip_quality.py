"""VoIP quality assessment module."""

from __future__ import annotations

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
        
        Parses RTP stream statistics and calculates MOS scores.
        
        Args:
            tshark_output: Raw tshark RTP streams output
            output_format: Output format ("txt" or "md", default: "txt")
            
        Returns:
            Formatted output with VoIP quality assessment
        """
        if not tshark_output.strip():
            return "No RTP streams found for VoIP quality analysis\n"
        
        lines = []
        lines.append("=" * 100)
        lines.append("VoIP Quality Assessment (MOS Analysis)")
        lines.append("=" * 100)
        lines.append("")
        
        # Parse RTP stream data
        streams = []
        stream_pattern = re.compile(
            r'\s*(\d+\.\d+)\s+(\d+\.\d+)\s+'  # Start time, End time
            r'([\d.]+)\s+(\d+)\s+'  # Src IP, Src Port
            r'([\d.]+)\s+(\d+)\s+'  # Dst IP, Dst Port
            r'(0x[0-9A-Fa-f]+)\s+'  # SSRC
            r'(\S+)\s+'  # Payload/Codec
            r'(\d+)\s+'  # Packets
            r'(\d+)\s+\(([\d.]+)%\)\s+'  # Lost packets and percentage
            r'([\d.]+)\s+'  # Min Delta
            r'([\d.]+)\s+'  # Mean Delta
            r'([\d.]+)\s+'  # Max Delta
            r'([\d.]+)\s+'  # Min Jitter
            r'([\d.]+)\s+'  # Mean Jitter
            r'([\d.]+)'  # Max Jitter
        )
        
        for line in tshark_output.split('\n'):
            match = stream_pattern.search(line)
            if match:
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
                min_delta = float(match.group(12))
                mean_delta = float(match.group(13))
                max_delta = float(match.group(14))
                min_jitter = float(match.group(15))
                mean_jitter = float(match.group(16))
                max_jitter = float(match.group(17))
                
                # Calculate MOS
                mos, rating = self._calculate_mos(loss_percent, mean_jitter, codec)
                
                duration = end_time - start_time
                
                streams.append({
                    'src': f"{src_ip}:{src_port}",
                    'dst': f"{dst_ip}:{dst_port}",
                    'ssrc': ssrc,
                    'codec': codec,
                    'packets': packets,
                    'lost': lost_packets,
                    'loss_percent': loss_percent,
                    'mean_jitter': mean_jitter,
                    'max_jitter': max_jitter,
                    'duration': duration,
                    'mos': mos,
                    'rating': rating,
                })
        
        if not streams:
            return "No valid RTP streams found for quality analysis\n"
        
        # Overall summary
        total_streams = len(streams)
        avg_mos = sum(s['mos'] for s in streams) / total_streams
        
        # Count quality levels
        excellent = sum(1 for s in streams if s['rating'] == 'Excellent')
        good = sum(1 for s in streams if s['rating'] == 'Good')
        fair = sum(1 for s in streams if s['rating'] == 'Fair')
        poor = sum(1 for s in streams if s['rating'] == 'Poor')
        bad = sum(1 for s in streams if s['rating'] == 'Bad')
        
        lines.append("Overall Summary:")
        lines.append("-" * 100)
        lines.append(f"  Total RTP Streams:       {total_streams}")
        lines.append(f"  Average MOS Score:       {avg_mos:.2f}")
        lines.append("")
        lines.append("Quality Distribution:")
        lines.append(f"  Excellent (MOS ≥ 4.3):   {excellent} streams")
        lines.append(f"  Good (MOS 4.0-4.3):      {good} streams")
        lines.append(f"  Fair (MOS 3.6-4.0):      {fair} streams")
        lines.append(f"  Poor (MOS 3.1-3.6):      {poor} streams")
        lines.append(f"  Bad (MOS < 3.1):         {bad} streams")
        lines.append("")
        
        # Detailed stream analysis
        lines.append("Detailed Stream Quality Analysis:")
        lines.append("-" * 100)
        lines.append(f"{'Stream':<6} {'MOS':<6} {'Rating':<12} {'Loss%':<8} {'Jitter(ms)':<12} "
                    f"{'Codec':<10} {'Packets':<10} {'Duration(s)':<12}")
        lines.append("-" * 100)
        
        for i, stream in enumerate(streams, 1):
            mos_str = f"{stream['mos']:.2f}"
            loss_str = f"{stream['loss_percent']:.1f}%"
            jitter_str = f"{stream['mean_jitter']:.2f}"
            duration_str = f"{stream['duration']:.1f}"
            
            # Add indicator for quality
            if stream['rating'] == 'Excellent':
                indicator = "✓"
            elif stream['rating'] in ['Good', 'Fair']:
                indicator = "○"
            else:
                indicator = "⚠"
            
            lines.append(f"{i:<6} {mos_str:<6} {indicator} {stream['rating']:<10} {loss_str:<8} "
                        f"{jitter_str:<12} {stream['codec']:<10} {stream['packets']:<10} {duration_str:<12}")
        
        lines.append("")
        
        # Detailed information for each stream
        lines.append("Stream Details:")
        lines.append("-" * 100)
        
        for i, stream in enumerate(streams, 1):
            lines.append(f"\nStream {i}: {stream['src']} → {stream['dst']}")
            lines.append(f"  SSRC:           {stream['ssrc']}")
            lines.append(f"  Codec:          {stream['codec']}")
            lines.append(f"  Duration:       {stream['duration']:.2f} seconds")
            lines.append(f"  Packets:        {stream['packets']} (Lost: {stream['lost']}, {stream['loss_percent']:.2f}%)")
            lines.append(f"  Mean Jitter:    {stream['mean_jitter']:.3f} ms")
            lines.append(f"  Max Jitter:     {stream['max_jitter']:.3f} ms")
            lines.append(f"  MOS Score:      {stream['mos']:.2f} ({stream['rating']})")
            
            # Quality assessment
            issues = []
            if stream['loss_percent'] > 5:
                issues.append(f"HIGH packet loss ({stream['loss_percent']:.1f}%)")
            elif stream['loss_percent'] > 1:
                issues.append(f"Moderate packet loss ({stream['loss_percent']:.1f}%)")
            
            if stream['mean_jitter'] > 30:
                issues.append(f"HIGH jitter ({stream['mean_jitter']:.1f} ms)")
            elif stream['mean_jitter'] > 20:
                issues.append(f"Moderate jitter ({stream['mean_jitter']:.1f} ms)")
            
            if issues:
                lines.append(f"  Issues:         {', '.join(issues)}")
            else:
                lines.append(f"  Issues:         None - Good quality")
        
        lines.append("")
        lines.append("=" * 100)
        lines.append("")
        lines.append("MOS Score Reference:")
        lines.append("  5.0       - Excellent (imperceptible impairment)")
        lines.append("  4.0-4.9   - Good (perceptible but not annoying)")
        lines.append("  3.0-3.9   - Fair (slightly annoying)")
        lines.append("  2.0-2.9   - Poor (annoying)")
        lines.append("  1.0-1.9   - Bad (very annoying)")
        lines.append("")
        lines.append("Recommendations:")
        if avg_mos >= 4.0:
            lines.append("  ✓ VoIP quality is good. No immediate action required.")
        elif avg_mos >= 3.6:
            lines.append("  ○ VoIP quality is acceptable but could be improved.")
            lines.append("    - Check network congestion and QoS settings")
            lines.append("    - Monitor for packet loss and jitter spikes")
        else:
            lines.append("  ⚠ VoIP quality is poor. Immediate action recommended:")
            lines.append("    - Investigate network issues (congestion, routing)")
            lines.append("    - Enable QoS/traffic prioritization for VoIP")
            lines.append("    - Check for bandwidth limitations")
            lines.append("    - Consider upgrading network infrastructure")
        
        lines.append("")
        lines.append("=" * 100)
        
        return '\n'.join(lines) + '\n'

