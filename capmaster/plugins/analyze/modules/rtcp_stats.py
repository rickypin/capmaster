"""RTCP (RTP Control Protocol) statistics module."""

from pathlib import Path
from collections import Counter, defaultdict

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class RtcpStatsModule(AnalysisModule):
    """Generate RTCP protocol statistics.
    
    Analyzes RTP Control Protocol (RTCP) messages to extract:
    - Packet types (SR, RR, SDES, BYE, APP)
    - Sender Reports (SR) - transmission statistics
    - Receiver Reports (RR) - reception quality
    - Source Description (SDES) - participant information
    - Goodbye (BYE) - session termination
    
    RTCP provides out-of-band statistics and control information for RTP flows.
    This module helps monitor VoIP call quality and identify issues.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "rtcp_stats"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "rtcp-stats.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"rtcp"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for RTCP analysis
        """
        return [
            "-Y", "rtcp",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.len",
            "-e", "ip.src",
            "-e", "udp.srcport",
            "-e", "ip.dst",
            "-e", "udp.dstport",
            "-e", "rtcp.pt",
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process RTCP messages to generate statistics.
        
        Args:
            tshark_output: Raw tshark output
            output_format: Output format ("txt" or "md", default: "txt")
            
        Returns:
            Formatted output with RTCP statistics
        """
        if not tshark_output.strip():
            return "No RTCP messages found\n"
        
        lines = []
        lines.append("=" * 80)
        lines.append("RTCP Statistics")
        lines.append("=" * 80)
        lines.append("")
        
        # RTCP packet type mapping
        pt_names = {
            '200': 'SR (Sender Report)',
            '201': 'RR (Receiver Report)',
            '202': 'SDES (Source Description)',
            '203': 'BYE (Goodbye)',
            '204': 'APP (Application-Defined)',
        }
        
        # Parse RTCP messages
        messages = []
        packet_types = Counter()
        streams = defaultdict(lambda: {'packets': 0, 'types': Counter()})
        
        for line in tshark_output.strip().split('\n'):
            parts = line.split('\t')
            if len(parts) < 7:
                continue
            
            frame_num = parts[0]
            frame_len = parts[1]
            src_ip = parts[2]
            src_port = parts[3]
            dst_ip = parts[4]
            dst_port = parts[5]
            pt_values = parts[6]  # Can be multiple comma-separated values
            
            # Parse packet types (can be multiple in one RTCP compound packet)
            pts = [pt.strip() for pt in pt_values.split(',') if pt.strip()]
            
            stream_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            
            for pt in pts:
                packet_types[pt] += 1
                streams[stream_key]['types'][pt] += 1
            
            streams[stream_key]['packets'] += 1
            
            messages.append({
                'frame': frame_num,
                'size': int(frame_len) if frame_len else 0,
                'src': f"{src_ip}:{src_port}",
                'dst': f"{dst_ip}:{dst_port}",
                'types': pts,
            })
        
        total_messages = len(messages)
        total_packets = sum(packet_types.values())
        
        # Summary
        lines.append("Summary:")
        lines.append("-" * 80)
        lines.append(f"  Total RTCP Messages:     {total_messages}")
        lines.append(f"  Total RTCP Packets:      {total_packets}")
        lines.append(f"  Unique Streams:          {len(streams)}")
        lines.append("")
        
        # Packet type distribution
        if packet_types:
            lines.append("RTCP Packet Types:")
            lines.append("-" * 80)
            lines.append(f"{'Type':<30} {'Count':<10} {'Percentage':<12}")
            lines.append("-" * 80)
            
            for pt, count in packet_types.most_common():
                pt_name = pt_names.get(pt, f'Unknown ({pt})')
                percentage = (count / total_packets) * 100
                lines.append(f"{pt_name:<30} {count:<10} {percentage:>5.1f}%")
            
            lines.append("")
        
        # Stream statistics
        if streams:
            lines.append("RTCP Streams:")
            lines.append("-" * 80)
            lines.append(f"{'Stream':<45} {'Messages':<12} {'Packet Types':<20}")
            lines.append("-" * 80)
            
            # Sort by message count
            sorted_streams = sorted(
                streams.items(),
                key=lambda x: x[1]['packets'],
                reverse=True
            )[:10]
            
            for stream, stats in sorted_streams:
                # Get top packet types for this stream
                top_types = ', '.join([
                    pt_names.get(pt, pt)[:10]
                    for pt, _ in stats['types'].most_common(3)
                ])
                lines.append(f"{stream:<45} {stats['packets']:<12} {top_types:<20}")
            
            lines.append("")
        
        # Quality indicators
        sr_count = packet_types.get('200', 0)
        rr_count = packet_types.get('201', 0)
        
        if sr_count > 0 or rr_count > 0:
            lines.append("Quality Monitoring:")
            lines.append("-" * 80)
            lines.append(f"  Sender Reports (SR):     {sr_count}")
            lines.append(f"  Receiver Reports (RR):   {rr_count}")
            
            if sr_count > 0:
                lines.append("  ✓ Sender reports present - transmission statistics available")
            if rr_count > 0:
                lines.append("  ✓ Receiver reports present - reception quality data available")
            
            if sr_count == 0 and rr_count == 0:
                lines.append("  ⚠ No SR/RR packets found - quality monitoring may be limited")
            
            lines.append("")
        
        # Session control
        sdes_count = packet_types.get('202', 0)
        bye_count = packet_types.get('203', 0)
        
        if sdes_count > 0 or bye_count > 0:
            lines.append("Session Control:")
            lines.append("-" * 80)
            lines.append(f"  Source Description (SDES): {sdes_count}")
            lines.append(f"  Goodbye (BYE):             {bye_count}")
            
            if bye_count > 0:
                lines.append(f"  ℹ {bye_count} session(s) terminated gracefully")
            
            lines.append("")
        
        # Message size distribution
        all_sizes = [m['size'] for m in messages]
        if all_sizes:
            lines.append("Message Size Distribution:")
            lines.append("-" * 80)
            
            avg_size = sum(all_sizes) / len(all_sizes)
            min_size = min(all_sizes)
            max_size = max(all_sizes)
            
            lines.append(f"  Average Size:            {avg_size:.0f} bytes")
            lines.append(f"  Min Size:                {min_size} bytes")
            lines.append(f"  Max Size:                {max_size} bytes")
            lines.append("")
        
        lines.append("=" * 80)
        lines.append("")
        lines.append("RTCP Protocol Notes:")
        lines.append("  - RTCP provides feedback on RTP stream quality")
        lines.append("  - Typically sent periodically (every few seconds)")
        lines.append("  - Packet Types:")
        lines.append("    * SR (200)  - Sender Report: transmission and reception statistics")
        lines.append("    * RR (201)  - Receiver Report: reception statistics only")
        lines.append("    * SDES (202) - Source Description: participant identification")
        lines.append("    * BYE (203)  - Goodbye: indicates end of participation")
        lines.append("    * APP (204)  - Application-specific messages")
        lines.append("  - RTCP packets are often compound (multiple types in one message)")
        lines.append("  - Used for:")
        lines.append("    * Quality monitoring (packet loss, jitter)")
        lines.append("    * Synchronization between media streams")
        lines.append("    * Participant identification")
        lines.append("    * Session size estimation")
        lines.append("")
        lines.append("=" * 80)
        
        return '\n'.join(lines) + '\n'

