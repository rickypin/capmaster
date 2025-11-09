"""SSH statistics module."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class SshStatsModule(AnalysisModule):
    """Generate SSH statistics.
    
    Analyzes SSH (Secure Shell) connections to extract:
    - SSH protocol versions
    - Connection endpoints (source/destination IP and ports)
    - TCP stream information
    - Connection counts and patterns
    
    This helps identify SSH connection issues and security analysis.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "ssh_stats"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "ssh-stats.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"ssh"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for SSH statistics extraction
        """
        return [
            "-Y",
            "ssh",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "tcp.stream",
            "-e",
            "ssh.protocol",
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process SSH connection data to generate statistics.
        
        Groups SSH connections by:
        1. TCP streams
        2. Protocol versions
        3. Connection endpoints
        
        Args:
            tshark_output: Raw tshark output (tab-separated fields)
            output_format: Output format ("txt" or "md", default: "txt")
            
        Returns:
            Formatted output with SSH statistics
        """
        if not tshark_output.strip():
            return "No SSH traffic found\n"
        
        # Storage for analysis
        stream_info: dict[str, dict] = defaultdict(lambda: {
            'frames': [],
            'src': None,
            'dst': None,
            'protocol': None
        })
        protocol_counter: Counter[str] = Counter()
        connection_counter: Counter[str] = Counter()
        
        for line in tshark_output.strip().split('\n'):
            if not line.strip():
                continue
            
            parts = line.split('\t')
            if len(parts) < 7:
                continue
            
            frame_num = parts[0] if parts[0] else ""
            src_ip = parts[1] if parts[1] else ""
            src_port = parts[2] if parts[2] else ""
            dst_ip = parts[3] if parts[3] else ""
            dst_port = parts[4] if parts[4] else ""
            stream_id = parts[5] if parts[5] else ""
            protocol = parts[6] if parts[6] else ""
            
            if not stream_id:
                continue
            
            # Record frame for this stream
            if frame_num:
                stream_info[stream_id]['frames'].append(frame_num)
            
            # Record connection endpoints (use first occurrence)
            if not stream_info[stream_id]['src'] and src_ip and src_port:
                stream_info[stream_id]['src'] = f"{src_ip}:{src_port}"
            if not stream_info[stream_id]['dst'] and dst_ip and dst_port:
                stream_info[stream_id]['dst'] = f"{dst_ip}:{dst_port}"
            
            # Record protocol version (use first occurrence)
            if protocol and not stream_info[stream_id]['protocol']:
                stream_info[stream_id]['protocol'] = protocol
                protocol_counter[protocol] += 1
            
            # Count connection
            if src_ip and dst_ip:
                connection = f"{src_ip}:{src_port} <-> {dst_ip}:{dst_port}"
                connection_counter[connection] += 1
        
        # Generate output
        lines = []
        lines.append("=" * 80)
        lines.append("SSH Statistics")
        lines.append("=" * 80)
        lines.append("")
        
        # SSH Protocol Versions
        if protocol_counter:
            lines.append("SSH Protocol Versions:")
            lines.append("-" * 80)
            lines.append(f"{'Protocol Version':<40} {'Count':>10}")
            lines.append("-" * 80)
            
            for protocol, count in sorted(protocol_counter.items(), key=lambda x: -x[1]):
                lines.append(f"{protocol:<40} {count:>10}")
            lines.append("")
        
        # SSH Connections (TCP Streams)
        if stream_info:
            lines.append("SSH Connections (by TCP Stream):")
            lines.append("-" * 80)
            lines.append(f"{'Stream':<10} {'Frames':<10} {'Source':<25} {'Destination':<25} {'Protocol':<20}")
            lines.append("-" * 80)
            
            # Sort by stream ID numerically
            sorted_streams = sorted(stream_info.keys(), key=lambda x: int(x) if x.isdigit() else 0)
            
            for stream_id in sorted_streams:
                info = stream_info[stream_id]
                frame_count = len(info['frames'])
                src = info['src'] if info['src'] else "Unknown"
                dst = info['dst'] if info['dst'] else "Unknown"
                protocol = info['protocol'] if info['protocol'] else "Unknown"
                
                # Truncate long values for display
                src_display = src[:24] if len(src) <= 24 else src[:21] + "..."
                dst_display = dst[:24] if len(dst) <= 24 else dst[:21] + "..."
                protocol_display = protocol[:19] if len(protocol) <= 19 else protocol[:16] + "..."
                
                lines.append(f"{stream_id:<10} {frame_count:<10} {src_display:<25} {dst_display:<25} {protocol_display:<20}")
            lines.append("")
        
        # Connection Details
        if connection_counter:
            lines.append("Connection Packet Counts:")
            lines.append("-" * 80)
            lines.append(f"{'Connection':<60} {'Packets':>10}")
            lines.append("-" * 80)
            
            for connection, count in sorted(connection_counter.items(), key=lambda x: -x[1]):
                # Truncate long connection strings
                conn_display = connection[:59] if len(connection) <= 59 else connection[:56] + "..."
                lines.append(f"{conn_display:<60} {count:>10}")
            lines.append("")
        
        # Detailed Stream Information
        if stream_info:
            lines.append("Detailed Stream Information:")
            lines.append("-" * 80)
            
            for stream_id in sorted_streams:
                info = stream_info[stream_id]
                lines.append(f"\nStream {stream_id}:")
                lines.append(f"  Source:      {info['src'] if info['src'] else 'Unknown'}")
                lines.append(f"  Destination: {info['dst'] if info['dst'] else 'Unknown'}")
                lines.append(f"  Protocol:    {info['protocol'] if info['protocol'] else 'Unknown'}")
                lines.append(f"  Frames:      {len(info['frames'])} packets")
                
                # Show first few frame numbers
                if info['frames']:
                    frame_sample = ', '.join(info['frames'][:10])
                    if len(info['frames']) > 10:
                        frame_sample += f", ... ({len(info['frames']) - 10} more)"
                    lines.append(f"  Frame IDs:   {frame_sample}")
            lines.append("")
        
        # Summary
        lines.append("=" * 80)
        lines.append("Summary:")
        lines.append(f"  Total SSH Streams:       {len(stream_info)}")
        lines.append(f"  Total SSH Packets:       {sum(len(info['frames']) for info in stream_info.values())}")
        lines.append(f"  Unique Connections:      {len(connection_counter)}")
        lines.append(f"  Protocol Versions Found: {len(protocol_counter)}")
        lines.append("=" * 80)
        
        return '\n'.join(lines) + '\n'

