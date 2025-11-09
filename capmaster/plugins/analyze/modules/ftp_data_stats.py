"""FTP-DATA statistics module."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class FtpDataStatsModule(AnalysisModule):
    """Generate FTP-DATA transfer statistics.
    
    Analyzes FTP data channel transfers to extract:
    - Data transfer sessions
    - Transfer sizes and rates
    - Connection endpoints
    - Transfer direction (upload/download)
    
    This helps identify FTP data transfer issues and performance problems.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "ftp_data_stats"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "ftp-data-stats.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"ftp-data"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for FTP-DATA statistics extraction
        """
        return [
            "-Y",
            "ftp-data",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_relative",
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
            "tcp.len",
            "-e",
            "frame.len",
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process FTP-DATA transfers to generate statistics.
        
        Groups transfers by TCP stream and calculates:
        - Total bytes transferred
        - Number of packets
        - Transfer duration
        - Average transfer rate
        
        Args:
            tshark_output: Raw tshark output (tab-separated fields)
            output_format: Output format ("txt" or "md", default: "txt")
            
        Returns:
            Formatted output with FTP-DATA transfer statistics
        """
        if not tshark_output.strip():
            return "No FTP-DATA transfers found\n"
        
        # Storage for stream information
        streams: dict[str, dict] = defaultdict(lambda: {
            'frames': [],
            'src': None,
            'dst': None,
            'total_bytes': 0,
            'total_payload': 0,
            'packet_count': 0,
            'start_time': None,
            'end_time': None,
        })
        
        for line in tshark_output.strip().split('\n'):
            if not line.strip():
                continue
            
            parts = line.split('\t')
            if len(parts) < 9:
                continue
            
            frame_num = parts[0] if parts[0] else ""
            time_rel = parts[1] if parts[1] else "0"
            src_ip = parts[2] if parts[2] else ""
            src_port = parts[3] if parts[3] else ""
            dst_ip = parts[4] if parts[4] else ""
            dst_port = parts[5] if parts[5] else ""
            stream_id = parts[6] if parts[6] else ""
            tcp_len = parts[7] if parts[7] else "0"
            frame_len = parts[8] if parts[8] else "0"
            
            if not stream_id:
                continue
            
            stream = streams[stream_id]
            
            # Record frame
            if frame_num:
                stream['frames'].append(frame_num)
            
            # Record endpoints (use first occurrence)
            if not stream['src'] and src_ip and src_port:
                stream['src'] = f"{src_ip}:{src_port}"
            if not stream['dst'] and dst_ip and dst_port:
                stream['dst'] = f"{dst_ip}:{dst_port}"
            
            # Accumulate bytes
            try:
                stream['total_payload'] += int(tcp_len)
                stream['total_bytes'] += int(frame_len)
                stream['packet_count'] += 1
            except ValueError:
                pass
            
            # Track time
            try:
                time_val = float(time_rel)
                if stream['start_time'] is None or time_val < stream['start_time']:
                    stream['start_time'] = time_val
                if stream['end_time'] is None or time_val > stream['end_time']:
                    stream['end_time'] = time_val
            except ValueError:
                pass
        
        # Generate output
        lines = []
        lines.append("=" * 90)
        lines.append("FTP-DATA Transfer Statistics")
        lines.append("=" * 90)
        lines.append("")
        
        # Summary
        total_streams = len(streams)
        total_bytes = sum(s['total_bytes'] for s in streams.values())
        total_payload = sum(s['total_payload'] for s in streams.values())
        total_packets = sum(s['packet_count'] for s in streams.values())
        
        lines.append("Summary:")
        lines.append("-" * 90)
        lines.append(f"  Total FTP-DATA Streams:  {total_streams}")
        lines.append(f"  Total Packets:           {total_packets}")
        lines.append(f"  Total Bytes (with headers): {total_bytes:,} bytes ({total_bytes / 1024:.2f} KB)")
        lines.append(f"  Total Payload:           {total_payload:,} bytes ({total_payload / 1024:.2f} KB)")
        if total_streams > 0:
            lines.append(f"  Average per Stream:      {total_payload / total_streams:.2f} bytes")
        lines.append("")
        
        # Detailed stream information
        lines.append("Transfer Details:")
        lines.append("-" * 90)
        lines.append(f"{'Stream':<8} {'Packets':<10} {'Payload':<15} {'Duration':<12} {'Rate':<15} {'Endpoints':<30}")
        lines.append("-" * 90)
        
        # Sort streams by stream ID numerically
        sorted_streams = sorted(streams.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0)
        
        for stream_id, info in sorted_streams:
            packets = info['packet_count']
            payload = info['total_payload']
            
            # Calculate duration and rate
            if info['start_time'] is not None and info['end_time'] is not None:
                duration = info['end_time'] - info['start_time']
                if duration > 0:
                    rate = payload / duration  # bytes per second
                    rate_str = f"{rate:.2f} B/s"
                    if rate > 1024:
                        rate_str = f"{rate / 1024:.2f} KB/s"
                    if rate > 1048576:
                        rate_str = f"{rate / 1048576:.2f} MB/s"
                    duration_str = f"{duration:.3f} s"
                else:
                    rate_str = "N/A"
                    duration_str = "0.000 s"
            else:
                duration_str = "N/A"
                rate_str = "N/A"
            
            # Format payload size
            if payload < 1024:
                payload_str = f"{payload} B"
            elif payload < 1048576:
                payload_str = f"{payload / 1024:.2f} KB"
            else:
                payload_str = f"{payload / 1048576:.2f} MB"
            
            # Format endpoints
            src = info['src'] if info['src'] else "Unknown"
            dst = info['dst'] if info['dst'] else "Unknown"
            endpoints = f"{src} -> {dst}"
            endpoints_display = endpoints[:29] if len(endpoints) <= 29 else endpoints[:26] + "..."
            
            lines.append(f"{stream_id:<8} {packets:<10} {payload_str:<15} {duration_str:<12} {rate_str:<15} {endpoints_display:<30}")
        
        lines.append("")
        
        # Size distribution
        lines.append("Transfer Size Distribution:")
        lines.append("-" * 90)
        
        size_buckets = {
            "< 1KB": 0,
            "1KB - 10KB": 0,
            "10KB - 100KB": 0,
            "100KB - 1MB": 0,
            "1MB - 10MB": 0,
            "> 10MB": 0
        }
        
        for info in streams.values():
            payload = info['total_payload']
            if payload < 1024:
                size_buckets["< 1KB"] += 1
            elif payload < 10240:
                size_buckets["1KB - 10KB"] += 1
            elif payload < 102400:
                size_buckets["10KB - 100KB"] += 1
            elif payload < 1048576:
                size_buckets["100KB - 1MB"] += 1
            elif payload < 10485760:
                size_buckets["1MB - 10MB"] += 1
            else:
                size_buckets["> 10MB"] += 1
        
        lines.append(f"{'Size Range':<20} {'Count':>10} {'Percentage':>12}")
        lines.append("-" * 90)
        
        for size_range in ["< 1KB", "1KB - 10KB", "10KB - 100KB", "100KB - 1MB", "1MB - 10MB", "> 10MB"]:
            count = size_buckets[size_range]
            pct = (count / total_streams * 100) if total_streams > 0 else 0
            lines.append(f"{size_range:<20} {count:>10} {pct:>11.1f}%")
        
        lines.append("")
        
        # Detailed stream breakdown
        lines.append("Detailed Stream Information:")
        lines.append("-" * 90)
        
        for stream_id, info in sorted_streams:
            lines.append(f"\nStream {stream_id}:")
            lines.append(f"  Source:      {info['src'] if info['src'] else 'Unknown'}")
            lines.append(f"  Destination: {info['dst'] if info['dst'] else 'Unknown'}")
            lines.append(f"  Packets:     {info['packet_count']}")
            lines.append(f"  Payload:     {info['total_payload']:,} bytes ({info['total_payload'] / 1024:.2f} KB)")
            lines.append(f"  Total Size:  {info['total_bytes']:,} bytes ({info['total_bytes'] / 1024:.2f} KB)")
            
            if info['start_time'] is not None and info['end_time'] is not None:
                duration = info['end_time'] - info['start_time']
                lines.append(f"  Duration:    {duration:.3f} seconds")
                if duration > 0:
                    rate = info['total_payload'] / duration
                    lines.append(f"  Avg Rate:    {rate:.2f} bytes/sec ({rate / 1024:.2f} KB/s)")
            
            # Show sample frame numbers
            if info['frames']:
                frame_sample = ', '.join(info['frames'][:10])
                if len(info['frames']) > 10:
                    frame_sample += f", ... ({len(info['frames']) - 10} more)"
                lines.append(f"  Frames:      {frame_sample}")
        
        lines.append("")
        lines.append("=" * 90)
        
        return '\n'.join(lines) + '\n'

