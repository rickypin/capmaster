"""FTP-DATA statistics module."""

from __future__ import annotations

from collections import Counter, defaultdict
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
        
        def classify_transfer(payload: int, duration: float | None, rate: float | None) -> str:
            if payload < 10_240:
                return "Low"
            if duration is None or rate is None or duration <= 0:
                return "Medium"
            if rate < 50 * 1024:
                return "High"
            if rate < 200 * 1024:
                return "Medium"
            return "Low"

        severity_rank = {"High": 0, "Medium": 1, "Low": 2}
        stream_summaries: list[tuple[str, dict, str, float | None, float | None]] = []
        severity_counts: Counter[str] = Counter()
        for stream_id, info in streams.items():
            duration = None
            rate = None
            if info['start_time'] is not None and info['end_time'] is not None:
                duration = info['end_time'] - info['start_time']
                if duration > 0:
                    rate = info['total_payload'] / duration
            severity = classify_transfer(info['total_payload'], duration, rate)
            severity_counts[severity] += 1
            stream_summaries.append((stream_id, info, severity, duration, rate))

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
            lines.append(f"  High Severity Streams:   {severity_counts['High']}")
            lines.append(f"  Medium Severity Streams: {severity_counts['Medium']}")
            lines.append(f"  Low Severity Streams:    {severity_counts['Low']}")
        lines.append("")
        
        if stream_summaries:
            def format_size(value: int) -> str:
                if value < 1024:
                    return f"{value} B"
                if value < 1_048_576:
                    return f"{value / 1024:.2f} KB"
                return f"{value / 1_048_576:.2f} MB"

            def format_rate(rate: float | None) -> str:
                if rate is None or rate <= 0:
                    return "N/A"
                if rate < 1024:
                    return f"{rate:.2f} B/s"
                if rate < 1_048_576:
                    return f"{rate / 1024:.2f} KB/s"
                return f"{rate / 1_048_576:.2f} MB/s"

            lines.append("Highlighted Transfers:")
            lines.append("-" * 90)
            lines.append("Stream,Packets,Payload,Duration(s),Rate,Severity,Endpoints")
            stream_summaries.sort(
                key=lambda item: (
                    severity_rank[item[2]],
                    -item[1]['total_payload'],
                )
            )
            for stream_id, info, severity, duration, rate in stream_summaries[:5]:
                packets = info['packet_count']
                payload_str = format_size(info['total_payload'])
                duration_str = f"{duration:.3f}" if duration is not None else "N/A"
                rate_str = format_rate(rate)
                src = info['src'] or "Unknown"
                dst = info['dst'] or "Unknown"
                endpoints = f"{src}->{dst}"
                lines.append(
                    f"{stream_id},{packets},{payload_str},{duration_str},{rate_str},{severity},{endpoints}"
                )
            remaining = total_streams - min(5, total_streams)
            if remaining > 0:
                lines.append(f"... {remaining} additional transfer(s) hidden")
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
        
        lines.append("")
        lines.append("=" * 90)
        
        return '\n'.join(lines) + '\n'

