"""MQ (Message Queue) statistics module."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class MqStatsModule(AnalysisModule):
    """Generate MQ (Message Queue) statistics.

    Analyzes IBM MQ (WebSphere MQ) protocol messages to extract:
    - Message counts and sizes
    - Completion codes (MQCC_OK, MQCC_WARNING, MQCC_FAILED)
    - Reason codes (detailed error information)
    - Error message detection and statistics
    - Queue manager connections
    - Channel information
    - Connection endpoints
    - Message flow patterns

    This helps identify message queue performance issues and errors.
    Completion codes and reason codes are critical for troubleshooting
    MQ communication failures and application errors.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "mq_stats"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "mq-stats.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"mq"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for MQ statistics extraction
        """
        return [
            "-Y",
            "mq",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.len",
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
            "mq.api.completioncode",  # MQ API completion code
            "-e",
            "mq.api.reasoncode",      # MQ API reason code
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process MQ messages to generate statistics.

        Groups MQ messages by:
        1. Completion codes and reason codes (for error detection)
        2. TCP streams (connections)
        3. Endpoints
        4. Message sizes

        Args:
            tshark_output: Raw tshark output (tab-separated fields)
            output_format: Output format ("txt" or "md", default: "txt")

        Returns:
            Formatted output with MQ statistics including error analysis
        """
        if not tshark_output.strip():
            return "No MQ messages found\n"

        # Counters and storage
        total_messages = 0
        total_size = 0

        # Completion code and reason code tracking
        completion_codes: dict[str, list[str]] = defaultdict(list)  # {code: [connections]}
        reason_codes: dict[str, list[str]] = defaultdict(list)      # {code: [connections]}
        error_messages = 0  # Messages with non-zero completion code

        # Size distribution
        size_buckets = {
            "< 1KB": 0,
            "1KB - 10KB": 0,
            "10KB - 100KB": 0,
            "100KB - 1MB": 0,
            "> 1MB": 0
        }

        # Stream tracking
        streams: dict[str, dict] = defaultdict(lambda: {
            'count': 0,
            'src': None,
            'dst': None,
            'total_size': 0,
            'frames': [],
            'errors': 0  # Count of error messages in this stream
        })

        # Connection tracking
        connections: dict[str, int] = defaultdict(int)

        for line in tshark_output.strip().split('\n'):
            if not line.strip():
                continue

            parts = line.split('\t')
            if len(parts) < 9:  # Now expecting 9 fields (added 2 new fields)
                # Handle old format without completion/reason codes
                if len(parts) >= 7:
                    parts.extend(['', ''])  # Add empty completion and reason codes
                else:
                    continue

            frame_num = parts[0] if parts[0] else ""
            frame_len = parts[1] if parts[1] else "0"
            src_ip = parts[2] if parts[2] else ""
            src_port = parts[3] if parts[3] else ""
            dst_ip = parts[4] if parts[4] else ""
            dst_port = parts[5] if parts[5] else ""
            stream_id = parts[6] if parts[6] else ""
            completion_code = parts[7] if len(parts) > 7 and parts[7] else ""
            reason_code = parts[8] if len(parts) > 8 and parts[8] else ""

            total_messages += 1

            # Parse frame length
            try:
                size = int(frame_len)
                total_size += size

                # Categorize by size
                if size < 1024:
                    size_buckets["< 1KB"] += 1
                elif size < 10240:
                    size_buckets["1KB - 10KB"] += 1
                elif size < 102400:
                    size_buckets["10KB - 100KB"] += 1
                elif size < 1048576:
                    size_buckets["100KB - 1MB"] += 1
                else:
                    size_buckets["> 1MB"] += 1
            except ValueError:
                size = 0

            # Track completion and reason codes
            connection = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"

            if completion_code:
                completion_codes[completion_code].append(connection)
                # Non-zero completion code indicates an error
                if completion_code != "0":
                    error_messages += 1
                    if stream_id and stream_id in streams:
                        streams[stream_id]['errors'] += 1

            if reason_code:
                reason_codes[reason_code].append(connection)

            # Track stream
            if stream_id:
                stream = streams[stream_id]
                stream['count'] += 1
                stream['total_size'] += size
                if frame_num:
                    stream['frames'].append(frame_num)

                # Record endpoints (use first occurrence)
                if not stream['src'] and src_ip and src_port:
                    stream['src'] = f"{src_ip}:{src_port}"
                if not stream['dst'] and dst_ip and dst_port:
                    stream['dst'] = f"{dst_ip}:{dst_port}"

            # Track connection
            if src_ip and dst_ip:
                connections[connection] += 1
        
        # Generate output
        lines = []
        lines.append("=" * 90)
        lines.append("MQ (Message Queue) Statistics")
        lines.append("=" * 90)
        lines.append("")

        # Summary
        lines.append("Summary:")
        lines.append("-" * 90)
        lines.append(f"  Total MQ Messages:       {total_messages}")
        lines.append(f"  Error Messages:          {error_messages} ({(error_messages/total_messages*100) if total_messages > 0 else 0:.1f}%)")
        lines.append(f"  Total MQ Streams:        {len(streams)}")
        lines.append(f"  Unique Connections:      {len(connections)}")
        if total_messages > 0:
            avg_size = total_size / total_messages
            lines.append(f"  Total Data Size:         {total_size:,} bytes ({total_size / 1024:.2f} KB)")
            lines.append(f"  Average Message Size:    {avg_size:.2f} bytes")
        lines.append("")

        # Completion Code Statistics (Error Detection)
        if completion_codes:
            lines.append("Completion Code Statistics:")
            lines.append("-" * 90)
            lines.append(f"{'Code':<10} {'Count':>10} {'Description':<30} {'Sample Connections':<40}")
            lines.append("-" * 90)

            # Sort by code (numerically if possible)
            sorted_codes = sorted(completion_codes.keys(),
                                key=lambda x: int(x) if x.isdigit() else 9999)

            # MQ Completion Code descriptions
            code_descriptions = {
                "0": "Success (MQCC_OK)",
                "1": "Warning (MQCC_WARNING)",
                "2": "Failed (MQCC_FAILED)",
            }

            for code in sorted_codes:
                conns = completion_codes[code]
                count = len(conns)
                desc = code_descriptions.get(code, "Unknown")

                # Show first connection as sample
                sample = conns[0] if conns else ""
                sample_display = sample[:39] if len(sample) <= 39 else sample[:36] + "..."

                lines.append(f"{code:<10} {count:>10} {desc:<30} {sample_display:<40}")

            lines.append("")

        # Reason Code Statistics (Detailed Error Information)
        if reason_codes:
            lines.append("Reason Code Statistics (Top 10):")
            lines.append("-" * 90)
            lines.append(f"{'Code':<10} {'Count':>10} {'Sample Connection':<70}")
            lines.append("-" * 90)

            # Sort by frequency (most common first)
            sorted_reasons = sorted(reason_codes.items(),
                                  key=lambda x: -len(x[1]))[:10]

            for code, conns in sorted_reasons:
                if not code:  # Skip empty codes
                    continue
                count = len(conns)

                # Show first connection as sample
                sample = conns[0] if conns else ""
                sample_display = sample[:69] if len(sample) <= 69 else sample[:66] + "..."

                lines.append(f"{code:<10} {count:>10} {sample_display:<70}")

            lines.append("")

        # Message Size Distribution
        lines.append("Message Size Distribution:")
        lines.append("-" * 90)
        lines.append(f"{'Size Range':<20} {'Count':>10} {'Percentage':>12}")
        lines.append("-" * 90)

        for size_range in ["< 1KB", "1KB - 10KB", "10KB - 100KB", "100KB - 1MB", "> 1MB"]:
            count = size_buckets[size_range]
            pct = (count / total_messages * 100) if total_messages > 0 else 0
            lines.append(f"{size_range:<20} {count:>10} {pct:>11.1f}%")
        lines.append("")
        
        # Stream Information
        if streams:
            lines.append("MQ Streams (by TCP stream):")
            lines.append("-" * 90)
            lines.append(f"{'Stream':<10} {'Messages':>10} {'Total Size':<15} {'Endpoints':<55}")
            lines.append("-" * 90)
            
            # Sort streams by stream ID numerically
            sorted_streams = sorted(streams.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0)
            
            for stream_id, info in sorted_streams[:20]:  # Show top 20 streams
                count = info['count']
                total = info['total_size']
                
                # Format size
                if total < 1024:
                    size_str = f"{total} B"
                elif total < 1048576:
                    size_str = f"{total / 1024:.2f} KB"
                else:
                    size_str = f"{total / 1048576:.2f} MB"
                
                # Format endpoints
                src = info['src'] if info['src'] else "Unknown"
                dst = info['dst'] if info['dst'] else "Unknown"
                endpoints = f"{src} -> {dst}"
                endpoints_display = endpoints[:54] if len(endpoints) <= 54 else endpoints[:51] + "..."
                
                lines.append(f"{stream_id:<10} {count:>10} {size_str:<15} {endpoints_display:<55}")
            
            if len(sorted_streams) > 20:
                lines.append(f"... and {len(sorted_streams) - 20} more streams")
            lines.append("")
        
        # Top Connections
        if connections:
            lines.append("Top Connections (by message count):")
            lines.append("-" * 90)
            lines.append(f"{'Connection':<70} {'Messages':>10}")
            lines.append("-" * 90)
            
            sorted_conns = sorted(connections.items(), key=lambda x: -x[1])
            for conn, count in sorted_conns[:10]:
                conn_display = conn[:69] if len(conn) <= 69 else conn[:66] + "..."
                lines.append(f"{conn_display:<70} {count:>10}")
            
            if len(sorted_conns) > 10:
                lines.append(f"... and {len(sorted_conns) - 10} more connections")
            lines.append("")
        
        lines.append("=" * 90)
        
        return '\n'.join(lines) + '\n'

