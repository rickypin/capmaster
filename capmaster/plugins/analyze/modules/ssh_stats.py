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
        
        def classify_protocol(protocol: str | None) -> str:
            if not protocol:
                return "Medium"
            lower = protocol.lower()
            if lower.startswith("ssh-1"):
                return "High"
            if lower.startswith("ssh-2"):
                return "Low"
            return "Medium"

        severity_rank = {"High": 0, "Medium": 1, "Low": 2}
        stream_summaries: list[tuple[str, int, dict, str]] = []
        severity_counts: Counter[str] = Counter()
        for stream_id, info in stream_info.items():
            frame_count = len(info['frames'])
            severity = classify_protocol(info['protocol'])
            severity_counts[severity] += 1
            stream_summaries.append((stream_id, frame_count, info, severity))

        total_streams = len(stream_info)
        total_packets = sum(count for _, count, _, _ in stream_summaries)

        lines = []
        lines.append("SSH Overview")
        lines.append("Metric,Value")
        lines.append(f"Total Streams,{total_streams}")
        lines.append(f"Total Packets,{total_packets}")
        lines.append(f"High Severity Streams,{severity_counts['High']}")
        lines.append(f"Medium Severity Streams,{severity_counts['Medium']}")
        lines.append(f"Low Severity Streams,{severity_counts['Low']}")
        lines.append(f"Unique Connections,{len(connection_counter)}")
        lines.append(f"Protocol Variants,{len(protocol_counter)}")
        lines.append("")

        if protocol_counter:
            lines.append("Protocol Versions")
            lines.append("Version,Count,Severity")
            for protocol, count in sorted(protocol_counter.items(), key=lambda item: -item[1]):
                severity = classify_protocol(protocol)
                lines.append(f"{protocol},{count},{severity}")
            lines.append("")

        if stream_summaries:
            lines.append("Stream Highlights")
            lines.append("Stream,Packets,Source,Destination,Protocol,Severity")
            stream_summaries.sort(key=lambda item: (severity_rank[item[3]], -item[1]))
            for stream_id, packet_count, info, severity in stream_summaries[:5]:
                src = info['src'] or "Unknown"
                dst = info['dst'] or "Unknown"
                protocol = info['protocol'] or "Unknown"
                lines.append(
                    f"{stream_id},{packet_count},{src},{dst},{protocol},{severity}"
                )
            remaining = total_streams - min(5, total_streams)
            if remaining > 0:
                lines.append(f"... {remaining} additional stream(s) hidden")
            lines.append("")

        if connection_counter:
            lines.append("Top Connections")
            lines.append("Connection,Packets")
            for connection, count in sorted(connection_counter.items(), key=lambda item: -item[1])[:5]:
                lines.append(f"{connection},{count}")
            if len(connection_counter) > 5:
                lines.append(f"... {len(connection_counter) - 5} more connection(s)")

        return '\n'.join(lines) + '\n'

