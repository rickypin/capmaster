"""TLS alert message statistics module."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class TlsAlertModule(AnalysisModule):
    """Generate TLS alert message statistics.

    Extracts TLS alert messages and aggregates by alert type.
    Uses defaultdict for grouping and set for deduplicating connections.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "tls_alert"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "tls-alert-message.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"tls", "ssl"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for TLS alert message extraction
        """
        return [
            "-Y",
            "tls.alert_message && tcp",
            "-o",
            "tcp.desegment_tcp_streams:TRUE",
            "-o",
            "tcp.reassemble_out_of_order:TRUE",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "tls.alert_message.desc",
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process TLS alert messages to aggregate by alert type.
        
        Groups alerts by description, counts occurrences, and lists unique connections.
        
        Args:
            tshark_output: Raw tshark output (tab-separated fields)
            output_format: Output format ("txt" or "md", default: "txt")
            
        Returns:
            Formatted output with TLS alerts grouped by type
        """
        # Storage: {alert_desc: {count, connections}}
        alerts: dict[str, dict[str, object]] = defaultdict(
            lambda: {"count": 0, "connections": set()}
        )
        
        for line in tshark_output.strip().split('\n'):
            if not line.strip():
                continue
            
            parts = line.split('\t')
            if len(parts) < 5:
                continue
            
            src_ip = parts[0] if parts[0] else ""
            src_port = parts[1] if parts[1] else ""
            dst_ip = parts[2] if parts[2] else ""
            dst_port = parts[3] if parts[3] else ""
            alert_desc = parts[4] if parts[4] else "Unknown"
            
            connection = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            
            alerts[alert_desc]["count"] += 1  # type: ignore
            alerts[alert_desc]["connections"].add(connection)  # type: ignore
        
        # Sort by alert description
        sorted_alerts = sorted(alerts.items())
        
        # Generate output
        lines = []
        for alert_desc, data in sorted_alerts:
            count = data["count"]
            connections = sorted(data["connections"])  # type: ignore
            
            lines.append(f"TLS Alert: {alert_desc} (count {count}):")
            for conn in connections:
                lines.append(conn)
            lines.append("")  # Empty line between groups
        
        return '\n'.join(lines)

