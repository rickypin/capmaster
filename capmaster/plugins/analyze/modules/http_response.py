"""HTTP response code statistics module."""

from collections import defaultdict
from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class HttpResponseModule(AnalysisModule):
    """Generate HTTP response code statistics.

    Extracts HTTP response codes and aggregates by status code.
    Uses defaultdict for grouping connections by response code.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "http_response"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "http-response-code.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"http"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for HTTP response code extraction
        """
        return [
            "-Y",
            "http.response",
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
            "http.response.code",
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process HTTP response codes to aggregate by status code.
        
        Groups responses by status code and lists connections.
        
        Args:
            tshark_output: Raw tshark output (tab-separated fields)
            output_format: Output format ("txt" or "md", default: "txt")
            
        Returns:
            Formatted output with HTTP responses grouped by status code
        """
        # Storage: {status_code: [connections]}
        responses: dict[str, list[str]] = defaultdict(list)
        
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
            status_code = parts[4] if parts[4] else "Unknown"
            
            connection = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            responses[status_code].append(connection)
        
        # Sort by status code (numerically)
        sorted_codes = sorted(responses.keys(), key=lambda x: int(x) if x.isdigit() else 999)
        
        # Generate output
        lines = []
        for code in sorted_codes:
            connections = responses[code]
            lines.append(f"Status {code}:")
            for conn in connections:
                lines.append(conn)
            lines.append("")  # Empty line between groups
        
        return '\n'.join(lines)

