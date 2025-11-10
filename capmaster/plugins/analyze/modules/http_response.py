"""HTTP response code statistics module."""

from __future__ import annotations

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
        
        sorted_codes = sorted(responses.keys(), key=lambda x: int(x) if x.isdigit() else 999)
        total_count = sum(len(conns) for conns in responses.values())

        def classify(code: str) -> str:
            if code.startswith('5'):
                return "High"
            if code.startswith('4'):
                return "Medium"
            return "Low"

        lines: list[str] = []
        lines.append("HTTP Response Summary")
        lines.append("Status,Severity,Count,Share")
        for code in sorted_codes:
            count = len(responses[code])
            share = (count / total_count * 100) if total_count else 0.0
            severity = classify(code)
            lines.append(f"{code},{severity},{count},{share:.1f}%")

        highlighted = [code for code in sorted_codes if classify(code) != "Low"]
        highlighted = highlighted[:3]
        if highlighted:
            lines.append("")
            lines.append("Highlighted Statuses")
            for code in highlighted:
                severity = classify(code)
                connections = responses[code]
                lines.append(f"{code} [{severity}] total={len(connections)}")
                samples = self.sample_items(connections, limit=3)
                for conn in samples:
                    lines.append(f"  sample: {conn}")
                remaining = len(connections) - len(samples)
                if remaining > 0:
                    lines.append(f"  ... {remaining} more")

        return '\n'.join(lines)

