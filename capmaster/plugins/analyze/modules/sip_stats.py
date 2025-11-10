"""SIP statistics module."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class SipStatsModule(AnalysisModule):
    """Generate SIP statistics.
    
    Analyzes SIP (Session Initiation Protocol) messages to extract:
    - SIP methods (INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, etc.)
    - SIP response codes (1xx, 2xx, 3xx, 4xx, 5xx, 6xx)
    - Connection information (source/destination IP and ports)
    
    This helps identify SIP errors and call setup issues.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "sip_stats"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "sip-stats.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"sip"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for SIP statistics extraction
        """
        return [
            "-Y",
            "sip",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "udp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.dstport",
            "-e",
            "sip.Method",
            "-e",
            "sip.Status-Code",
            "-e",
            "sip.Status-Line",
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process SIP messages to generate statistics.
        
        Groups SIP messages by:
        1. Methods (requests)
        2. Response codes (responses)
        
        Args:
            tshark_output: Raw tshark output (tab-separated fields)
            output_format: Output format ("txt" or "md", default: "txt")
            
        Returns:
            Formatted output with SIP statistics
        """
        if not tshark_output.strip():
            return "No SIP messages found\n"
        
        # Counters for methods and response codes
        method_counter: Counter[str] = Counter()
        response_counter: Counter[str] = Counter()
        
        # Detailed connection info grouped by method/response
        method_connections: dict[str, list[str]] = defaultdict(list)
        response_connections: dict[str, list[str]] = defaultdict(list)
        
        for line in tshark_output.strip().split('\n'):
            if not line.strip():
                continue
            
            parts = line.split('\t')
            if len(parts) < 9:
                continue
            
            src_ip = parts[0] if parts[0] else ""
            tcp_src_port = parts[1] if parts[1] else ""
            udp_src_port = parts[2] if parts[2] else ""
            dst_ip = parts[3] if parts[3] else ""
            tcp_dst_port = parts[4] if parts[4] else ""
            udp_dst_port = parts[5] if parts[5] else ""
            method = parts[6] if parts[6] else ""
            status_code = parts[7] if parts[7] else ""
            status_line = parts[8] if parts[8] else ""
            
            # Determine actual source and destination ports
            src_port = tcp_src_port if tcp_src_port else udp_src_port
            dst_port = tcp_dst_port if tcp_dst_port else udp_dst_port
            
            connection = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            
            # Process SIP request (has method)
            if method:
                method_counter[method] += 1
                method_connections[method].append(connection)
            
            # Process SIP response (has status code)
            if status_code:
                response_counter[status_code] += 1
                response_connections[status_code].append(connection)
        
        # Generate output
        lines = []
        lines.append("=" * 70)
        lines.append("SIP Statistics")
        lines.append("=" * 70)
        lines.append("")
        
        # SIP Methods section
        if method_counter:
            lines.append("SIP Methods (Requests):")
            lines.append("-" * 70)
            lines.append(f"{'Method':<20} {'Count':>10}")
            lines.append("-" * 70)

            sorted_methods = sorted(method_counter.items(), key=lambda x: -x[1])
            for method, count in sorted_methods:
                lines.append(f"{method:<20} {count:>10}")

            top_methods = sorted_methods[:3]
            if top_methods:
                lines.append("")
                lines.append("Top Method Samples:")
                lines.append("-" * 70)
                for method, count in top_methods:
                    lines.append(f"{method} total={count}")
                    samples = self.sample_items(method_connections[method], limit=3)
                    for conn in samples:
                        lines.append(f"  sample: {conn}")
                    remaining = len(method_connections[method]) - len(samples)
                    if remaining > 0:
                        lines.append(f"  ... {remaining} more")
                lines.append("")
        
        # SIP Response Codes section
        if response_counter:
            lines.append("SIP Response Codes:")
            lines.append("-" * 70)
            lines.append(f"{'Status Code':<20} {'Count':>10} {'Severity':>10}")
            lines.append("-" * 70)

            def classify_status(code: str) -> str:
                if code.startswith('5'):
                    return "High"
                if code.startswith('4'):
                    return "Medium"
                return "Low"

            sorted_codes = sorted(response_counter.keys(), key=lambda x: int(x) if x.isdigit() else 999)
            for code in sorted_codes:
                count = response_counter[code]
                severity = classify_status(code)
                lines.append(f"{code:<20} {count:>10} {severity:>10}")

            highlights = [code for code in sorted_codes if classify_status(code) != "Low"]
            highlights = highlights[:3]
            if highlights:
                lines.append("")
                lines.append("Highlighted Responses:")
                lines.append("-" * 70)
                for code in highlights:
                    severity = classify_status(code)
                    total = response_counter[code]
                    lines.append(f"Status {code} [{severity}] total={total}")
                    samples = self.sample_items(response_connections[code], limit=3)
                    for conn in samples:
                        lines.append(f"  sample: {conn}")
                    remaining = len(response_connections[code]) - len(samples)
                    if remaining > 0:
                        lines.append(f"  ... {remaining} more")
                lines.append("")
        
        # Summary
        lines.append("=" * 70)
        lines.append("Summary:")
        lines.append(f"  Total SIP Requests:  {sum(method_counter.values())}")
        lines.append(f"  Total SIP Responses: {sum(response_counter.values())}")
        lines.append(f"  Unique Methods:      {len(method_counter)}")
        lines.append(f"  Unique Status Codes: {len(response_counter)}")
        lines.append("=" * 70)
        
        return '\n'.join(lines) + '\n'

