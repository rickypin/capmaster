"""XML statistics module."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
import re

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class XmlStatsModule(AnalysisModule):
    """Generate XML/SOAP statistics.
    
    Analyzes XML messages in HTTP traffic to extract:
    - XML message counts and sizes
    - HTTP methods and status codes for XML/SOAP APIs
    - SOAP actions and faults
    - Request/response patterns
    - Connection endpoints
    
    This helps identify XML/SOAP API errors and performance issues.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "xml_stats"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "xml-stats.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"xml"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for XML statistics extraction
        """
        return [
            "-Y",
            "xml",
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
            "http.request.method",
            "-e",
            "http.response.code",
            "-e",
            "http.content_type",
            "-e",
            "http.content_length",
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process XML messages to generate statistics.
        
        Groups XML messages by:
        1. HTTP methods (for requests)
        2. HTTP response codes (for responses)
        3. Content types (text/xml, application/soap+xml, etc.)
        4. Message sizes
        
        Args:
            tshark_output: Raw tshark output (tab-separated fields)
            output_format: Output format ("txt" or "md", default: "txt")
            
        Returns:
            Formatted output with XML statistics
        """
        if not tshark_output.strip():
            return "No XML messages found\n"
        
        # Counters and storage
        method_counter: Counter[str] = Counter()
        response_counter: Counter[str] = Counter()
        content_type_counter: Counter[str] = Counter()
        
        total_messages = 0
        total_size = 0
        request_count = 0
        response_count = 0
        
        # Size distribution
        size_buckets = {
            "< 1KB": 0,
            "1KB - 10KB": 0,
            "10KB - 100KB": 0,
            "100KB - 1MB": 0,
            "> 1MB": 0
        }
        
        # Connection tracking
        connections: dict[str, int] = defaultdict(int)
        
        # Detailed records for error analysis
        error_responses: list[tuple[str, str, str]] = []  # (code, connection, frame)
        
        # SOAP-specific tracking
        soap_messages = 0
        
        for line in tshark_output.strip().split('\n'):
            if not line.strip():
                continue
            
            parts = line.split('\t')
            if len(parts) < 10:
                continue
            
            frame_num = parts[0] if parts[0] else ""
            frame_len = parts[1] if parts[1] else "0"
            src_ip = parts[2] if parts[2] else ""
            src_port = parts[3] if parts[3] else ""
            dst_ip = parts[4] if parts[4] else ""
            dst_port = parts[5] if parts[5] else ""
            method = parts[6] if parts[6] else ""
            response_code = parts[7] if parts[7] else ""
            content_type = parts[8] if parts[8] else ""
            content_length = parts[9] if parts[9] else ""
            
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
                pass
            
            # Track connection
            if src_ip and dst_ip:
                connection = f"{src_ip}:{src_port} <-> {dst_ip}:{dst_port}"
                connections[connection] += 1
            
            # Process HTTP request (has method)
            if method:
                method_counter[method] += 1
                request_count += 1
            
            # Process HTTP response (has status code)
            if response_code:
                response_counter[response_code] += 1
                response_count += 1
                
                # Track error responses (4xx, 5xx)
                if response_code.startswith('4') or response_code.startswith('5'):
                    conn = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                    error_responses.append((response_code, conn, frame_num))
            
            # Track content type
            if content_type:
                # Extract main content type (before semicolon)
                main_type = content_type.split(';')[0].strip()
                content_type_counter[main_type] += 1
                
                # Check if SOAP
                if 'soap' in main_type.lower():
                    soap_messages += 1
        
        # Generate output
        lines = []
        lines.append("=" * 80)
        lines.append("XML/SOAP Statistics")
        lines.append("=" * 80)
        lines.append("")
        
        # Summary
        lines.append("Summary:")
        lines.append("-" * 80)
        lines.append(f"  Total XML Messages:      {total_messages}")
        lines.append(f"  XML Requests:            {request_count}")
        lines.append(f"  XML Responses:           {response_count}")
        lines.append(f"  SOAP Messages:           {soap_messages}")
        if total_messages > 0:
            avg_size = total_size / total_messages
            lines.append(f"  Total Data Size:         {total_size:,} bytes ({total_size / 1024:.2f} KB)")
            lines.append(f"  Average Message Size:    {avg_size:.2f} bytes")
        lines.append("")
        
        # HTTP Methods
        if method_counter:
            lines.append("HTTP Methods (XML Requests):")
            lines.append("-" * 80)
            lines.append(f"{'Method':<20} {'Count':>10} {'Percentage':>12}")
            lines.append("-" * 80)
            
            for method, count in sorted(method_counter.items(), key=lambda x: -x[1]):
                pct = (count / request_count * 100) if request_count > 0 else 0
                lines.append(f"{method:<20} {count:>10} {pct:>11.1f}%")
            lines.append("")
        
        # HTTP Response Codes
        if response_counter:
            lines.append("HTTP Response Codes (XML Responses):")
            lines.append("-" * 80)
            lines.append(f"{'Status Code':<20} {'Count':>10} {'Percentage':>12} {'Status':<15}")
            lines.append("-" * 80)
            
            # Sort by status code numerically
            sorted_codes = sorted(response_counter.keys(), key=lambda x: int(x) if x.isdigit() else 999)
            for code in sorted_codes:
                count = response_counter[code]
                pct = (count / response_count * 100) if response_count > 0 else 0
                
                # Determine status category
                if code.startswith('2'):
                    status = "✓ Success"
                elif code.startswith('3'):
                    status = "→ Redirect"
                elif code.startswith('4'):
                    status = "⚠ Client Error"
                elif code.startswith('5'):
                    status = "⚠ Server Error"
                else:
                    status = "Unknown"
                
                lines.append(f"{code:<20} {count:>10} {pct:>11.1f}% {status:<15}")
            lines.append("")
        
        # Error Analysis
        if error_responses:
            lines.append("Error Responses (sampled):")
            lines.append("-" * 80)
            lines.append("Status,Severity,Total,Sample Connections")

            grouped_errors: dict[str, list[tuple[str, str]]] = defaultdict(list)
            for code, conn, frame in error_responses:
                grouped_errors[code].append((frame, conn))

            sorted_errors = sorted(grouped_errors.items(), key=lambda item: -len(item[1]))
            for code, entries in sorted_errors:
                severity = "High" if code.startswith('5') else "Medium"
                samples = self.sample_items(entries, limit=2)
                sample_text = "; ".join(
                    f"{frame}@{conn[:55] + '...' if len(conn) > 55 else conn}"
                    for frame, conn in samples
                )
                lines.append(f"{code},{severity},{len(entries)},{sample_text}")

            lines.append("")
        
        # Message Size Distribution
        lines.append("Message Size Distribution:")
        lines.append("-" * 80)
        lines.append(f"{'Size Range':<20} {'Count':>10} {'Percentage':>12}")
        lines.append("-" * 80)
        
        for size_range in ["< 1KB", "1KB - 10KB", "10KB - 100KB", "100KB - 1MB", "> 1MB"]:
            count = size_buckets[size_range]
            pct = (count / total_messages * 100) if total_messages > 0 else 0
            lines.append(f"{size_range:<20} {count:>10} {pct:>11.1f}%")
        lines.append("")
        
        # Content Types
        if content_type_counter:
            lines.append("Content Types:")
            lines.append("-" * 80)
            lines.append(f"{'Content Type':<50} {'Count':>10} {'Type':<15}")
            lines.append("-" * 80)
            
            for ctype, count in sorted(content_type_counter.items(), key=lambda x: -x[1]):
                ctype_display = ctype[:49] if len(ctype) <= 49 else ctype[:46] + "..."
                
                # Identify type
                if 'soap' in ctype.lower():
                    type_label = "SOAP"
                elif 'xml' in ctype.lower():
                    type_label = "XML"
                else:
                    type_label = "Other"
                
                lines.append(f"{ctype_display:<50} {count:>10} {type_label:<15}")
            lines.append("")
        
        # Top Connections
        if connections:
            lines.append("Top Connections (by message count):")
            lines.append("-" * 80)
            lines.append(f"{'Connection':<60} {'Messages':>10}")
            lines.append("-" * 80)
            
            sorted_conns = sorted(connections.items(), key=lambda x: -x[1])
            for conn, count in sorted_conns[:10]:
                conn_display = conn[:59] if len(conn) <= 59 else conn[:56] + "..."
                lines.append(f"{conn_display:<60} {count:>10}")
            
            if len(sorted_conns) > 10:
                lines.append(f"... and {len(sorted_conns) - 10} more connections")
            lines.append("")
        
        lines.append("=" * 80)
        
        return '\n'.join(lines) + '\n'

