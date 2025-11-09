"""MGCP (Media Gateway Control Protocol) statistics module."""

from __future__ import annotations

from pathlib import Path
from collections import Counter, defaultdict

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class MgcpStatsModule(AnalysisModule):
    """Generate MGCP protocol statistics.
    
    Analyzes Media Gateway Control Protocol (MGCP) messages to extract:
    - Command types (CRCX, MDCX, DLCX, RQNT, NTFY, AUEP, AUCX, RSIP)
    - Response codes (200, 250, 400, 500, etc.)
    - Transaction patterns
    - Gateway and call agent communication
    
    MGCP is used for controlling media gateways from external call control
    elements (call agents). This module helps identify MGCP signaling issues.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "mgcp_stats"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "mgcp-stats.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"mgcp"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for MGCP analysis
        """
        return [
            "-Y", "mgcp",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.len",
            "-e", "ip.src",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "mgcp.req",
            "-e", "mgcp.rsp",
            "-e", "mgcp.req.verb",
            "-e", "mgcp.rsp.rspcode",
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process MGCP messages to generate statistics.
        
        Args:
            tshark_output: Raw tshark output
            output_format: Output format ("txt" or "md", default: "txt")
            
        Returns:
            Formatted output with MGCP statistics
        """
        if not tshark_output.strip():
            return "No MGCP messages found\n"
        
        lines = []
        lines.append("=" * 80)
        lines.append("MGCP Statistics")
        lines.append("=" * 80)
        lines.append("")
        
        # Parse MGCP messages
        requests = []
        responses = []
        connections = defaultdict(lambda: {'requests': 0, 'responses': 0})

        # Counters for commands and response codes
        command_counter: Counter[str] = Counter()
        response_code_counter: Counter[str] = Counter()

        # Detailed connection info grouped by command/response code
        command_connections: dict[str, list[str]] = defaultdict(list)
        response_code_connections: dict[str, list[str]] = defaultdict(list)

        for line in tshark_output.strip().split('\n'):
            parts = line.split('\t')
            if len(parts) < 12:
                continue

            frame_num = parts[0]
            frame_len = parts[1]
            src_ip = parts[2]
            tcp_src_port = parts[3]
            udp_src_port = parts[4]
            dst_ip = parts[5]
            tcp_dst_port = parts[6]
            udp_dst_port = parts[7]
            is_request = parts[8]
            is_response = parts[9]
            command_verb = parts[10] if len(parts) > 10 else ""
            response_code = parts[11] if len(parts) > 11 else ""

            # Determine actual port (TCP or UDP)
            src_port = tcp_src_port if tcp_src_port else udp_src_port
            dst_port = tcp_dst_port if tcp_dst_port else udp_dst_port

            connection = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"

            if is_request == "True":
                requests.append({
                    'frame': frame_num,
                    'size': int(frame_len) if frame_len else 0,
                    'src': f"{src_ip}:{src_port}",
                    'dst': f"{dst_ip}:{dst_port}",
                    'command': command_verb,
                })
                connections[connection]['requests'] += 1

                # Count command types
                if command_verb:
                    command_counter[command_verb] += 1
                    command_connections[command_verb].append(connection)

            if is_response == "True":
                responses.append({
                    'frame': frame_num,
                    'size': int(frame_len) if frame_len else 0,
                    'src': f"{src_ip}:{src_port}",
                    'dst': f"{dst_ip}:{dst_port}",
                    'code': response_code,
                })
                connections[connection]['responses'] += 1

                # Count response codes
                if response_code:
                    response_code_counter[response_code] += 1
                    response_code_connections[response_code].append(connection)
        
        total_messages = len(requests) + len(responses)
        
        # Summary
        lines.append("Summary:")
        lines.append("-" * 80)
        lines.append(f"  Total MGCP Messages:     {total_messages}")
        lines.append(f"  Requests:                {len(requests)}")
        lines.append(f"  Responses:               {len(responses)}")
        lines.append(f"  Unique Commands:         {len(command_counter)}")
        lines.append(f"  Unique Response Codes:   {len(response_code_counter)}")
        lines.append("")
        
        # MGCP Commands section
        if command_counter:
            lines.append("MGCP Commands (Requests):")
            lines.append("-" * 80)
            lines.append(f"{'Command':<20} {'Count':>10}")
            lines.append("-" * 80)

            for command, count in sorted(command_counter.items(), key=lambda x: -x[1]):
                lines.append(f"{command:<20} {count:>10}")

            lines.append("")
            lines.append("Command Details:")
            lines.append("-" * 80)
            for command in sorted(command_counter.keys()):
                lines.append(f"\n{command} ({command_counter[command]} occurrences):")
                # Show first 5 connections for each command
                unique_conns = list(dict.fromkeys(command_connections[command]))  # Remove duplicates while preserving order
                for conn in unique_conns[:5]:
                    lines.append(f"  {conn}")
                if len(unique_conns) > 5:
                    lines.append(f"  ... and {len(unique_conns) - 5} more")
            lines.append("")

        # MGCP Response Codes section
        if response_code_counter:
            lines.append("MGCP Response Codes:")
            lines.append("-" * 80)
            lines.append(f"{'Response Code':<20} {'Count':>10} {'Status':<20}")
            lines.append("-" * 80)

            # Sort by response code numerically
            sorted_codes = sorted(response_code_counter.keys(), key=lambda x: int(x) if x.isdigit() else 999)
            for code in sorted_codes:
                count = response_code_counter[code]

                # Determine status category
                if code.startswith('2'):
                    status = "✓ Success"
                elif code.startswith('4'):
                    status = "⚠ Client Error"
                elif code.startswith('5'):
                    status = "⚠ Server Error"
                else:
                    status = "Unknown"

                lines.append(f"{code:<20} {count:>10} {status:<20}")

            lines.append("")
            lines.append("Response Code Details:")
            lines.append("-" * 80)
            for code in sorted_codes:
                lines.append(f"\nResponse {code} ({response_code_counter[code]} occurrences):")
                # Show first 5 connections for each response code
                unique_conns = list(dict.fromkeys(response_code_connections[code]))  # Remove duplicates while preserving order
                for conn in unique_conns[:5]:
                    lines.append(f"  {conn}")
                if len(unique_conns) > 5:
                    lines.append(f"  ... and {len(unique_conns) - 5} more")
            lines.append("")

        # Message type distribution
        if requests:
            lines.append("Request Messages:")
            lines.append("-" * 80)
            lines.append(f"  Total Requests:          {len(requests)}")

            # Calculate average size
            avg_req_size = sum(r['size'] for r in requests) / len(requests)
            lines.append(f"  Average Request Size:    {avg_req_size:.0f} bytes")
            lines.append("")

        if responses:
            lines.append("Response Messages:")
            lines.append("-" * 80)
            lines.append(f"  Total Responses:         {len(responses)}")

            # Calculate average size
            avg_rsp_size = sum(r['size'] for r in responses) / len(responses)
            lines.append(f"  Average Response Size:   {avg_rsp_size:.0f} bytes")
            lines.append("")
        
        # Connection statistics
        if connections:
            lines.append("Top MGCP Connections (by message count):")
            lines.append("-" * 80)
            lines.append(f"{'Connection':<50} {'Requests':<12} {'Responses':<12}")
            lines.append("-" * 80)
            
            # Sort by total messages
            sorted_conns = sorted(
                connections.items(),
                key=lambda x: x[1]['requests'] + x[1]['responses'],
                reverse=True
            )[:10]
            
            for conn, stats in sorted_conns:
                lines.append(f"{conn:<50} {stats['requests']:<12} {stats['responses']:<12}")
            
            lines.append("")
        
        # Request/Response ratio analysis
        if requests and responses:
            ratio = len(requests) / len(responses)
            lines.append("Request/Response Analysis:")
            lines.append("-" * 80)
            lines.append(f"  Request/Response Ratio:  {ratio:.2f}")
            
            if ratio > 1.2:
                lines.append("  ⚠ Warning: More requests than responses detected")
                lines.append("    - Some requests may not have received responses")
                lines.append("    - Check for network issues or gateway problems")
            elif ratio < 0.8:
                lines.append("  ⚠ Warning: More responses than requests detected")
                lines.append("    - Possible duplicate responses or capture issues")
            else:
                lines.append("  ✓ Request/response ratio is balanced")
            
            lines.append("")
        
        # Size distribution
        all_sizes = [r['size'] for r in requests] + [r['size'] for r in responses]
        if all_sizes:
            lines.append("Message Size Distribution:")
            lines.append("-" * 80)
            
            size_ranges = {
                '< 100 bytes': sum(1 for s in all_sizes if s < 100),
                '100-200 bytes': sum(1 for s in all_sizes if 100 <= s < 200),
                '200-500 bytes': sum(1 for s in all_sizes if 200 <= s < 500),
                '> 500 bytes': sum(1 for s in all_sizes if s >= 500),
            }
            
            for range_name, count in size_ranges.items():
                percentage = (count / len(all_sizes)) * 100
                lines.append(f"  {range_name:<20} {count:>6} ({percentage:>5.1f}%)")
            
            lines.append("")
        
        lines.append("=" * 80)
        lines.append("")
        lines.append("MGCP Protocol Notes:")
        lines.append("  - MGCP is a master/slave protocol for controlling media gateways")
        lines.append("  - Call agents send commands (CRCX, MDCX, DLCX, etc.)")
        lines.append("  - Gateways respond with status codes")
        lines.append("")
        lines.append("  Common Commands:")
        lines.append("    * CRCX - Create Connection")
        lines.append("    * MDCX - Modify Connection")
        lines.append("    * DLCX - Delete Connection")
        lines.append("    * RQNT - Request Notification")
        lines.append("    * NTFY - Notify")
        lines.append("    * AUEP - Audit Endpoint")
        lines.append("    * AUCX - Audit Connection")
        lines.append("    * RSIP - Restart In Progress")
        lines.append("")
        lines.append("  Common Response Codes:")
        lines.append("    * 200 - Success (transaction executed normally)")
        lines.append("    * 250 - Delete Connection (connection was deleted)")
        lines.append("    * 400 - Transient Error (transaction could not be executed)")
        lines.append("    * 401 - Phone Off Hook")
        lines.append("    * 402 - Phone On Hook")
        lines.append("    * 500 - Endpoint Unknown")
        lines.append("    * 501 - Endpoint Not Ready")
        lines.append("    * 502 - Endpoint Insufficient Resources")
        lines.append("    * 510 - Protocol Error")
        lines.append("    * 511 - Unrecognized Command")
        lines.append("    * 512 - Unsupported Command")
        lines.append("    * 513 - Unsupported Parameter")
        lines.append("    * 515 - Invalid Parameter Value")
        lines.append("    * 516 - Unknown Connection ID")
        lines.append("    * 517 - Unsupported Mode")
        lines.append("    * 518 - Unsupported Package")
        lines.append("    * 520 - Endpoint Restarting")
        lines.append("    * 521 - Endpoint Redirected")
        lines.append("")
        lines.append("=" * 80)
        
        return '\n'.join(lines) + '\n'

