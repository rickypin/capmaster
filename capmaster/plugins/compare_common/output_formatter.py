"""Output formatting helpers for compare plugin.

This module builds the human-readable comparison report text while keeping
behavior identical to the original inline implementation in plugin.py.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .flow_hash import (
    calculate_connection_flow_hash,
    format_flow_hash,
)
from .packet_comparator import DiffType
from .utils import (
    to_nanoseconds,
    parse_tcp_flags,
    format_tcp_flags_change,
)


def build_report_text(
    results: list,
    baseline_file: Path,
    compare_file: Path,
    *,
    matched_only: bool,
    show_flow_hash: bool,
    flow_hash_cache: dict[tuple[str, str, int, int], tuple[int, Any]] | None = None,
) -> str:
    """Build the full text report for packet-level TCP connection comparison.

    Args:
        results: List of (match, packets_a, packets_b, comparison_result) tuples
        baseline_file: Baseline PCAP file (file1)
        compare_file: Compare PCAP file (file2)
        matched_only: Whether to only show matched packets
        show_flow_hash: Whether to calculate/display flow hash
        flow_hash_cache: Cache to avoid repeated flow hash calculation

    Returns:
        The report text exactly as previously produced by plugin.py
    """
    if flow_hash_cache is None:
        flow_hash_cache = {}

    def get_cached_flow_hash(client_ip: str, server_ip: str, client_port: int, server_port: int) -> tuple[int, Any]:
        """Get flow hash from cache or calculate and cache it."""
        cache_key = (client_ip, server_ip, client_port, server_port)
        if cache_key not in flow_hash_cache:
            flow_hash_cache[cache_key] = calculate_connection_flow_hash(
                client_ip, server_ip, client_port, server_port
            )
        return flow_hash_cache[cache_key]

    lines: list[str] = []
    # Markdown title
    lines.append("## TCP Connection Packet-Level Comparison Report")
    lines.append("")

    # Content in code block
    lines.append("```text")
    lines.append(f"Baseline File: {baseline_file.name}")
    lines.append(f"Compare File:  {compare_file.name}")
    lines.append(f"Comparison Direction: {compare_file.name} relative to {baseline_file.name}")
    lines.append(f"Matched Connections: {len(results)}")
    if matched_only:
        lines.append("Mode: Matched-only (only comparing packets with matching IPID in both files)")
    lines.append("")

    # Section 1: Matched TCP Connections from Baseline File
    lines.append(f"Matched TCP Connections in Baseline File ({baseline_file.name})")
    lines.append("-" * 140)

    if show_flow_hash:
        lines.append(f"{'No.':<6} {'Stream ID':<12} {'Client IP:Port':<25} {'Server IP:Port':<25} {'Packets':<10} {'First Time':<22} {'Last Time':<22} {'Flow Hash':<30}")
    else:
        lines.append(f"{'No.':<6} {'Stream ID':<12} {'Client IP:Port':<25} {'Server IP:Port':<25} {'Packets':<10} {'First Time':<22} {'Last Time':<22}")
    lines.append("-" * 140)

    # Group results by baseline stream_id to avoid duplicates
    baseline_streams_seen: set[int] = set()
    unique_baseline_count = 0

    for idx, (match, packets_a, packets_b, result) in enumerate(results, 1):
        conn = match.conn1  # Baseline connection

        # Skip if we've already output this baseline stream
        if conn.stream_id in baseline_streams_seen:
            continue

        baseline_streams_seen.add(conn.stream_id)
        unique_baseline_count += 1

        client_addr = f"{conn.client_ip}:{conn.client_port}"
        server_addr = f"{conn.server_ip}:{conn.server_port}"

        # Extract timestamps from baseline packets
        first_time_str = "N/A"
        last_time_str = "N/A"
        if packets_a:
            first_time_ns = to_nanoseconds(packets_a[0].timestamp)
            last_time_ns = to_nanoseconds(packets_a[-1].timestamp)
            first_time_str = str(first_time_ns)
            last_time_str = str(last_time_ns)

        if show_flow_hash:
            # Get flow hash from cache (OPTIMIZATION: avoid redundant calculation)
            hash_hex, flow_side = get_cached_flow_hash(
                conn.client_ip,
                conn.server_ip,
                conn.client_port,
                conn.server_port,
            )
            flow_hash_str = format_flow_hash(hash_hex, flow_side)
            lines.append(
                f"{unique_baseline_count:<6} {conn.stream_id:<12} {client_addr:<25} {server_addr:<25} {len(packets_a):<10} {first_time_str:<22} {last_time_str:<22} {flow_hash_str:<30}"
            )
        else:
            lines.append(
                f"{unique_baseline_count:<6} {conn.stream_id:<12} {client_addr:<25} {server_addr:<25} {len(packets_a):<10} {first_time_str:<22} {last_time_str:<22}"
            )

    lines.append("-" * 140)
    lines.append(f"Total: {unique_baseline_count} connections")
    lines.append("")

    # Section 2: Matched TCP Connections from Compare File
    lines.append(f"Matched TCP Connections in Compare File ({compare_file.name})")
    lines.append("-" * 140)

    if show_flow_hash:
        lines.append(f"{'No.':<6} {'Stream ID':<12} {'Client IP:Port':<25} {'Server IP:Port':<25} {'Packets':<10} {'First Time':<22} {'Last Time':<22} {'Flow Hash':<30}")
    else:
        lines.append(f"{'No.':<6} {'Stream ID':<12} {'Client IP:Port':<25} {'Server IP:Port':<25} {'Packets':<10} {'First Time':<22} {'Last Time':<22}")
    lines.append("-" * 140)

    # Group results by compare stream_id to avoid duplicates
    compare_streams_seen: set[int] = set()
    unique_compare_count = 0

    for idx, (match, packets_a, packets_b, result) in enumerate(results, 1):
        conn = match.conn2  # Compare connection

        # Skip if we've already output this compare stream
        if conn.stream_id in compare_streams_seen:
            continue

        compare_streams_seen.add(conn.stream_id)
        unique_compare_count += 1

        client_addr = f"{conn.client_ip}:{conn.client_port}"
        server_addr = f"{conn.server_ip}:{conn.server_port}"

        # Extract timestamps from compare packets
        first_time_str = "N/A"
        last_time_str = "N/A"
        if packets_b:
            first_time_ns = to_nanoseconds(packets_b[0].timestamp)
            last_time_ns = to_nanoseconds(packets_b[-1].timestamp)
            first_time_str = str(first_time_ns)
            last_time_str = str(last_time_ns)

        if show_flow_hash:
            # Get flow hash from cache (OPTIMIZATION: avoid redundant calculation)
            hash_hex, flow_side = get_cached_flow_hash(
                conn.client_ip,
                conn.server_ip,
                conn.client_port,
                conn.server_port,
            )
            flow_hash_str = format_flow_hash(hash_hex, flow_side)
            lines.append(
                f"{unique_compare_count:<6} {conn.stream_id:<12} {client_addr:<25} {server_addr:<25} {len(packets_b):<10} {first_time_str:<22} {last_time_str:<22} {flow_hash_str:<30}"
            )
        else:
            lines.append(
                f"{unique_compare_count:<6} {conn.stream_id:<12} {client_addr:<25} {server_addr:<25} {len(packets_b):<10} {first_time_str:<22} {last_time_str:<22}"
            )

    lines.append("-" * 140)
    lines.append(f"Total: {unique_compare_count} connections")
    lines.append("")

    # Overall summary statistics
    identical_count = sum(1 for _, _, _, r in results if r.is_identical)
    diff_count = len(results) - identical_count

    lines.append("Overall Summary")
    lines.append("-" * 100)
    lines.append(f"Total matched pairs: {len(results)}")
    lines.append(f"Unique baseline streams: {unique_baseline_count}")
    lines.append(f"Unique compare streams: {unique_compare_count}")
    lines.append(f"Identical connections: {identical_count}")
    lines.append(f"Connections with differences: {diff_count}")
    lines.append("")

    # Collect statistics per stream pair
    # Structure: {(baseline_stream_id, compare_stream_id): {diff_type: count, tcp_flags: {flags_pair: count}}}
    stream_pair_stats: dict[tuple[int, int], dict[str, Any]] = {}

    for match, packets_a, packets_b, result in results:
        # Create stream pair identifier
        stream_pair = (match.conn1.stream_id, match.conn2.stream_id)

        if stream_pair not in stream_pair_stats:
            stream_pair_stats[stream_pair] = {
                'diff_types': Counter(),
                'tcp_flags': Counter(),
                'tcp_flags_frames': {},
                'connection_id': result.connection_id,
                'is_identical': result.is_identical,
            }

        if not result.is_identical:
            # Count differences by type for this stream pair
            for diff in result.differences:
                stream_pair_stats[stream_pair]['diff_types'][diff.diff_type] += 1

                # Collect TCP FLAGS details for this stream pair
                if diff.diff_type == DiffType.TCP_FLAGS:
                    flags_pair = f"{diff.value_a} → {diff.value_b}"
                    stream_pair_stats[stream_pair]['tcp_flags'][flags_pair] += 1

                    # Track frame id pairs for this flags difference
                    if flags_pair not in stream_pair_stats[stream_pair]['tcp_flags_frames']:
                        stream_pair_stats[stream_pair]['tcp_flags_frames'][flags_pair] = []
                    stream_pair_stats[stream_pair]['tcp_flags_frames'][flags_pair].append((diff.frame_a, diff.frame_b))

    # Output statistics per stream pair
    if stream_pair_stats:
        lines.append("Per-Stream-Pair Statistics")
        lines.append("-" * 140)

        # Sort stream pairs by baseline stream id, then compare stream id
        sorted_pairs = sorted(stream_pair_stats.keys())

        for stream_pair in sorted_pairs:
            stats = stream_pair_stats[stream_pair]
            baseline_stream, compare_stream = stream_pair

            lines.append("")
            lines.append(f"Stream Pair: Baseline Stream {baseline_stream} ↔ Compare Stream {compare_stream}")
            lines.append(f"Connection: {stats['connection_id']}")
            lines.append("─" * 140)

            # Show if identical
            if stats['is_identical']:
                lines.append(f"\n  Status: ✓ Identical (no differences found)")
                continue

            # Difference Type Statistics for this stream pair
            if stats['diff_types']:
                lines.append(f"\n  Difference Type Statistics:")
                lines.append(f"  {'Difference Type':<20} {'Count':<15}")
                lines.append(f"  {'-'*35}")

                for diff_type, count in stats['diff_types'].most_common():
                    diff_type_name = diff_type.value.upper() + '_DIFF'
                    lines.append(f"  {diff_type_name:<20} {count:<15}")

                lines.append(f"  {'-'*35}")

            # TCP FLAGS Detailed Breakdown for this stream pair
            if stats['tcp_flags']:
                lines.append(f"\n  TCP FLAGS Detailed Breakdown:")
                lines.append(f"  {'Baseline FLAGS':<35} {'Compare FLAGS':<35} {'Count':<15}")
                lines.append(f"  {'-'*85}")

                for flags_pair, count in stats['tcp_flags'].most_common():
                    flags_baseline, flags_compare = flags_pair.split(" → ")
                    # Parse flags to human-readable format
                    flags_baseline_readable = parse_tcp_flags(flags_baseline)
                    flags_compare_readable = parse_tcp_flags(flags_compare)
                    lines.append(f"  {flags_baseline_readable:<35} {flags_compare_readable:<35} {count:<15}")

                    # Show frame id pairs for this flags difference
                    frame_pairs = stats['tcp_flags_frames'].get(flags_pair, [])
                    if frame_pairs:
                        # Show first few pairs as examples
                        max_examples = 10
                        lines.append(f"    Example Frame ID pairs (Baseline → Compare):")

                        # Format pairs in a compact way, multiple per line
                        pairs_per_line = 5
                        for i in range(0, min(max_examples, len(frame_pairs)), pairs_per_line):
                            batch = frame_pairs[i:i+pairs_per_line]
                            pair_strs = [f"({frame_baseline}→{frame_compare})" for frame_baseline, frame_compare in batch]
                            lines.append(f"      {', '.join(pair_strs)}")

                        # If there are more pairs, show summary
                        if len(frame_pairs) > max_examples:
                            lines.append(f"      ... and {len(frame_pairs) - max_examples} more pairs")

                lines.append(f"  {'-'*85}")
                lines.append(f"  {'TOTAL':<71} {sum(stats['tcp_flags'].values()):<15}")

    # Close code block
    lines.append("```")

    return "\n".join(lines)
