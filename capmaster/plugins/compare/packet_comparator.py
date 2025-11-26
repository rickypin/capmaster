"""Packet-level comparator for TCP connections."""

from __future__ import annotations
import logging
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum

from capmaster.plugins.compare.packet_extractor import TcpPacket

logger = logging.getLogger(__name__)


class DiffType(Enum):
    """Type of difference found in packet comparison."""
    
    IP_ID = "ipid"
    TCP_FLAGS = "tcp_flags"
    SEQ_NUM = "seq_num"
    ACK_NUM = "ack_num"
    PACKET_COUNT = "packet_count"


@dataclass
class PacketDiff:
    """
    Difference found between two packets.

    OPTIMIZATION: Uses __slots__ to reduce memory overhead per instance.
    With large numbers of differences, this can save 20-30% memory.
    """

    __slots__ = ('diff_type', 'packet_index', 'frame_a', 'frame_b', 'value_a', 'value_b')

    diff_type: DiffType
    """Type of difference"""

    packet_index: int
    """Index of the packet in the sequence"""

    frame_a: int
    """Frame number in PCAP A"""

    frame_b: int
    """Frame number in PCAP B"""

    value_a: str | int
    """Value from PCAP A"""

    value_b: str | int
    """Value from PCAP B"""

    def __str__(self) -> str:
        """String representation."""
        return (
            f"[Packet {self.packet_index}] {self.diff_type.value}: "
            f"A(frame {self.frame_a})={self.value_a} != "
            f"B(frame {self.frame_b})={self.value_b}"
        )


@dataclass
class ComparisonResult:
    """
    Result of comparing two packet sequences.
    """
    
    connection_id: str
    """Connection identifier (5-tuple)"""
    
    packets_a: int
    """Number of packets in PCAP A"""
    
    packets_b: int
    """Number of packets in PCAP B"""
    
    differences: list[PacketDiff]
    """List of differences found"""
    
    @property
    def is_identical(self) -> bool:
        """Check if the two sequences are identical."""
        return len(self.differences) == 0
    
    @property
    def diff_count(self) -> int:
        """Total number of differences."""
        return len(self.differences)
    
    def get_diff_summary(self) -> dict[str, int]:
        """
        Get summary of differences by type.
        
        Returns:
            Dictionary mapping diff type to count
        """
        summary: dict[str, int] = {}
        for diff in self.differences:
            diff_type = diff.diff_type.value
            summary[diff_type] = summary.get(diff_type, 0) + 1
        return summary
    
    def __str__(self) -> str:
        """String representation."""
        if self.is_identical:
            return f"{self.connection_id}: IDENTICAL ({self.packets_a} packets)"
        
        summary = self.get_diff_summary()
        summary_str = ", ".join(f"{k}={v}" for k, v in summary.items())
        return (
            f"{self.connection_id}: {self.diff_count} differences "
            f"({summary_str}) in {self.packets_a}/{self.packets_b} packets"
        )


class PacketComparator:
    """
    Compare TCP packet sequences at the packet level.

    Uses IP ID as the unique pairing criterion between packets from both sides.
    For matched packets (same IP ID), compares:
    - TCP flags
    - Sequence number
    - Acknowledgment number
    """

    def compare(
        self,
        packets_a: list[TcpPacket],
        packets_b: list[TcpPacket],
        connection_id: str,
        matched_only: bool = False,
    ) -> ComparisonResult:
        """
        Compare two packet sequences using IP ID as pairing key.

        Args:
            packets_a: Packets from PCAP A
            packets_b: Packets from PCAP B
            connection_id: Connection identifier for reporting
            matched_only: If True, only compare packets that exist in both A and B
                         with matching IPID (ignore packets only in A or only in B)

        Returns:
            ComparisonResult with detailed differences
        """
        differences: list[PacketDiff] = []

        # OPTIMIZATION: Build IP ID index for both sides using defaultdict
        # This eliminates the need for "if key not in dict" checks, improving performance
        # Note: Multiple packets may have the same IP ID, so we use lists
        ipid_map_a: dict[int, list[TcpPacket]] = defaultdict(list)
        ipid_map_b: dict[int, list[TcpPacket]] = defaultdict(list)

        for pkt in packets_a:
            ipid_map_a[pkt.ip_id].append(pkt)

        for pkt in packets_b:
            ipid_map_b[pkt.ip_id].append(pkt)

        # Find all unique IP IDs from both sides
        all_ipids = set(ipid_map_a.keys()) | set(ipid_map_b.keys())

        # Track packets only in A or only in B
        only_in_a = set(ipid_map_a.keys()) - set(ipid_map_b.keys())
        only_in_b = set(ipid_map_b.keys()) - set(ipid_map_a.keys())

        # Log packet count differences (only if not in matched_only mode)
        if not matched_only and len(packets_a) != len(packets_b):
            logger.warning(
                f"{connection_id}: Packet count mismatch: "
                f"A={len(packets_a)}, B={len(packets_b)}"
            )
            differences.append(
                PacketDiff(
                    diff_type=DiffType.PACKET_COUNT,
                    packet_index=-1,
                    frame_a=-1,
                    frame_b=-1,
                    value_a=len(packets_a),
                    value_b=len(packets_b),
                )
            )

        # Compare packets with matching IP IDs
        matched_ipids = set(ipid_map_a.keys()) & set(ipid_map_b.keys())
        for ipid in sorted(matched_ipids):
            pkts_a = ipid_map_a[ipid]
            pkts_b = ipid_map_b[ipid]

            # If counts differ for same IP ID, log it
            if len(pkts_a) != len(pkts_b):
                logger.debug(
                    f"{connection_id}: IP ID {ipid:#06x} count mismatch: "
                    f"A={len(pkts_a)}, B={len(pkts_b)}"
                )

            # Compare packets pairwise (up to min count)
            for i in range(min(len(pkts_a), len(pkts_b))):
                pkt_a = pkts_a[i]
                pkt_b = pkts_b[i]

                # Compare TCP flags
                if pkt_a.tcp_flags != pkt_b.tcp_flags:
                    differences.append(
                        PacketDiff(
                            diff_type=DiffType.TCP_FLAGS,
                            packet_index=-1,  # No longer sequential index
                            frame_a=pkt_a.frame_number,
                            frame_b=pkt_b.frame_number,
                            value_a=pkt_a.tcp_flags,
                            value_b=pkt_b.tcp_flags,
                        )
                    )

                # Compare sequence number
                if pkt_a.seq != pkt_b.seq:
                    differences.append(
                        PacketDiff(
                            diff_type=DiffType.SEQ_NUM,
                            packet_index=-1,
                            frame_a=pkt_a.frame_number,
                            frame_b=pkt_b.frame_number,
                            value_a=pkt_a.seq,
                            value_b=pkt_b.seq,
                        )
                    )

                # Compare acknowledgment number
                if pkt_a.ack != pkt_b.ack:
                    differences.append(
                        PacketDiff(
                            diff_type=DiffType.ACK_NUM,
                            packet_index=-1,
                            frame_a=pkt_a.frame_number,
                            frame_b=pkt_b.frame_number,
                            value_a=pkt_a.ack,
                            value_b=pkt_b.ack,
                        )
                    )

        # Record IP IDs only in A (skip if matched_only mode)
        if not matched_only:
            for ipid in only_in_a:
                for pkt in ipid_map_a[ipid]:
                    differences.append(
                        PacketDiff(
                            diff_type=DiffType.IP_ID,
                            packet_index=-1,
                            frame_a=pkt.frame_number,
                            frame_b=-1,
                            value_a=f"{ipid:#06x}",
                            value_b="N/A",
                        )
                    )

            # Record IP IDs only in B
            for ipid in only_in_b:
                for pkt in ipid_map_b[ipid]:
                    differences.append(
                        PacketDiff(
                            diff_type=DiffType.IP_ID,
                            packet_index=-1,
                            frame_a=-1,
                            frame_b=pkt.frame_number,
                            value_a="N/A",
                            value_b=f"{ipid:#06x}",
                        )
                    )

        return ComparisonResult(
            connection_id=connection_id,
            packets_a=len(packets_a),
            packets_b=len(packets_b),
            differences=differences,
        )
    
    def format_comparison_table(
        self,
        packets_a: list[TcpPacket],
        packets_b: list[TcpPacket],
        result: ComparisonResult,
    ) -> str:
        """
        Format comparison result as a table using IP ID as pairing key.

        Args:
            packets_a: Packets from PCAP A
            packets_b: Packets from PCAP B
            result: Comparison result

        Returns:
            Formatted table string
        """
        lines = []
        lines.append(f"\n{'='*100}")
        lines.append(f"Connection: {result.connection_id}")
        lines.append(f"{'='*100}")

        # Build IP ID index for both sides
        ipid_map_a: dict[int, list[TcpPacket]] = {}
        ipid_map_b: dict[int, list[TcpPacket]] = {}

        for pkt in packets_a:
            if pkt.ip_id not in ipid_map_a:
                ipid_map_a[pkt.ip_id] = []
            ipid_map_a[pkt.ip_id].append(pkt)

        for pkt in packets_b:
            if pkt.ip_id not in ipid_map_b:
                ipid_map_b[pkt.ip_id] = []
            ipid_map_b[pkt.ip_id].append(pkt)

        # Get all unique IP IDs and sort them
        all_ipids = sorted(set(ipid_map_a.keys()) | set(ipid_map_b.keys()))

        # Header
        lines.append(
            f"{'IPID':<12} {'Frame A':<10} {'Frame B':<10} "
            f"{'Flags A':<10} {'Flags B':<10} "
            f"{'Seq A':<12} {'Seq B':<12} "
            f"{'Ack A':<12} {'Ack B':<12} {'Status':<15}"
        )
        lines.append("-" * 110)

        # Process each IP ID
        for ipid in all_ipids:
            pkts_a = ipid_map_a.get(ipid, [])
            pkts_b = ipid_map_b.get(ipid, [])

            ipid_str = f"{ipid:#06x}"

            # Case 1: IP ID only in A
            if not pkts_b:
                for pkt_a in pkts_a:
                    lines.append(
                        f"{ipid_str:<12} {pkt_a.frame_number:<10} {'N/A':<10} "
                        f"{pkt_a.tcp_flags:<10} {'N/A':<10} "
                        f"{pkt_a.seq:<12} {'N/A':<12} "
                        f"{pkt_a.ack:<12} {'N/A':<12} {'ONLY_IN_A':<15}"
                    )
            # Case 2: IP ID only in B
            elif not pkts_a:
                for pkt_b in pkts_b:
                    lines.append(
                        f"{ipid_str:<12} {'N/A':<10} {pkt_b.frame_number:<10} "
                        f"{'N/A':<10} {pkt_b.tcp_flags:<10} "
                        f"{'N/A':<12} {pkt_b.seq:<12} "
                        f"{'N/A':<12} {pkt_b.ack:<12} {'ONLY_IN_B':<15}"
                    )
            # Case 3: IP ID in both sides - pair them up
            else:
                max_count = max(len(pkts_a), len(pkts_b))
                for i in range(max_count):
                    pkt_a = pkts_a[i] if i < len(pkts_a) else None
                    pkt_b = pkts_b[i] if i < len(pkts_b) else None

                    if pkt_a and pkt_b:
                        # Both packets exist - compare them
                        diffs = []
                        if pkt_a.tcp_flags != pkt_b.tcp_flags:
                            diffs.append("FLAGS")
                        if pkt_a.seq != pkt_b.seq:
                            diffs.append("SEQ")
                        if pkt_a.ack != pkt_b.ack:
                            diffs.append("ACK")

                        status = "DIFF" if diffs else "OK"
                        status_str = f"{status}({','.join(diffs)})" if diffs else status

                        lines.append(
                            f"{ipid_str:<12} {pkt_a.frame_number:<10} {pkt_b.frame_number:<10} "
                            f"{pkt_a.tcp_flags:<10} {pkt_b.tcp_flags:<10} "
                            f"{pkt_a.seq:<12} {pkt_b.seq:<12} "
                            f"{pkt_a.ack:<12} {pkt_b.ack:<12} {status_str:<15}"
                        )
                    elif pkt_a:
                        # Only A has this occurrence
                        lines.append(
                            f"{ipid_str:<12} {pkt_a.frame_number:<10} {'N/A':<10} "
                            f"{pkt_a.tcp_flags:<10} {'N/A':<10} "
                            f"{pkt_a.seq:<12} {'N/A':<12} "
                            f"{pkt_a.ack:<12} {'N/A':<12} {'EXTRA_IN_A':<15}"
                        )
                    else:
                        # Only B has this occurrence
                        lines.append(
                            f"{ipid_str:<12} {'N/A':<10} {pkt_b.frame_number:<10} "
                            f"{'N/A':<10} {pkt_b.tcp_flags:<10} "
                            f"{'N/A':<12} {pkt_b.seq:<12} "
                            f"{'N/A':<12} {pkt_b.ack:<12} {'EXTRA_IN_B':<15}"
                        )

        # Summary
        lines.append(f"\n{'='*100}")
        lines.append(f"Summary: {result}")
        lines.append(f"{'='*100}\n")

        return "\n".join(lines)

    def format_flow_comparison(
        self,
        packets_a: list[TcpPacket],
        packets_b: list[TcpPacket],
        result: ComparisonResult,
    ) -> str:
        """
        Format comparison result as a visual flow graph.

        Args:
            packets_a: Packets from PCAP A
            packets_b: Packets from PCAP B
            result: Comparison result

        Returns:
            Formatted table string
        """
        lines = []
        lines.append(f"\n{'='*150}")
        lines.append(f"Connection: {result.connection_id}")
        lines.append(f"{'='*150}")

        # Build IP ID index for both sides
        ipid_map_a: dict[int, list[TcpPacket]] = defaultdict(list)
        ipid_map_b: dict[int, list[TcpPacket]] = defaultdict(list)

        for pkt in packets_a:
            ipid_map_a[pkt.ip_id].append(pkt)

        for pkt in packets_b:
            ipid_map_b[pkt.ip_id].append(pkt)

        # Get all unique IP IDs
        all_ipids = set(ipid_map_a.keys()) | set(ipid_map_b.keys())

        # Create a list of rows to be sorted by timestamp
        rows = []

        for ipid in all_ipids:
            pkts_a = ipid_map_a.get(ipid, [])
            pkts_b = ipid_map_b.get(ipid, [])

            max_count = max(len(pkts_a), len(pkts_b))
            for i in range(max_count):
                pkt_a = pkts_a[i] if i < len(pkts_a) else None
                pkt_b = pkts_b[i] if i < len(pkts_b) else None

                # Determine timestamp for sorting
                if pkt_a and pkt_b:
                    ts = min(pkt_a.timestamp, pkt_b.timestamp)
                elif pkt_a:
                    ts = pkt_a.timestamp
                elif pkt_b:
                    ts = pkt_b.timestamp
                else:
                    continue

                # Determine status
                status_str = ""
                if pkt_a and pkt_b:
                    diffs = []
                    if pkt_a.tcp_flags != pkt_b.tcp_flags:
                        diffs.append("FLAGS")
                    if pkt_a.seq != pkt_b.seq:
                        diffs.append("SEQ")
                    if pkt_a.ack != pkt_b.ack:
                        diffs.append("ACK")
                    
                    if diffs:
                        status_str = f"DIFF({','.join(diffs)})"
                    else:
                        status_str = "MATCH"
                elif pkt_a:
                    status_str = "ONLY_IN_A"
                else:
                    status_str = "ONLY_IN_B"

                rows.append({
                    "ts": ts,
                    "ipid": ipid,
                    "pkt_a": pkt_a,
                    "pkt_b": pkt_b,
                    "status": status_str
                })

        # Sort rows by timestamp
        rows.sort(key=lambda x: x["ts"])

        # Calculate relative time
        start_time = rows[0]["ts"] if rows else 0

        # Header
        # Time | Capture A (Flow) | Capture B (Flow) | Diff
        # We need to determine the "Client" IP to orient arrows consistently.
        # Heuristic: Use the src IP of the first packet as "Client" (Left side).
        client_ip = ""
        if rows:
            first_row = rows[0]
            pkt = first_row["pkt_a"] or first_row["pkt_b"]
            if pkt:
                client_ip = pkt.src_ip

        header = (
            f"{'Time':<10} {'IPID':<8} | "
            f"{'Capture A Flow':<80} | "
            f"{'Capture B Flow':<80} | "
            f"{'Status':<15}"
        )
        lines.append(header)
        lines.append("-" * 210)

        for row in rows:
            ts = row["ts"]
            rel_time = float(ts - start_time)
            ipid_str = f"{row['ipid']:#06x}"
            pkt_a = row["pkt_a"]
            pkt_b = row["pkt_b"]
            status = row["status"]
            time_str = f"{rel_time:.6f}"

            # Helper to format flow string
            def format_flow(pkt: TcpPacket | None) -> str:
                if not pkt:
                    return ""
                
                # Determine direction arrow
                # If src_ip matches our "client_ip", it's -->
                # Otherwise it's <--
                arrow = "-->" if pkt.src_ip == client_ip else "<--"
                
                # Format: Arrow Info (Seq/Ack)
                # Truncate info if too long
                info = pkt.info[:60]
                return f"{arrow} {info:<60} {pkt.seq}/{pkt.ack}"

            flow_a = format_flow(pkt_a)
            flow_b = format_flow(pkt_b)

            line = (
                f"{time_str:<10} {ipid_str:<8} | "
                f"{flow_a:<80} | "
                f"{flow_b:<80} | "
                f"{status:<15}"
            )
            lines.append(line)

        # Summary footer
        lines.append(f"\n{'='*210}")
        lines.append(f"Summary: {result}")
        lines.append(f"{'='*210}\n")

        return "\n".join(lines)
