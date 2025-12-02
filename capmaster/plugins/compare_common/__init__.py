"""Shared packet comparison utilities for multiple plugins.

This package hosts the reusable pieces that were previously scoped under the
compare plugin so other commands (e.g. comparative-analysis, streamdiff) can
import a single shared implementation without duplicating code.
"""

from .packet_extractor import PacketExtractor, TcpPacket
from .packet_comparator import ComparisonResult, DiffType, PacketComparator, PacketDiff
from .output_formatter import build_report_text
from .flow_hash import (
    FlowSide,
    calculate_connection_flow_hash,
    calculate_flow_hash,
    format_flow_hash,
)
from .utils import format_tcp_flags_change, parse_tcp_flags, to_nanoseconds

__all__ = [
    "PacketExtractor",
    "TcpPacket",
    "PacketComparator",
    "ComparisonResult",
    "DiffType",
    "PacketDiff",
    "build_report_text",
    "FlowSide",
    "calculate_connection_flow_hash",
    "calculate_flow_hash",
    "format_flow_hash",
    "format_tcp_flags_change",
    "parse_tcp_flags",
    "to_nanoseconds",
]
