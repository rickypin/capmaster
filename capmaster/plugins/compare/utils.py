"""Internal utilities for the compare plugin.

These helpers are kept within the compare namespace for cohesion. If they
become cross-plugin utilities in the future, we can promote them to a
common/core module.
"""

from __future__ import annotations

from decimal import Decimal


def to_nanoseconds(timestamp_seconds: float | Decimal) -> int:
    """Convert timestamp from seconds to nanoseconds with full precision.

    Args:
        timestamp_seconds: Unix timestamp in seconds (float or Decimal for full precision)

    Returns:
        Timestamp in nanoseconds (int), preserving full nanosecond precision

    Example:
        Input:  Decimal('1757441703.689601150') seconds
        Output: 1757441703689601150 nanoseconds (full precision preserved)

        Input:  1757441703.689601024 (float)
        Output: 1757441703689601024 nanoseconds (converted via Decimal)
    """
    # Convert float to Decimal to preserve precision
    if isinstance(timestamp_seconds, float):
        timestamp_seconds = Decimal(str(timestamp_seconds))

    # Convert to nanoseconds using Decimal to preserve full precision
    # Decimal arithmetic ensures no precision loss during multiplication
    timestamp_nanoseconds = int(timestamp_seconds * Decimal("1000000000"))
    return timestamp_nanoseconds


def parse_tcp_flags(flags_hex: str) -> str:
    """Parse TCP flags from hex string to human-readable format.

    Args:
        flags_hex: Hex string like "0x0002" or "0x0010"

    Returns:
        Human-readable flags like "[SYN]" or "[ACK]"
    """
    try:
        flags_int = int(flags_hex, 16)
    except (ValueError, TypeError):
        return flags_hex

    flag_names: list[str] = []
    if flags_int & 0x01:  # FIN
        flag_names.append("FIN")
    if flags_int & 0x02:  # SYN
        flag_names.append("SYN")
    if flags_int & 0x04:  # RST
        flag_names.append("RST")
    if flags_int & 0x08:  # PSH
        flag_names.append("PSH")
    if flags_int & 0x10:  # ACK
        flag_names.append("ACK")
    if flags_int & 0x20:  # URG
        flag_names.append("URG")
    if flags_int & 0x40:  # ECE
        flag_names.append("ECE")
    if flags_int & 0x80:  # CWR
        flag_names.append("CWR")

    if not flag_names:
        return f"{flags_hex} [NONE]"

    return f"{flags_hex} [{', '.join(flag_names)}]"


def format_tcp_flags_change(flags_baseline: str, flags_compare: str) -> str:
    """Format TCP flags change in human-readable format.

    Args:
        flags_baseline: Baseline (local side) flags (hex string like "0x0002")
        flags_compare: Compare (remote side) flags (hex string like "0x0010")

    Returns:
        Human-readable change like "SYN (Local Side) -> ACK" or "SYN -> ACK (Local Side)".
        The Local Side marker is placed on the baseline flags side.
    """

    def _get_flag_names(flags_hex: str) -> list[str]:
        """Extract flag names from hex string."""
        try:
            flags_int = int(flags_hex, 16)
        except (ValueError, TypeError):
            return []

        names: list[str] = []
        if flags_int & 0x01:  # FIN
            names.append("FIN")
        if flags_int & 0x02:  # SYN
            names.append("SYN")
        if flags_int & 0x04:  # RST
            names.append("RST")
        if flags_int & 0x08:  # PSH
            names.append("PSH")
        if flags_int & 0x10:  # ACK
            names.append("ACK")
        if flags_int & 0x20:  # URG
            names.append("URG")
        if flags_int & 0x40:  # ECE
            names.append("ECE")
        if flags_int & 0x80:  # CWR
            names.append("CWR")

        return names

    baseline_flags = _get_flag_names(flags_baseline)
    compare_flags = _get_flag_names(flags_compare)

    baseline_str = "+".join(baseline_flags) if baseline_flags else "NONE"
    compare_str = "+".join(compare_flags) if compare_flags else "NONE"

    # Determine which side should have the Local Side marker based on typical TCP flow
    flag_priority = {
        "SYN": 1,
        "SYN+ACK": 2,
        "ACK": 3,
        "PSH+ACK": 4,
        "FIN": 5,
        "FIN+ACK": 6,  # FIN+ACK comes after FIN (response)
        "RST": 7,
        "RST+ACK": 8,  # RST+ACK comes after RST (response)
    }

    baseline_priority = flag_priority.get(baseline_str, 999)
    compare_priority = flag_priority.get(compare_str, 999)

    if baseline_priority <= compare_priority:
        return f"{baseline_str} (Local Side) -> {compare_str}"
    else:
        # Swap to maintain natural order, but keep Local Side on baseline
        return f"{compare_str} -> {baseline_str} (Local Side)"

