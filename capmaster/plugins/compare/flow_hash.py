"""Flow hash calculation for TCP connections.

This module implements flow hash calculation using SipHash-1-3 algorithm.

The implementation uses:
- SipHash-1-3 with multi-message support
- Big-endian for ports in the hash input
- Special message structure with IP address length markers
- Normalization logic for bidirectional flow consistency

The hash calculation follows this message structure:
1. Port 1 (2 bytes, big-endian)
2. Port 2 (2 bytes, big-endian)
3. IP length marker 1 (8 bytes, little-endian, value=0)
4. IP length marker 2 (8 bytes, little-endian, value=4)
5. IP address 1 (4 bytes, packed)
6. IP length marker 3 (8 bytes, little-endian, value=0)
7. IP length marker 4 (8 bytes, little-endian, value=4)
8. IP address 2 (4 bytes, packed)
9. Fixed value (8 bytes, little-endian, value=1)
10. Protocol (1 byte, big-endian)

The messages are normalized by comparing ports and swapping if needed.
"""

from __future__ import annotations
import ipaddress
import struct
from enum import IntEnum


class FlowSide(IntEnum):
    """Flow direction indicator."""
    UNKNOWN = 0
    LHS_GE_RHS = 1  # Left-hand side >= Right-hand side
    RHS_GT_LHS = 2  # Right-hand side > Left-hand side


def _rotl64(x: int, b: int) -> int:
    """Rotate left for 64-bit integer."""
    return ((x << b) | (x >> (64 - b))) & 0xFFFFFFFFFFFFFFFF


def _siphash_round(v0: int, v1: int, v2: int, v3: int) -> tuple[int, int, int, int]:
    """Perform one SipHash round."""
    v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF
    v1 = _rotl64(v1, 13)
    v1 ^= v0
    v0 = _rotl64(v0, 32)

    v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF
    v3 = _rotl64(v3, 16)
    v3 ^= v2

    v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF
    v3 = _rotl64(v3, 21)
    v3 ^= v0

    v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF
    v1 = _rotl64(v1, 17)
    v1 ^= v2
    v2 = _rotl64(v2, 32)

    return v0, v1, v2, v3


def _load_int_le(buf: bytes, offset: int, length: int) -> int:
    """Load integer from buffer in little-endian format."""
    return int.from_bytes(buf[offset:offset+length], "little")


def _u8to64_le(buf: bytes, start: int, length: int) -> int:
    """Convert up to 8 bytes to a 64-bit integer in little-endian format."""
    i = 0
    out = 0
    if i + 3 < length:
        out = _load_int_le(buf, start + i, 4)
        i += 4
    if i + 1 < length:
        out |= _load_int_le(buf, start + i, 2) << (i * 8)
        i += 2
    if i < length:
        out |= buf[start + i] << (i * 8)
        i += 1
    return out


def siphash13(key: bytes, msgs: list[bytes]) -> int:
    """
    SipHash-1-3 implementation with multi-message support.

    This implementation processes multiple messages sequentially,
    maintaining state across message boundaries.

    Args:
        key: 16-byte key for SipHash
        msgs: List of byte messages to hash

    Returns:
        64-bit hash value as unsigned integer
    """
    assert len(key) == 16

    k0 = int.from_bytes(key[:8], "little")
    k1 = int.from_bytes(key[8:], "little")

    v0 = 0x736f6d6570736575 ^ k0
    v1 = 0x646f72616e646f6d ^ k1
    v2 = 0x6c7967656e657261 ^ k0
    v3 = 0x7465646279746573 ^ k1

    length = 0
    tail = 0
    ntail = 0

    def sip_round():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & 0xffffffffffffffff
        v1 = _rotl64(v1, 13)
        v1 ^= v0
        v0 = _rotl64(v0, 32)
        v2 = (v2 + v3) & 0xffffffffffffffff
        v3 = _rotl64(v3, 16)
        v3 ^= v2
        v0 = (v0 + v3) & 0xffffffffffffffff
        v3 = _rotl64(v3, 21)
        v3 ^= v0
        v2 = (v2 + v1) & 0xffffffffffffffff
        v1 = _rotl64(v1, 17)
        v1 ^= v2
        v2 = _rotl64(v2, 32)

    # Process all messages
    for msg in msgs:
        length += len(msg)
        needed = 0

        if ntail != 0:
            needed = 8 - ntail
            tail |= _u8to64_le(msg, 0, min(len(msg), needed)) << (8 * ntail)
            if len(msg) < needed:
                ntail += len(msg)
                continue
            else:
                v3 ^= tail
                sip_round()
                v0 ^= tail
                ntail = 0

        l = len(msg) - needed
        left = l & 0x7
        offset = needed

        while offset < l - left:
            m = int.from_bytes(msg[offset:offset+8], "little")
            offset += 8
            v3 ^= m
            sip_round()  # c=1
            v0 ^= m

        tail = _u8to64_le(msg, offset, left)
        ntail = left

    # Final block
    t = (length & 0xff) << 56 | tail

    v3 ^= t
    sip_round()
    v0 ^= t

    # Finalization
    v2 ^= 0xff
    sip_round()
    sip_round()
    sip_round()

    return (v0 ^ v1 ^ v2 ^ v3) & 0xffffffffffffffff


def _u64_to_i64(u: int) -> int:
    """Convert unsigned 64-bit integer to signed 64-bit integer."""
    u &= 0xFFFFFFFFFFFFFFFF
    if u >= 0x8000000000000000:
        return u - 0x10000000000000000
    return u


def _compare_ports(port1: int, port2: int) -> FlowSide:
    """
    Compare two ports to determine flow side.
    
    Args:
        port1: First port number
        port2: Second port number
    
    Returns:
        FlowSide indicating which side is greater
    """
    if port1 >= port2:
        return FlowSide.LHS_GE_RHS
    else:
        return FlowSide.RHS_GT_LHS


def _compare_addresses(addr1: str, addr2: str) -> FlowSide:
    """
    Compare two IP addresses to determine flow side.
    
    Args:
        addr1: First IP address (string)
        addr2: Second IP address (string)
    
    Returns:
        FlowSide indicating which side is greater
    """
    try:
        ip1 = ipaddress.ip_address(addr1)
        ip2 = ipaddress.ip_address(addr2)
        
        if ip1 >= ip2:
            return FlowSide.LHS_GE_RHS
        else:
            return FlowSide.RHS_GT_LHS
    except ValueError:
        # If IP parsing fails, fall back to string comparison
        if addr1 >= addr2:
            return FlowSide.LHS_GE_RHS
        else:
            return FlowSide.RHS_GT_LHS


def calculate_flow_hash(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: int = 6,  # TCP protocol number
) -> tuple[int, FlowSide]:
    """
    Calculate flow hash for a TCP connection using SipHash-1-3.

    This function implements a bidirectional flow hash algorithm that produces
    the same hash value for both directions of a flow. It normalizes the
    5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) by ordering
    the endpoints consistently.

    IMPORTANT: This IS a bidirectional hash. The same connection will produce
    the same hash value regardless of direction:
    - calculate_flow_hash(ip1, ip2, port1, port2) == calculate_flow_hash(ip2, ip1, port2, port1)

    The hash calculation uses a specific message structure:
    1. Port 1 (2 bytes, big-endian)
    2. Port 2 (2 bytes, big-endian)
    3. IP length marker 1 (8 bytes, little-endian, value=0)
    4. IP length marker 2 (8 bytes, little-endian, value=4)
    5. IP address 1 (4 bytes, packed)
    6. IP length marker 3 (8 bytes, little-endian, value=0)
    7. IP length marker 4 (8 bytes, little-endian, value=4)
    8. IP address 2 (4 bytes, packed)
    9. Fixed value (8 bytes, little-endian, value=1)
    10. Protocol (1 byte, big-endian)

    Normalization logic:
    - Ports are compared as little-endian integers
    - The larger port (by little-endian value) is always placed first
    - If ports are equal, IP addresses are compared
    - This ensures bidirectional consistency

    Args:
        src_ip: Source IP address (IPv4)
        dst_ip: Destination IP address (IPv4)
        src_port: Source port number
        dst_port: Destination port number
        protocol: IP protocol number (default: 6 for TCP)

    Returns:
        Tuple of (hash_value, flow_side)
        - hash_value: 64-bit signed integer hash value
        - flow_side: FlowSide enum indicating the normalization direction

    Example:
        >>> hash_val, side = calculate_flow_hash("8.67.2.125", "8.42.96.45", 26302, 35101)
        >>> print(f"Flow hash: {hash_val}, Side: {side}")
        Flow hash: -1173584886679544929, Side: FlowSide.LHS_GE_RHS
        >>> # Reverse direction produces same hash
        >>> hash_val2, side2 = calculate_flow_hash("8.42.96.45", "8.67.2.125", 35101, 26302)
        >>> assert hash_val == hash_val2  # True
    """
    key = b"\x00" * 16

    # Compare ports as little-endian integers to determine canonical order
    src_port_le = int.from_bytes(src_port.to_bytes(2, "big"), "little")
    dst_port_le = int.from_bytes(dst_port.to_bytes(2, "big"), "little")

    # Determine canonical order (larger port first)
    if src_port_le > dst_port_le:
        # src_port is larger, use original order
        p1, p2 = src_port, dst_port
        ip_1, ip_2 = src_ip, dst_ip
        flow_side = FlowSide.LHS_GE_RHS
    elif src_port_le < dst_port_le:
        # dst_port is larger, swap
        p1, p2 = dst_port, src_port
        ip_1, ip_2 = dst_ip, src_ip
        flow_side = FlowSide.RHS_GT_LHS
    else:
        # Ports equal, compare IPs
        if ipaddress.ip_address(src_ip) >= ipaddress.ip_address(dst_ip):
            p1, p2 = src_port, dst_port
            ip_1, ip_2 = src_ip, dst_ip
            flow_side = FlowSide.LHS_GE_RHS
        else:
            p1, p2 = dst_port, src_port
            ip_1, ip_2 = dst_ip, src_ip
            flow_side = FlowSide.RHS_GT_LHS

    # Build messages in canonical order
    msg1 = p1.to_bytes(2, "big")
    msg2 = p2.to_bytes(2, "big")
    msg3 = (0).to_bytes(8, "little")

    # Handle both IPv4 and IPv6
    ip_1_obj = ipaddress.ip_address(ip_1)
    ip_2_obj = ipaddress.ip_address(ip_2)

    if isinstance(ip_1_obj, ipaddress.IPv4Address):
        msg4 = (4).to_bytes(8, "little")
        msg5 = ip_1_obj.packed
    else:  # IPv6
        msg4 = (16).to_bytes(8, "little")
        msg5 = ip_1_obj.packed

    msg6 = (0).to_bytes(8, "little")

    if isinstance(ip_2_obj, ipaddress.IPv4Address):
        msg7 = (4).to_bytes(8, "little")
        msg8 = ip_2_obj.packed
    else:  # IPv6
        msg7 = (16).to_bytes(8, "little")
        msg8 = ip_2_obj.packed

    msg9 = (1).to_bytes(8, "little")
    msg10 = protocol.to_bytes(1, "big")

    # Calculate hash
    hash_value = siphash13(key, [msg1, msg2, msg3, msg4, msg5, msg6, msg7, msg8, msg9, msg10])

    # Convert to signed 64-bit integer
    hash_value = _u64_to_i64(hash_value)

    return hash_value, flow_side


def format_flow_hash(hash_value: int, flow_side: FlowSide) -> str:
    """
    Format flow hash for display.

    Args:
        hash_value: Hash value as signed 64-bit integer
        flow_side: Flow side indicator

    Returns:
        Formatted string for display

    Example:
        >>> format_flow_hash(-1234567890123456789, FlowSide.LHS_GE_RHS)
        '-1234567890123456789 (LHS>=RHS)'
    """
    side_str = {
        FlowSide.UNKNOWN: "UNKNOWN",
        FlowSide.LHS_GE_RHS: "LHS>=RHS",
        FlowSide.RHS_GT_LHS: "RHS>LHS",
    }.get(flow_side, "UNKNOWN")

    return f"{hash_value} ({side_str})"


def calculate_connection_flow_hash(
    client_ip: str,
    server_ip: str,
    client_port: int,
    server_port: int,
) -> tuple[int, FlowSide]:
    """
    Calculate flow hash for a TCP connection given client/server endpoints.

    This is a convenience wrapper around calculate_flow_hash that uses
    client/server terminology instead of src/dst.

    Args:
        client_ip: Client IP address
        server_ip: Server IP address
        client_port: Client port number
        server_port: Server port number

    Returns:
        Tuple of (hash_value, flow_side)
        - hash_value: 64-bit signed integer hash value
        - flow_side: FlowSide enum indicating the normalization direction

    Example:
        >>> hash_val, side = calculate_connection_flow_hash(
        ...     "192.168.1.100", "10.0.0.1", 54321, 80
        ... )
    """
    return calculate_flow_hash(
        src_ip=client_ip,
        dst_ip=server_ip,
        src_port=client_port,
        dst_port=server_port,
        protocol=6,  # TCP
    )

