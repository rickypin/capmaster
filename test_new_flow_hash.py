#!/usr/bin/env python3
"""Test the new flow hash implementation against the provided reference code."""

import ipaddress


def rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & 0xffffffffffffffff


def siphash13(key: bytes, msgs: list[bytes]) -> int:
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
        v1 = rotl(v1, 13)
        v1 ^= v0
        v0 = rotl(v0, 32)
        v2 = (v2 + v3) & 0xffffffffffffffff
        v3 = rotl(v3, 16)
        v3 ^= v2
        v0 = (v0 + v3) & 0xffffffffffffffff
        v3 = rotl(v3, 21)
        v3 ^= v0
        v2 = (v2 + v1) & 0xffffffffffffffff
        v1 = rotl(v1, 17)
        v1 ^= v2
        v2 = rotl(v2, 32)

    def load_int_le(buf, offset, len):
        return int.from_bytes(buf[offset:offset+len], "little")

    def u8to64_le(buf: bytes, start, len):
        i = 0
        out = 0
        if i + 3 < len:
            out = load_int_le(buf, start + i, 4)
            i += 4
        if i + 1 < len:
            out |= load_int_le(buf, start + i, 2) << (i * 8)
            i += 2
        if i < len:
            out |= buf[start + i] << (i * 8)
            i += 1
        return out

    for msg in msgs:
        length += len(msg)
        needed = 0
        if ntail != 0:
            needed = 8 - ntail
            tail |= u8to64_le(msg, 0, min(len(msg), needed)) << (8 * ntail)
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
        tail = u8to64_le(msg, offset, left)
        ntail = left

    # process message blocks
    t = (length & 0xff) << 56 | tail

    v3 ^= t
    sip_round()
    v0 ^= t

    # finalization
    v2 ^= 0xff
    sip_round()
    sip_round()
    sip_round()

    return (v0 ^ v1 ^ v2 ^ v3) & 0xffffffffffffffff


def u64_to_i64(u):
    u &= 0xFFFFFFFFFFFFFFFF  # 保证只保留 64 位
    if u >= 0x8000000000000000:
        return u - 0x10000000000000000
    return u


def calculate_flow_hash_reference(ip1: str, ip2: str, port1: int, port2: int, proto: int = 6) -> int:
    """Reference implementation from the provided Python code."""
    key = b"\x00" * 16

    msg = port1.to_bytes(2, "big")
    msg2 = port2.to_bytes(2, "big")
    msg3 = (0).to_bytes(8, "little")
    msg4 = (4).to_bytes(8, "little")
    msg5 = ipaddress.IPv4Address(ip1).packed
    msg6 = (0).to_bytes(8, "little")
    msg7 = (4).to_bytes(8, "little")
    msg8 = ipaddress.IPv4Address(ip2).packed
    msg9 = (1).to_bytes(8, "little")
    msg10 = proto.to_bytes(1, "big")

    # Swap logic
    if int.from_bytes(msg, "little") <= int.from_bytes(msg2, "little"):
        msg, msg2 = msg2, msg
        if msg < msg2 or msg3 < msg4:
            msg4, msg6 = msg6, msg4
            msg3, msg5 = msg5, msg3

    return u64_to_i64(siphash13(key, [msg, msg2, msg3, msg4, msg5, msg6, msg7, msg8, msg9, msg10]))


# Test with the example from the provided code
if __name__ == "__main__":
    port1 = 26302
    port2 = 35101
    ip1 = "8.67.2.125"
    ip2 = "8.42.96.45"
    proto = 6

    result = calculate_flow_hash_reference(ip1, ip2, port1, port2, proto)
    print(f"Flow hash: {result}")
    print(f"Expected: (from your code)")

    # Test bidirectional consistency
    print("\nBidirectional consistency test:")
    test_cases = [
        ("8.67.2.125", "8.42.96.45", 26302, 35101, 6),
        ("192.168.1.1", "10.0.0.1", 12345, 80, 6),
        ("10.0.0.1", "192.168.1.1", 80, 12345, 6),
    ]

    for ip1, ip2, port1, port2, proto in test_cases:
        hash_val1 = calculate_flow_hash_reference(ip1, ip2, port1, port2, proto)
        hash_val2 = calculate_flow_hash_reference(ip2, ip1, port2, port1, proto)
        match = "✓" if hash_val1 == hash_val2 else "✗"
        print(f"{match} {ip1}:{port1} <-> {ip2}:{port2}")
        print(f"  Forward:  {hash_val1}")
        print(f"  Backward: {hash_val2}")
        print()

