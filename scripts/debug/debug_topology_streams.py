#!/usr/bin/env python3
"""Debug script to print TcpConnection roles for key streams.

This is used to verify that topology uses roles from PCAP extraction
(rather than from matched_connections.txt).
"""

from pathlib import Path

from capmaster.core.connection.connection_extractor import extract_connections_from_pcap


def print_stream_roles(pcap_path: str, label: str) -> None:
    path = Path(pcap_path)
    conns = extract_connections_from_pcap(path)
    by_id = {c.stream_id: c for c in conns}
    print(f"=== {label}: {path.name} ===")
    for sid in sorted(by_id):
        if sid not in (0, 1, 2):
            continue
        c = by_id[sid]
        print(
            f"stream {sid}: client {c.client_ip}:{c.client_port} -> "
            f"server {c.server_ip}:{c.server_port} (proto={c.protocol})"
        )
    print()


if __name__ == "__main__":
    print_stream_roles("data/2hops/dbs_ori/0215-0315_10.64.0.125.pcap", "Capture A")
    print_stream_roles("data/2hops/dbs_ori/idc_appdbdefault_20250910030547.pcap", "Capture B")

