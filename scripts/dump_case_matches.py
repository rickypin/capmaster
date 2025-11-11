#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dump matched TCP connections for a given two-PCAP case directory.

Usage:
    venv/bin/python scripts/dump_case_matches.py /path/to/TC-xxx

Output:
- Lists each matched pair with:
  * A/B 5-tuple
  * packet_count for each side
  * score and evidence
- Prints a compact summary at the end.
"""
from __future__ import annotations

import sys
from pathlib import Path

from capmaster.plugins.match.connection_extractor import extract_connections_from_pcap
from capmaster.plugins.match.matcher import ConnectionMatcher, BucketStrategy, MatchMode
from capmaster.plugins.match.server_detector import ServerDetector
from capmaster.plugins.match.scorer import MatchScore
from capmaster.plugins.match.plugin import MatchPlugin


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python scripts/dump_case_matches.py <case_dir>")
        return 1

    case_dir = Path(sys.argv[1]).expanduser().resolve()
    if not case_dir.is_dir():
        print(f"Case dir not found: {case_dir}")
        return 1

    # Find exactly two PCAP files
    pcaps = [p for p in case_dir.iterdir() if p.is_file() and p.suffix.lower() in (".pcap", ".pcapng")]
    if len(pcaps) != 2:
        print(f"Expected exactly two PCAP files in {case_dir}, found {len(pcaps)}")
        for p in pcaps:
            print(" -", p.name)
        return 1

    pcaps = sorted(pcaps)
    f1, f2 = pcaps

    # Extract connections (same as plugin)
    conns1 = extract_connections_from_pcap(f1)
    conns2 = extract_connections_from_pcap(f2)

    # Improve server/client roles via cardinality analysis (same as plugin)
    det = ServerDetector()
    for c in conns1:
        det.collect_connection(c)
    for c in conns2:
        det.collect_connection(c)
    det.finalize_cardinality()

    plug = MatchPlugin()
    conns1 = plug._improve_server_detection(conns1, det)
    conns2 = plug._improve_server_detection(conns2, det)

    # Match
    matcher = ConnectionMatcher(
        bucket_strategy=BucketStrategy.AUTO,
        score_threshold=0.60,
        match_mode=MatchMode.ONE_TO_ONE,
    )
    matches = matcher.match(conns1, conns2)

    # Print
    print("=" * 80)
    print(f"Case: {case_dir.name}")
    print(f"PCAP A: {f1.name}")
    print(f"PCAP B: {f2.name}")
    print("=" * 80)
    print(f"Matched pairs: {len(matches)}\n")

    for i, m in enumerate(matches, 1):
        c1, c2 = m.conn1, m.conn2
        s: MatchScore = m.score
        print(f"[{i}] A: {c1.client_ip}:{c1.client_port} <-> {c1.server_ip}:{c1.server_port} | packets={c1.packet_count}")
        print(f"    B: {c2.client_ip}:{c2.client_port} <-> {c2.server_ip}:{c2.server_port} | packets={c2.packet_count}")
        print(f"    score={s.normalized_score:.2f} | evidence={s.evidence}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

