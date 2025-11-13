"""Matching strategy conversion helpers.

These helpers transform alternative matching results (F5/TLS) into the
standard ConnectionMatch objects used elsewhere in the pipeline.
"""
from __future__ import annotations

from typing import List


def convert_f5_matches_to_connection_matches(
    f5_matches: list,
    connections1: list,
    connections2: list,
) -> List:
    """Convert F5 matcher results to ConnectionMatch list.

    The evidence is marked as coming from the F5 trailer and we force accept.
    """
    from capmaster.core.connection.matcher import ConnectionMatch
    from capmaster.core.connection.scorer import MatchScore

    conn1_map = {conn.stream_id: conn for conn in connections1}
    conn2_map = {conn.stream_id: conn for conn in connections2}

    matches: list = []
    for f5_match in f5_matches:
        conn1 = conn1_map.get(f5_match.snat_stream_id)
        conn2 = conn2_map.get(f5_match.vip_stream_id)
        if conn1 and conn2:
            score = MatchScore(
                normalized_score=1.0,
                raw_score=1.0,
                available_weight=1.0,
                ipid_match=True,
                evidence=f"F5_TRAILER(client={f5_match.client_ip}:{f5_match.client_port})",
                force_accept=True,
            )
            matches.append(ConnectionMatch(conn1=conn1, conn2=conn2, score=score))

    return matches


def convert_tls_matches_to_connection_matches(
    tls_matches: list,
    connections1: list,
    connections2: list,
) -> List:
    """Convert TLS matcher results to ConnectionMatch list.

    Evidence uses the Client Hello random and session_id as a strong identifier.
    """
    from capmaster.core.connection.matcher import ConnectionMatch
    from capmaster.core.connection.scorer import MatchScore

    conn1_map = {conn.stream_id: conn for conn in connections1}
    conn2_map = {conn.stream_id: conn for conn in connections2}

    matches: list = []
    for tls_match in tls_matches:
        conn1 = conn1_map.get(tls_match.stream_id_1)
        conn2 = conn2_map.get(tls_match.stream_id_2)
        if conn1 and conn2:
            score = MatchScore(
                normalized_score=1.0,
                raw_score=1.0,
                available_weight=1.0,
                ipid_match=True,
                evidence=(
                    f"TLS_CLIENT_HELLO(random={tls_match.random[:16]}..., "
                    f"session_id={tls_match.session_id[:16]}...)"
                ),
                force_accept=True,
            )
            matches.append(ConnectionMatch(conn1=conn1, conn2=conn2, score=score))

    return matches

