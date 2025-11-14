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

    This function supports both stream_id-based matching (for normal extraction)
    and 5-tuple-based matching (for --merge-by-5tuple mode).
    """
    from capmaster.core.connection.matcher import ConnectionMatch
    from capmaster.core.connection.scorer import MatchScore

    # Build lookup maps using both stream_id and normalized 5-tuple
    # This allows matching to work in both normal and merge-by-5tuple modes
    conn1_by_stream = {conn.stream_id: conn for conn in connections1}
    conn2_by_stream = {conn.stream_id: conn for conn in connections2}

    # Build 5-tuple maps for merge-by-5tuple mode
    # Use normalized 5-tuple to handle direction independence
    conn1_by_5tuple = {conn.get_normalized_5tuple(): conn for conn in connections1}
    conn2_by_5tuple = {conn.get_normalized_5tuple(): conn for conn in connections2}

    matches: list = []
    matched_count = 0
    stream_id_matched = 0
    tuple_matched = 0

    for f5_match in f5_matches:
        conn1 = None
        conn2 = None

        # Try stream_id lookup first (for normal mode)
        conn1 = conn1_by_stream.get(f5_match.snat_stream_id)
        conn2 = conn2_by_stream.get(f5_match.vip_stream_id)

        if conn1 and conn2:
            stream_id_matched += 1
        else:
            # Fallback to 5-tuple lookup (for merge-by-5tuple mode)
            # Build normalized 5-tuple from F5 match info
            snat_5tuple = _normalize_5tuple(
                f5_match.snat_src_ip,
                f5_match.snat_src_port,
                f5_match.snat_dst_ip,
                f5_match.snat_dst_port,
            )
            vip_5tuple = _normalize_5tuple(
                f5_match.vip_src_ip,
                f5_match.vip_src_port,
                f5_match.vip_dst_ip,
                f5_match.vip_dst_port,
            )

            conn1 = conn1_by_5tuple.get(snat_5tuple)
            conn2 = conn2_by_5tuple.get(vip_5tuple)

            if conn1 and conn2:
                tuple_matched += 1

        if conn1 and conn2:
            matched_count += 1
            score = MatchScore(
                normalized_score=1.0,
                raw_score=1.0,
                available_weight=1.0,
                ipid_match=True,
                evidence=f"F5_TRAILER(client={f5_match.client_ip}:{f5_match.client_port})",
                force_accept=True,
            )
            matches.append(ConnectionMatch(conn1=conn1, conn2=conn2, score=score))

    # Log matching statistics for debugging
    from capmaster.utils.logger import get_logger
    logger = get_logger(__name__)
    logger.debug(
        f"F5 match conversion: {matched_count}/{len(f5_matches)} matched "
        f"(stream_id: {stream_id_matched}, 5-tuple: {tuple_matched})"
    )

    return matches


def _normalize_5tuple(ip1: str, port1: int, ip2: str, port2: int) -> tuple[str, int, str, int]:
    """
    Normalize a 5-tuple to canonical form for direction-independent matching.

    Args:
        ip1: First IP address
        port1: First port
        ip2: Second IP address
        port2: Second port

    Returns:
        Normalized 5-tuple (ip1, port1, ip2, port2) where ip1:port1 <= ip2:port2
    """
    endpoint1 = (ip1, port1)
    endpoint2 = (ip2, port2)

    if endpoint1 <= endpoint2:
        return (ip1, port1, ip2, port2)
    else:
        return (ip2, port2, ip1, port1)


def convert_tls_matches_to_connection_matches(
    tls_matches: list,
    connections1: list,
    connections2: list,
) -> List:
    """Convert TLS matcher results to ConnectionMatch list.

    Evidence uses the Client Hello random and session_id as a strong identifier.

    This function supports both stream_id-based matching (for normal extraction)
    and 5-tuple-based matching (for --merge-by-5tuple mode).
    """
    from capmaster.core.connection.matcher import ConnectionMatch
    from capmaster.core.connection.scorer import MatchScore

    # Build lookup maps using both stream_id and normalized 5-tuple
    conn1_by_stream = {conn.stream_id: conn for conn in connections1}
    conn2_by_stream = {conn.stream_id: conn for conn in connections2}

    # Build 5-tuple maps for merge-by-5tuple mode
    conn1_by_5tuple = {conn.get_normalized_5tuple(): conn for conn in connections1}
    conn2_by_5tuple = {conn.get_normalized_5tuple(): conn for conn in connections2}

    matches: list = []
    matched_count = 0
    stream_id_matched = 0
    tuple_matched = 0

    for tls_match in tls_matches:
        conn1 = None
        conn2 = None

        # Try stream_id lookup first (for normal mode)
        conn1 = conn1_by_stream.get(tls_match.stream_id_1)
        conn2 = conn2_by_stream.get(tls_match.stream_id_2)

        if conn1 and conn2:
            stream_id_matched += 1
        else:
            # Fallback to 5-tuple lookup (for merge-by-5tuple mode)
            tuple_1 = _normalize_5tuple(
                tls_match.src_ip_1,
                tls_match.src_port_1,
                tls_match.dst_ip_1,
                tls_match.dst_port_1,
            )
            tuple_2 = _normalize_5tuple(
                tls_match.src_ip_2,
                tls_match.src_port_2,
                tls_match.dst_ip_2,
                tls_match.dst_port_2,
            )

            conn1 = conn1_by_5tuple.get(tuple_1)
            conn2 = conn2_by_5tuple.get(tuple_2)

            if conn1 and conn2:
                tuple_matched += 1

        if conn1 and conn2:
            matched_count += 1
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

    # Log matching statistics for debugging
    from capmaster.utils.logger import get_logger
    logger = get_logger(__name__)
    logger.debug(
        f"TLS match conversion: {matched_count}/{len(tls_matches)} matched "
        f"(stream_id: {stream_id_matched}, 5-tuple: {tuple_matched})"
    )

    return matches

