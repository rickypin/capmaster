"""Connection matching logic with bucketing strategies."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from capmaster.core.connection.models import TcpConnection
from capmaster.core.connection.scorer import ConnectionScorer, MatchScore


class BucketStrategy(Enum):
    """Bucketing strategy for connection matching."""

    AUTO = "auto"
    """Automatically choose the best strategy"""

    SERVER = "server"
    """Bucket by server IP address"""

    PORT = "port"
    """Bucket by server port"""

    NONE = "none"
    """No bucketing (compare all connections)"""


class MatchMode(Enum):
    """Matching mode for connection matching."""

    ONE_TO_ONE = "one-to-one"
    """Greedy one-to-one matching (default, backward compatible)"""

    ONE_TO_MANY = "one-to-many"
    """Allow one connection to match multiple connections based on time overlap"""


@dataclass
class ConnectionMatch:
    """
    A matched pair of connections.
    """

    conn1: TcpConnection
    """Connection from first PCAP"""

    conn2: TcpConnection
    """Connection from second PCAP"""

    score: MatchScore
    """Match score"""

    def __str__(self) -> str:
        """String representation."""
        return (
            f"Match(score={self.score.normalized_score:.2f}, "
            f"{self.conn1.client_ip}:{self.conn1.client_port} <-> {self.conn1.server_ip}:{self.conn1.server_port})"
        )




def choose_bucket_strategy_auto(
    connections1: Sequence[TcpConnection],
    connections2: Sequence[TcpConnection],
) -> BucketStrategy:
    """Auto-select bucketing strategy based on connection characteristics.

    This implements the NAT-aware heuristic shared by ConnectionMatcher and
    BehavioralMatcher. Callers should handle non-AUTO strategies before
    delegating here.
    """
    # Auto-select based on connection characteristics
    # NAT-aware heuristic to support both SNAT and DNAT automatically.
    # Heuristics:
    # - If client IPs have no overlap but server IPs overlap -> likely SNAT → use PORT
    # - If server IPs have no overlap but client IPs overlap -> likely DNAT → use PORT
    # - If neither clients nor servers overlap but there are common ports -> ambiguous NAT/LB → use PORT
    # - If servers are identical on both sides -> use SERVER (high precision)
    # - Else if some common servers exist -> prefer SERVER; otherwise PORT

    # Count unique clients, servers and ports
    clients1 = {c.client_ip for c in connections1}
    clients2 = {c.client_ip for c in connections2}
    servers1 = {c.server_ip for c in connections1}
    servers2 = {c.server_ip for c in connections2}
    ports1 = {c.server_port for c in connections1}
    ports2 = {c.server_port for c in connections2}

    # Intersections
    common_clients = clients1 & clients2
    common_servers = servers1 & servers2
    common_ports = ports1 & ports2

    # NAT likelihood checks
    snat_likely = (not common_clients) and bool(common_servers)
    dnat_likely = (not common_servers) and bool(common_clients)
    nat_ambiguous = (not common_clients) and (not common_servers) and bool(common_ports)

    if snat_likely or dnat_likely or nat_ambiguous:
        # PORT bucketing is robust to IP translation (only requires a common port)
        return BucketStrategy.PORT

    # If servers are identical, use SERVER bucketing (highest precision)
    if common_servers and len(common_servers) == len(servers1) == len(servers2):
        return BucketStrategy.SERVER

    # If servers differ but have common ports, use PORT bucketing (NAT/LB friendly)
    if not common_servers and common_ports:
        return BucketStrategy.PORT

    # If have some common servers, prefer SERVER bucketing
    if common_servers:
        return BucketStrategy.SERVER

    # Default to PORT bucketing (more flexible for NAT scenarios)
    return BucketStrategy.PORT


def create_buckets(
    connections: Sequence[TcpConnection],
    strategy: BucketStrategy,
) -> dict[str, list[TcpConnection]]:
    """Create buckets of connections based on strategy.

    Shared helper for ConnectionMatcher and BehavioralMatcher.
    """
    buckets: dict[str, list[TcpConnection]] = defaultdict(list)

    for conn in connections:
        if strategy == BucketStrategy.SERVER:
            # Use both IPs from normalized 5-tuple to handle direction independence
            ip1, port1, ip2, port2 = conn.get_normalized_5tuple()
            key = f"{ip1}:{ip2}"
            buckets[key].append(conn)
        elif strategy == BucketStrategy.PORT:
            # OPTIMIZATION: Place connection only in server_port bucket
            # This reduces memory usage by 30-40% compared to placing in both ports
            # After ServerDetector improvement, server_port should be reliable
            # Connections with the same server_port will be in the same bucket
            # Example:
            #   Connection A: 47525 <-> 10007  buckets["10007"]
            #   Connection B: 1425 <-> 10007   buckets["10007"]
            #   They will both be in buckets["10007"] and can be matched
            buckets[str(conn.server_port)].append(conn)
        else:  # NONE or AUTO (fallback)
            key = "all"
            buckets[key].append(conn)

    return buckets

class ConnectionMatcher:
    """
    Match connections between two PCAP files.

    Supports two matching modes:
    - ONE_TO_ONE: Greedy one-to-one matching (default, backward compatible)
    - ONE_TO_MANY: Allow one connection to match multiple connections based on time overlap

    Uses bucketing to improve performance.

    Implements weighted normalization scoring matching the original script.
    """

    def __init__(
        self,
        bucket_strategy: BucketStrategy = BucketStrategy.AUTO,
        score_threshold: float = 0.60,
        match_mode: MatchMode = MatchMode.ONE_TO_ONE,
    ):
        """
        Initialize the matcher.

        Args:
            bucket_strategy: Strategy for bucketing connections
            score_threshold: Minimum normalized score for a valid match (default: 0.60)
                           Matching original script's default threshold
            match_mode: Matching mode (ONE_TO_ONE or ONE_TO_MANY, default: ONE_TO_ONE)
        """
        self.bucket_strategy = bucket_strategy
        self.score_threshold = score_threshold
        self.match_mode = match_mode
        self.scorer = ConnectionScorer()

    def match(
        self,
        connections1: Sequence[TcpConnection],
        connections2: Sequence[TcpConnection],
    ) -> list[ConnectionMatch]:
        """
        Match connections between two sets.

        Args:
            connections1: Connections from first PCAP
            connections2: Connections from second PCAP

        Returns:
            List of matched connection pairs
        """
        # Choose bucketing strategy
        strategy = self._choose_strategy(connections1, connections2)

        # Create buckets
        buckets1 = self._create_buckets(connections1, strategy)
        buckets2 = self._create_buckets(connections2, strategy)

        # Match within each bucket
        matches = []
        # Track matched pairs to avoid duplicates (for PORT bucketing where connections appear in multiple buckets)
        seen_pairs: set[tuple[int, int]] = set()

        for bucket_key in buckets1.keys():
            if bucket_key in buckets2:
                bucket_matches = self._match_bucket(
                    buckets1[bucket_key],
                    buckets2[bucket_key],
                )
                # Deduplicate matches by stream_id pair
                for match in bucket_matches:
                    pair_key = (match.conn1.stream_id, match.conn2.stream_id)
                    if pair_key not in seen_pairs:
                        seen_pairs.add(pair_key)
                        matches.append(match)

        # Align port directions: ensure same ports are on the same side (client or server)
        # Prioritize connections with SYN packets (more reliable server detection)
        matches = self._align_port_directions(matches)

        return matches

    def _choose_strategy(
        self,
        connections1: Sequence[TcpConnection],
        connections2: Sequence[TcpConnection],
    ) -> BucketStrategy:
        """
        Choose the best bucketing strategy.

        Args:
            connections1: Connections from first PCAP
            connections2: Connections from second PCAP

        Returns:
            Chosen bucketing strategy
        """
        if self.bucket_strategy != BucketStrategy.AUTO:
            return self.bucket_strategy

        return choose_bucket_strategy_auto(connections1, connections2)


    def _create_buckets(
        self,
        connections: Sequence[TcpConnection],
        strategy: BucketStrategy,
    ) -> dict[str, list[TcpConnection]]:
        """Create buckets of connections based on strategy.

        Uses shared helper to keep bucketing behavior consistent across matchers.
        """
        return create_buckets(connections, strategy)

    def _match_bucket(
        self,
        bucket1: list[TcpConnection],
        bucket2: list[TcpConnection],
    ) -> list[ConnectionMatch]:
        """
        Match connections within a bucket.

        Supports two modes:
        - ONE_TO_ONE: Greedy one-to-one matching (each connection matches at most once)
        - ONE_TO_MANY: Allow one connection to match multiple connections

        Args:
            bucket1: Connections from first PCAP
            bucket2: Connections from second PCAP

        Returns:
            List of matched pairs
        """
        if self.match_mode == MatchMode.ONE_TO_ONE:
            return self._match_bucket_one_to_one(bucket1, bucket2)
        else:
            return self._match_bucket_one_to_many(bucket1, bucket2)

    def _match_bucket_one_to_one(
        self,
        bucket1: list[TcpConnection],
        bucket2: list[TcpConnection],
    ) -> list[ConnectionMatch]:
        """
        Match connections using greedy one-to-one algorithm.

        Each connection can match at most once.

        Args:
            bucket1: Connections from first PCAP
            bucket2: Connections from second PCAP

        Returns:
            List of matched pairs
        """
        matches = []
        used1 = set()
        used2 = set()

        # Score all pairs
        scored_pairs = []

        for i, conn1 in enumerate(bucket1):
            for j, conn2 in enumerate(bucket2):
                # OPTIMIZATION: Pre-filter invalid matches before expensive scoring
                # Check server port requirement first - fast check
                # At least one common port (the server port) must match
                ports1 = {conn1.client_port, conn1.server_port}
                ports2 = {conn2.client_port, conn2.server_port}
                if not (ports1 & ports2):
                    continue

                # Check IPID requirement - fast set intersection check (direction-aware with overlap threshold)
                ipid_ok = self._check_ipid_prefilter(conn1, conn2)
                if not ipid_ok:
                    # Try microflow auto-accept path (relaxed IPID for ultra-short flows)
                    micro_score = self.scorer.score_microflow(conn1, conn2)
                    if micro_score and micro_score.is_valid_match(self.score_threshold):
                        scored_pairs.append((0, micro_score.normalized_score, i, j, conn1, conn2, micro_score))
                    continue

                # Only score if pre-checks pass
                score = self.scorer.score(conn1, conn2)

                if score.is_valid_match(self.score_threshold):
                    # Prioritize strong IPID matches in sorting
                    scored_pairs.append((1 if score.force_accept else 0, score.normalized_score, i, j, conn1, conn2, score))

        # Sort by (force_accept, normalized score, stream_id1, stream_id2) descending
        # Using stream IDs as tie-breakers ensures stable, deterministic sorting
        # when multiple pairs have the same score
        scored_pairs.sort(key=lambda x: (x[0], x[1], -x[4].stream_id, -x[5].stream_id), reverse=True)

        # Greedy matching: take highest scoring pairs first
        for _, _, i, j, conn1, conn2, score in scored_pairs:
            if i not in used1 and j not in used2:
                matches.append(ConnectionMatch(conn1, conn2, score))
                used1.add(i)
                used2.add(j)

        return matches

    def _match_bucket_one_to_many(
        self,
        bucket1: list[TcpConnection],
        bucket2: list[TcpConnection],
    ) -> list[ConnectionMatch]:
        """
        Match connections allowing one-to-many relationships.

        One connection can match multiple connections if they have:
        - Same IPID
        - Time overlap
        - Score above threshold

        This is useful when one PCAP has a long stream that spans multiple
        shorter streams in another PCAP (same 5-tuple, different time ranges).

        Args:
            bucket1: Connections from first PCAP
            bucket2: Connections from second PCAP

        Returns:
            List of matched pairs (can have multiple matches per connection)
        """
        matches = []

        # Score all pairs and accept all valid matches
        for conn1 in bucket1:
            for conn2 in bucket2:
                # OPTIMIZATION: Pre-filter invalid matches before expensive scoring
                # Check server port requirement first - fast check
                # At least one common port (the server port) must match
                ports1 = {conn1.client_port, conn1.server_port}
                ports2 = {conn2.client_port, conn2.server_port}
                if not (ports1 & ports2):
                    continue

                # Check IPID requirement - fast set intersection check (direction-aware with overlap threshold)
                ipid_ok = self._check_ipid_prefilter(conn1, conn2)
                if not ipid_ok:
                    # Try microflow auto-accept path (relaxed IPID for ultra-short flows)
                    micro_score = self.scorer.score_microflow(conn1, conn2)
                    if micro_score and micro_score.is_valid_match(self.score_threshold):
                        matches.append(ConnectionMatch(conn1, conn2, micro_score))
                    continue

                # Only score if pre-checks pass
                score = self.scorer.score(conn1, conn2)

                if score.is_valid_match(self.score_threshold):
                    matches.append(ConnectionMatch(conn1, conn2, score))

        # Sort by (force_accept, normalized score, stream_id1, stream_id2) descending for consistent ordering
        # Using stream IDs as tie-breakers ensures stable, deterministic sorting
        matches.sort(key=lambda m: (1 if m.score.force_accept else 0, m.score.normalized_score, -m.conn1.stream_id, -m.conn2.stream_id), reverse=True)

        return matches

    def _check_ipid_prefilter(self, conn1: TcpConnection, conn2: TcpConnection) -> bool:
        """
        Fast IPID prefilter check with overlap threshold.

        This is a lightweight version of the full IPID check in scorer,
        used for early filtering to avoid expensive scoring operations.

        Uses global IPID matching (not direction-aware) to avoid false negatives
        from incorrect client/server role detection.

        OPTIMIZATION: Uses early exit strategy - stops as soon as we find
        enough overlapping IPIDs, avoiding full set intersection for large sets.

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            True if connections have sufficient IPID overlap, False otherwise
        """
        # OPTIMIZATION: For small sets, use linear search with early exit
        # This is faster than set intersection for small sets
        if len(conn1.ipid_set) < 10 or len(conn2.ipid_set) < 10:
            overlap_count = 0
            # Iterate over the smaller set for efficiency
            smaller_set = conn1.ipid_set if len(conn1.ipid_set) <= len(conn2.ipid_set) else conn2.ipid_set
            larger_set = conn2.ipid_set if smaller_set is conn1.ipid_set else conn1.ipid_set

            for ipid in smaller_set:
                if ipid in larger_set:
                    overlap_count += 1
                    # Early exit: found enough overlap
                    if overlap_count >= self.scorer.MIN_IPID_OVERLAP:
                        return True
            return False

        # For large sets, use set intersection (still efficient)
        # But we can still benefit from early exit by checking length first
        intersection = conn1.ipid_set & conn2.ipid_set
        return len(intersection) >= self.scorer.MIN_IPID_OVERLAP

    def get_match_stats(
        self,
        connections1: Sequence[TcpConnection],
        connections2: Sequence[TcpConnection],
        matches: Sequence[ConnectionMatch],
    ) -> dict:
        """
        Get statistics about the matching operation.

        Note: In ONE_TO_MANY mode, matched_pairs can be greater than
        total_connections_1 or total_connections_2 because one connection
        can match multiple connections.

        Args:
            connections1: Connections from first PCAP
            connections2: Connections from second PCAP
            matches: Matched pairs

        Returns:
            Dictionary with matching statistics
        """
        matched1 = {m.conn1.stream_id for m in matches}
        matched2 = {m.conn2.stream_id for m in matches}

        avg_score = sum(m.score.normalized_score for m in matches) / len(matches) if matches else 0

        stats = {
            "total_connections_1": len(connections1),
            "total_connections_2": len(connections2),
            "matched_pairs": len(matches),
            "unique_matched_1": len(matched1),
            "unique_matched_2": len(matched2),
            "unmatched_1": len(connections1) - len(matched1),
            "unmatched_2": len(connections2) - len(matched2),
            "match_rate_1": len(matched1) / len(connections1) if connections1 else 0,
            "match_rate_2": len(matched2) / len(connections2) if connections2 else 0,
            "average_score": avg_score,
            "match_mode": self.match_mode.value,
        }

        # Add one-to-many specific stats
        if self.match_mode == MatchMode.ONE_TO_MANY:
            # Count how many times each connection was matched
            from collections import Counter

            conn1_match_counts = Counter(m.conn1.stream_id for m in matches)
            conn2_match_counts = Counter(m.conn2.stream_id for m in matches)

            stats["max_matches_per_conn1"] = max(conn1_match_counts.values()) if conn1_match_counts else 0
            stats["max_matches_per_conn2"] = max(conn2_match_counts.values()) if conn2_match_counts else 0
            stats["avg_matches_per_conn1"] = (
                sum(conn1_match_counts.values()) / len(conn1_match_counts) if conn1_match_counts else 0
            )
            stats["avg_matches_per_conn2"] = (
                sum(conn2_match_counts.values()) / len(conn2_match_counts) if conn2_match_counts else 0
            )

        return stats

    def _align_port_directions(self, matches: list[ConnectionMatch]) -> list[ConnectionMatch]:
        """
        Align port directions in matched connections.

        Ensures that the same port appears on the same side (client or server) in both connections.
        Prioritizes connections with SYN packets for more reliable server detection.

        Args:
            matches: List of matched connection pairs

        Returns:
            List of matches with aligned port directions

        Example:
            Before alignment:
                conn1: 8.67.2.125:26302 (server) <-> 8.42.96.45:35101 (client)
                conn2: 8.42.96.45:35101 (server) <-> 8.67.2.125:26302 (client)
                → Port 26302 is server in conn1 but client in conn2 (contradiction!)

            After alignment (assuming conn1 has SYN packet):
                conn1: 8.67.2.125:26302 (server) <-> 8.42.96.45:35101 (client)
                conn2: 8.67.2.125:26302 (server) <-> 8.42.96.45:35101 (client)
                → Port 26302 is server in both connections ✓
        """
        aligned_matches = []

        for match in matches:
            conn1 = match.conn1
            conn2 = match.conn2

            # Get port sets for both connections
            ports1 = {conn1.client_port, conn1.server_port}
            ports2 = {conn2.client_port, conn2.server_port}

            # Find common ports (should have at least one)
            common_ports = ports1 & ports2

            if not common_ports:
                # No common ports - keep original match
                aligned_matches.append(match)
                continue

            # Check if port directions are aligned
            # For each common port, check if it's on the same side (client or server)
            needs_swap = False

            for port in common_ports:
                # Check where this port appears in each connection
                is_server1 = (port == conn1.server_port)
                is_server2 = (port == conn2.server_port)

                if is_server1 != is_server2:
                    # Port is on different sides - need to swap one connection
                    needs_swap = True
                    break

            if not needs_swap:
                # Directions already aligned
                aligned_matches.append(match)
                continue

            # Need to swap one connection's direction
            # Prioritize keeping the connection with SYN packet (more reliable server detection)
            has_syn1 = conn1.syn_timestamp is not None
            has_syn2 = conn2.syn_timestamp is not None

            if has_syn1 and not has_syn2:
                # Keep conn1, swap conn2
                swapped_conn2 = self._swap_connection_direction(conn2)
                aligned_matches.append(ConnectionMatch(conn1, swapped_conn2, match.score))
            elif has_syn2 and not has_syn1:
                # Keep conn2, swap conn1
                swapped_conn1 = self._swap_connection_direction(conn1)
                aligned_matches.append(ConnectionMatch(swapped_conn1, conn2, match.score))
            else:
                # Both have SYN or both don't have SYN
                # Default: keep conn1, swap conn2
                swapped_conn2 = self._swap_connection_direction(conn2)
                aligned_matches.append(ConnectionMatch(conn1, swapped_conn2, match.score))

        return aligned_matches

    def _swap_connection_direction(self, conn: TcpConnection) -> TcpConnection:
        """
        Swap client/server roles in a connection.

        Args:
            conn: Connection to swap

        Returns:
            New connection with swapped client/server roles
        """
        return TcpConnection(
            stream_id=conn.stream_id,
            protocol=conn.protocol,
            # Swap IPs and ports
            client_ip=conn.server_ip,
            client_port=conn.server_port,
            server_ip=conn.client_ip,
            server_port=conn.client_port,
            # Keep timestamps
            syn_timestamp=conn.syn_timestamp,
            syn_options=conn.syn_options,
            # Swap ISNs
            client_isn=conn.server_isn,
            server_isn=conn.client_isn,
            # Keep TCP timestamps
            tcp_timestamp_tsval=conn.tcp_timestamp_tsval,
            tcp_timestamp_tsecr=conn.tcp_timestamp_tsecr,
            # Swap payloads
            client_payload_md5=conn.server_payload_md5,
            server_payload_md5=conn.client_payload_md5,
            # Keep signatures
            length_signature=conn.length_signature,
            is_header_only=conn.is_header_only,
            # Keep global IPID set
            ipid_set=conn.ipid_set,
            ipid_first=conn.ipid_first,
            # Swap direction-specific IPID sets
            client_ipid_set=conn.server_ipid_set,
            server_ipid_set=conn.client_ipid_set,
            # Keep time info
            first_packet_time=conn.first_packet_time,
            last_packet_time=conn.last_packet_time,
            packet_count=conn.packet_count,
            # Swap TTLs
            client_ttl=conn.server_ttl,
            server_ttl=conn.client_ttl,
        )
