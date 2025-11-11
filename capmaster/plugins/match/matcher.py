"""Connection matching logic with bucketing strategies."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from capmaster.plugins.match.connection import TcpConnection
from capmaster.plugins.match.scorer import ConnectionScorer, MatchScore


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

        for bucket_key in buckets1.keys():
            if bucket_key in buckets2:
                bucket_matches = self._match_bucket(
                    buckets1[bucket_key],
                    buckets2[bucket_key],
                )
                matches.extend(bucket_matches)

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

    def _create_buckets(
        self,
        connections: Sequence[TcpConnection],
        strategy: BucketStrategy,
    ) -> dict[str, list[TcpConnection]]:
        """
        Create buckets of connections based on strategy.

        Uses normalized 5-tuple for direction-independent bucketing.

        For PORT strategy, each connection is placed in multiple buckets (one for each port).
        This allows connections with different client ports but same server port to be matched
        (e.g., for F5 SNAT scenarios where client port changes but server port remains the same).

        Args:
            connections: List of connections
            strategy: Bucketing strategy

        Returns:
            Dictionary mapping bucket keys to connection lists
        """
        buckets: dict[str, list[TcpConnection]] = defaultdict(list)

        for conn in connections:
            if strategy == BucketStrategy.SERVER:
                # Use both IPs from normalized 5-tuple to handle direction independence
                ip1, port1, ip2, port2 = conn.get_normalized_5tuple()
                key = f"{ip1}:{ip2}"
                buckets[key].append(conn)
            elif strategy == BucketStrategy.PORT:
                # Place connection in buckets for BOTH ports
                # This ensures connections with at least one common port (the server port)
                # will be in the same bucket and can be compared
                # Example:
                #   Connection A: 47525 <-> 10007 → buckets["47525"] and buckets["10007"]
                #   Connection B: 1425 <-> 10007  → buckets["1425"] and buckets["10007"]
                #   They will both be in buckets["10007"] and can be matched
                for port in {conn.client_port, conn.server_port}:
                    buckets[str(port)].append(conn)
            else:  # NONE or AUTO (fallback)
                key = "all"
                buckets[key].append(conn)

        return buckets

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

        # Sort by (force_accept, normalized score) descending
        scored_pairs.sort(key=lambda x: (x[0], x[1]), reverse=True)

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

        # Sort by (force_accept, normalized score) descending for consistent ordering
        matches.sort(key=lambda m: (1 if m.score.force_accept else 0, m.score.normalized_score), reverse=True)

        return matches

    def _check_ipid_prefilter(self, conn1: TcpConnection, conn2: TcpConnection) -> bool:
        """
        Fast IPID prefilter check with overlap threshold.

        This is a lightweight version of the full IPID check in scorer,
        used for early filtering to avoid expensive scoring operations.

        Uses global IPID matching (not direction-aware) to avoid false negatives
        from incorrect client/server role detection.

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            True if connections have sufficient IPID overlap, False otherwise
        """
        # Use global IPID sets (all IPIDs from both directions)
        # This matches the refactored _check_ipid() in scorer.py
        intersection = conn1.ipid_set & conn2.ipid_set

        # Quick check: at least MIN_IPID_OVERLAP overlapping IPIDs
        # Full overlap ratio check will be done in scorer if this passes
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
