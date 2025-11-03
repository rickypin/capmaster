"""Connection matching logic with bucketing strategies."""

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
            f"{self.conn1.client_ip}:{self.conn1.server_port} <-> "
            f"{self.conn2.client_ip}:{self.conn2.server_port})"
        )


class ConnectionMatcher:
    """
    Match connections between two PCAP files.

    Uses a greedy one-to-one matching algorithm with bucketing
    to improve performance.

    Implements weighted normalization scoring matching the original script.
    """

    def __init__(
        self,
        bucket_strategy: BucketStrategy = BucketStrategy.AUTO,
        score_threshold: float = 0.60,
    ):
        """
        Initialize the matcher.

        Args:
            bucket_strategy: Strategy for bucketing connections
            score_threshold: Minimum normalized score for a valid match (default: 0.60)
                           Matching original script's default threshold
        """
        self.bucket_strategy = bucket_strategy
        self.score_threshold = score_threshold
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
        # This mimics the original script's logic:
        # - If servers are the same -> use SERVER bucketing (high precision)
        # - If servers differ but have common ports -> use PORT bucketing (NAT/LB friendly)
        # - Otherwise -> use SERVER bucketing (may not match)

        # Count unique servers and ports
        servers1 = {c.server_ip for c in connections1}
        servers2 = {c.server_ip for c in connections2}
        ports1 = {c.server_port for c in connections1}
        ports2 = {c.server_port for c in connections2}

        # Check for common servers and ports
        common_servers = servers1 & servers2
        common_ports = ports1 & ports2

        # If servers are identical, use SERVER bucketing
        if common_servers and len(common_servers) == len(servers1) == len(servers2):
            return BucketStrategy.SERVER

        # If servers differ but have common ports, use PORT bucketing
        if not common_servers and common_ports:
            return BucketStrategy.PORT

        # If have some common servers, use SERVER bucketing
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

        Args:
            connections: List of connections
            strategy: Bucketing strategy

        Returns:
            Dictionary mapping bucket keys to connection lists
        """
        buckets: dict[str, list[TcpConnection]] = defaultdict(list)

        for conn in connections:
            if strategy == BucketStrategy.SERVER:
                key = conn.server_ip
            elif strategy == BucketStrategy.PORT:
                key = str(conn.server_port)
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
        Match connections within a bucket using greedy algorithm.

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
                score = self.scorer.score(conn1, conn2)

                if score.is_valid_match(self.score_threshold):
                    # Use normalized_score for sorting
                    scored_pairs.append((score.normalized_score, i, j, conn1, conn2, score))

        # Sort by normalized score (descending)
        scored_pairs.sort(key=lambda x: x[0], reverse=True)

        # Greedy matching: take highest scoring pairs first
        for _, i, j, conn1, conn2, score in scored_pairs:
            if i not in used1 and j not in used2:
                matches.append(ConnectionMatch(conn1, conn2, score))
                used1.add(i)
                used2.add(j)

        return matches

    def get_match_stats(
        self,
        connections1: Sequence[TcpConnection],
        connections2: Sequence[TcpConnection],
        matches: Sequence[ConnectionMatch],
    ) -> dict:
        """
        Get statistics about the matching operation.

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

        return {
            "total_connections_1": len(connections1),
            "total_connections_2": len(connections2),
            "matched_pairs": len(matches),
            "unmatched_1": len(connections1) - len(matched1),
            "unmatched_2": len(connections2) - len(matched2),
            "match_rate_1": len(matched1) / len(connections1) if connections1 else 0,
            "match_rate_2": len(matched2) / len(connections2) if connections2 else 0,
            "average_score": avg_score,
        }
