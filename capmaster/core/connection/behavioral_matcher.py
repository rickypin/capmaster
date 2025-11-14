"""Behavior-only TCP connection matcher based on key behavioral features.

This matcher scores pairs using timing/size behavior only, without IPID or
payload/handshake feature requirements. It is intended for evaluation when
"behavioral" mode is explicitly enabled.

Behavioral features (all normalized to 0..1, weighted):
- Time range overlap ratio (configurable, default 35%)
- Duration similarity ratio (configurable, default 25%)
- Average inter-packet time (IAT) similarity (configurable, default 20%)
  * IAT approximates request-response RTT in interactive connections
- Total bytes similarity (configurable, default 20%)

Recommended configuration for two-hop scenarios with TLS:
- Time range overlap: 50% (primary constraint)
- IAT (request-response approximation): 50% (primary feature)
- Duration: 0% (unreliable in two-hop scenarios)
- Bytes: 0% (unreliable with TLS encryption/decryption)

Notes:
- Uses the same ConnectionMatch/MatchScore types for compatibility.
- Sets ipid_match=True in scores because IPID is not part of this strategy.
- Supports bucketing and match modes consistent with ConnectionMatcher.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from capmaster.core.connection.models import TcpConnection
from capmaster.core.connection.scorer import MatchScore
from capmaster.core.connection.matcher import BucketStrategy, MatchMode, ConnectionMatch


@dataclass
class _ScoredPair:
    force: int
    score: float
    i: int
    j: int
    c1: TcpConnection
    c2: TcpConnection
    ms: MatchScore


class BehavioralMatcher:
    def __init__(
        self,
        bucket_strategy: BucketStrategy = BucketStrategy.AUTO,
        score_threshold: float = 0.60,
        match_mode: MatchMode = MatchMode.ONE_TO_ONE,
        weight_overlap: float = 0.0,   # Unreliable in two-hop scenarios
        weight_duration: float = 0.4,  # Duration similarity (effective in most cases)
        weight_iat: float = 0.3,       # Inter-arrival time (approximates request-response RTT)
        weight_bytes: float = 0.3,     # Total bytes similarity
    ) -> None:
        self.bucket_strategy = bucket_strategy
        self.score_threshold = score_threshold
        self.match_mode = match_mode
        self.weight_overlap = weight_overlap
        self.weight_duration = weight_duration
        self.weight_iat = weight_iat
        self.weight_bytes = weight_bytes

    # --------- public API ---------
    def match(
        self,
        connections1: Sequence[TcpConnection],
        connections2: Sequence[TcpConnection],
    ) -> list[ConnectionMatch]:
        strategy = self._choose_strategy(connections1, connections2)
        buckets1 = self._create_buckets(connections1, strategy)
        buckets2 = self._create_buckets(connections2, strategy)

        matches: list[ConnectionMatch] = []
        seen_pairs: set[tuple[int, int]] = set()

        for key, b1 in buckets1.items():
            b2 = buckets2.get(key, [])
            if not b1 or not b2:
                continue
            bucket_matches = (
                self._match_bucket_one_to_one(b1, b2)
                if self.match_mode == MatchMode.ONE_TO_ONE
                else self._match_bucket_one_to_many(b1, b2)
            )
            # dedupe for PORT bucketing where a conn might appear multiple times
            for m in bucket_matches:
                pair_key = (m.conn1.stream_id, m.conn2.stream_id)
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                matches.append(m)

        return matches

    def get_match_stats(
        self,
        connections1: Sequence[TcpConnection],
        connections2: Sequence[TcpConnection],
        matches: Sequence[ConnectionMatch],
    ) -> dict:
        """Return stats with the same schema as ConnectionMatcher.get_match_stats."""
        matched1 = {m.conn1.stream_id for m in matches}
        matched2 = {m.conn2.stream_id for m in matches}
        avg_score = sum(m.score.normalized_score for m in matches) / len(matches) if matches else 0.0
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
        if self.match_mode == MatchMode.ONE_TO_MANY:
            from collections import Counter
            c1c = Counter(m.conn1.stream_id for m in matches)
            c2c = Counter(m.conn2.stream_id for m in matches)
            stats.update(
                max_matches_per_conn1=max(c1c.values()) if c1c else 0,
                max_matches_per_conn2=max(c2c.values()) if c2c else 0,
                avg_matches_per_conn1=(sum(c1c.values()) / len(c1c)) if c1c else 0,
                avg_matches_per_conn2=(sum(c2c.values()) / len(c2c)) if c2c else 0,
            )
        return stats

    # --------- internals: bucketing ---------
    def _choose_strategy(
        self,
        connections1: Sequence[TcpConnection],
        connections2: Sequence[TcpConnection],
    ) -> BucketStrategy:
        if self.bucket_strategy != BucketStrategy.AUTO:
            return self.bucket_strategy
        # Reuse simple heuristic from ConnectionMatcher: prefer PORT in NAT-ish scenarios
        clients1 = {c.client_ip for c in connections1}
        clients2 = {c.client_ip for c in connections2}
        servers1 = {c.server_ip for c in connections1}
        servers2 = {c.server_ip for c in connections2}
        ports1 = {c.server_port for c in connections1}
        ports2 = {c.server_port for c in connections2}
        common_clients = clients1 & clients2
        common_servers = servers1 & servers2
        common_ports = ports1 & ports2
        snat_likely = (not common_clients) and bool(common_servers)
        dnat_likely = (not common_servers) and bool(common_clients)
        nat_ambiguous = (not common_clients) and (not common_servers) and bool(common_ports)
        if snat_likely or dnat_likely or nat_ambiguous:
            return BucketStrategy.PORT
        if common_servers and len(common_servers) == len(servers1) == len(servers2):
            return BucketStrategy.SERVER
        if not common_servers and common_ports:
            return BucketStrategy.PORT
        if common_servers:
            return BucketStrategy.SERVER
        return BucketStrategy.PORT

    def _create_buckets(
        self,
        connections: Sequence[TcpConnection],
        strategy: BucketStrategy,
    ) -> dict[str, list[TcpConnection]]:
        buckets: dict[str, list[TcpConnection]] = defaultdict(list)
        for conn in connections:
            if strategy == BucketStrategy.SERVER:
                ip1, _p1, ip2, _p2 = conn.get_normalized_5tuple()
                key = f"{ip1}:{ip2}"
                buckets[key].append(conn)
            elif strategy == BucketStrategy.PORT:
                key = str(conn.server_port)
                buckets[key].append(conn)
            else:
                buckets["all"].append(conn)
        return buckets

    # --------- internals: matching ---------
    def _match_bucket_one_to_one(
        self,
        bucket1: list[TcpConnection],
        bucket2: list[TcpConnection],
    ) -> list[ConnectionMatch]:
        scored: list[_ScoredPair] = []
        for i, c1 in enumerate(bucket1):
            for j, c2 in enumerate(bucket2):
                ms = self._behavior_score(c1, c2)
                if ms.normalized_score >= self.score_threshold:
                    scored.append(_ScoredPair(0, ms.normalized_score, i, j, c1, c2, ms))
        scored.sort(key=lambda s: (s.score, -s.c1.stream_id, -s.c2.stream_id), reverse=True)
        used1: set[int] = set()
        used2: set[int] = set()
        matches: list[ConnectionMatch] = []
        for sp in scored:
            if sp.i in used1 or sp.j in used2:
                continue
            matches.append(ConnectionMatch(sp.c1, sp.c2, sp.ms))
            used1.add(sp.i)
            used2.add(sp.j)
        return matches

    def _match_bucket_one_to_many(
        self,
        bucket1: list[TcpConnection],
        bucket2: list[TcpConnection],
    ) -> list[ConnectionMatch]:
        matches: list[ConnectionMatch] = []
        for c1 in bucket1:
            for c2 in bucket2:
                ms = self._behavior_score(c1, c2)
                if ms.normalized_score >= self.score_threshold:
                    matches.append(ConnectionMatch(c1, c2, ms))
        matches.sort(key=lambda m: (m.score.normalized_score, -m.conn1.stream_id, -m.conn2.stream_id), reverse=True)
        return matches

    # --------- internals: scoring ---------
    def _behavior_score(self, c1: TcpConnection, c2: TcpConnection) -> MatchScore:
        # durations
        dur1 = max(0.0, c1.last_packet_time - c1.first_packet_time)
        dur2 = max(0.0, c2.last_packet_time - c2.first_packet_time)
        dur_sim = self._ratio_similarity(dur1, dur2)

        # overlap ratio of time ranges
        start = max(c1.first_packet_time, c2.first_packet_time)
        end = min(c1.last_packet_time, c2.last_packet_time)
        union_start = min(c1.first_packet_time, c2.first_packet_time)
        union_end = max(c1.last_packet_time, c2.last_packet_time)
        inter = max(0.0, end - start)
        union = max(0.0, union_end - union_start)
        overlap = 1.0 if union <= 0 else (inter / union)

        # average inter-arrival time (IAT)
        iat1 = (dur1 / max(c1.packet_count - 1, 1)) if dur1 > 0 else 0.0
        iat2 = (dur2 / max(c2.packet_count - 1, 1)) if dur2 > 0 else 0.0
        iat_sim = self._ratio_similarity(iat1, iat2)

        # total bytes similarity (proxy for sequence span)
        bytes_sim = self._ratio_similarity(float(c1.total_bytes), float(c2.total_bytes))

        # Use configured weights
        raw = (
            self.weight_overlap * overlap
            + self.weight_duration * dur_sim
            + self.weight_iat * iat_sim
            + self.weight_bytes * bytes_sim
        )
        avail = self.weight_overlap + self.weight_duration + self.weight_iat + self.weight_bytes
        norm = raw / avail if avail > 0 else 0.0

        evidence = (
            f"BEHAV(overlap={overlap:.2f} dur={dur_sim:.2f} iat={iat_sim:.2f} bytes={bytes_sim:.2f})"
        )

        return MatchScore(
            normalized_score=norm,
            raw_score=raw,
            available_weight=avail,
            ipid_match=True,  # Not used in this strategy
            evidence=evidence,
            force_accept=False,
            microflow_accept=False,
        )

    @staticmethod
    def _ratio_similarity(a: float, b: float) -> float:
        if a <= 0 and b <= 0:
            return 1.0
        if a <= 0 or b <= 0:
            return 0.0
        lo, hi = (a, b) if a <= b else (b, a)
        return lo / hi

