"""Connection matching scoring algorithm."""

from __future__ import annotations

from dataclasses import dataclass

from capmaster.core.connection.models import TcpConnection


@dataclass
class MatchScore:
    """
    Score for a connection match.

    Uses weighted normalization scoring (0.0-1.0) matching the original script.

    Features (8 total):
    1. SYN options (25%)
    2. Client ISN (12%)
    3. Server ISN (6%)
    4. TCP timestamp (10%)
    5. Client payload (15%)
    6. Server payload (8%)
    7. Length signature (8%)
    8. IPID (16%)
    """

    normalized_score: float
    """Normalized match score (0.0-1.0)"""

    raw_score: float
    """Raw score (sum of matched feature weights)"""

    available_weight: float
    """Total weight of available features"""

    ipid_match: bool
    """Whether IPID requirement is met (必要条件)"""

    evidence: str
    """Evidence string showing which features matched"""

    # Individual feature scores (for debugging)
    syn_options_score: float = 0.0
    isn_client_score: float = 0.0
    isn_server_score: float = 0.0
    timestamp_score: float = 0.0
    payload_client_score: float = 0.0
    payload_server_score: float = 0.0
    length_sig_score: float = 0.0
    ipid_score: float = 0.0

    # Strong acceptance flag: when True, bypass normalized threshold if IPID evidence is overwhelming
    force_accept: bool = False

    # Microflow acceptance flag: when True, this match is accepted by microflow rule without IPID>=2
    microflow_accept: bool = False

    def is_valid_match(self, threshold: float = 0.60) -> bool:
        """
        Check if this is a valid match.

        Args:
            threshold: Minimum normalized score required (default: 0.60)

        Returns:
            True if ANY of the following holds:
            - microflow_accept is True (auto-accept for microflow with strong handshake evidence), or
            - IPID requirement is met and (normalized score meets threshold or force_accept is True)
        """
        if self.microflow_accept:
            return True
        return self.ipid_match and (self.normalized_score >= threshold or self.force_accept)


class ConnectionScorer:
    """
    Score connection matches based on feature similarity.

    Implements weighted normalization scoring matching the original script:
    - IPID: 必要条件 (required, exact match)
    - 8 features with weights totaling 1.00
    - Normalized score = raw_score / available_weight

    Weight configuration (matching original script):
    - SYN options: 0.25 (25%)
    - Client ISN: 0.12 (12%)
    - Server ISN: 0.06 (6%)
    - TCP timestamp: 0.10 (10%)
    - Client payload: 0.15 (15%)
    - Server payload: 0.08 (8%)
    - Length signature: 0.08 (8%)
    - IPID: 0.16 (16%)
    """

    # Scoring weights (matching original script exactly)
    WEIGHT_SYN = 0.25
    WEIGHT_ISN_CLIENT = 0.12
    WEIGHT_ISN_SERVER = 0.06
    WEIGHT_TIMESTAMP = 0.10
    WEIGHT_PAYLOAD_CLIENT = 0.15
    WEIGHT_PAYLOAD_SERVER = 0.08
    WEIGHT_LENGTH_SIG = 0.08
    WEIGHT_IPID = 0.16

    # Length signature similarity threshold
    LENGTH_SIG_THRESHOLD = 0.6

    # IPID matching thresholds (必要条件)
    # We compute overlap on non-zero, de-duplicated IPID sets (direction-independent)
    MIN_IPID_OVERLAP = 2  # Absolute minimum number of overlapping IPIDs required
    MIN_IPID_OVERLAP_RATIO = 0.5  # Minimum overlap ratio (intersection / min(set1, set2))
    # Require at least half of the smaller IPID set to overlap

    # Strong IPID acceptance thresholds (充分条件)
    # When IPID evidence is overwhelming, we can accept even if normalized score is low.
    # We enhance robustness by requiring Jaccard similarity in addition to count/coverage.
    STRONG_IPID_MIN_OVERLAP = 10
    STRONG_IPID_MIN_RATIO = 0.8
    STRONG_IPID_MIN_JACCARD = 0.25  # Additional robustness: penalize subset-only overlaps
    # Optional numeric-range density gate (disabled by default: 0.0 means skip)
    STRONG_IPID_MIN_DENSITY = 0.0

    # Microflow (short-flow) matching configuration
    MICROFLOW_TRIGGER_MAX_PACKETS = 3
    MICROFLOW_TRIGGER_MAX_DURATION = 2.0  # seconds
    MICROFLOW_THRESHOLD = 0.80  # normalized microflow score threshold

    # Microflow feature weights (sum to 1.0)
    MICRO_W_SYN = 0.30
    MICRO_W_ISN = 0.30
    MICRO_W_TS = 0.20
    MICRO_W_TTL = 0.10
    MICRO_W_LEN = 0.10

    def __init__(self) -> None:
        """Initialize the scorer."""
        pass

    def score(
        self, conn1: TcpConnection, conn2: TcpConnection, use_payload: bool = True
    ) -> MatchScore:
        """
        Score the match between two connections.

        Args:
            conn1: First connection
            conn2: Second connection
            use_payload: Whether to use payload features (auto-detected based on header_only)

        Returns:
            MatchScore object with detailed scoring
        """
        # Check server port requirement (必要条件, direction-independent)
        # Only requires at least one common port (the server port) to match
        # This is more relaxed than 3-tuple matching, allowing client port to differ
        # Useful for scenarios with load balancers (F5, HAProxy) or NAT that perform SNAT
        if not self._check_server_port(conn1, conn2):
            return MatchScore(
                normalized_score=0.0,
                raw_score=0.0,
                available_weight=0.0,
                ipid_match=False,
                evidence="no-server-port",
            )

        # Check IPID requirement (必要条件)
        ipid_match = self._check_ipid(conn1, conn2)

        # If IPID doesn't match, return 0 score immediately
        if not ipid_match:
            return MatchScore(
                normalized_score=0.0,
                raw_score=0.0,
                available_weight=0.0,
                ipid_match=False,
                evidence="no-ipid",
            )

        # Determine if IPID overlap alone is a sufficient condition (强匹配)
        # When the IPID overlap is overwhelming, other features are not necessary.
        # Use non-zero, de-duplicated, direction-independent IPID sets.
        s1 = {x for x in conn1.ipid_set if x != 0}
        s2 = {x for x in conn2.ipid_set if x != 0}
        inter = s1 & s2
        union = s1 | s2
        overlap_count = len(inter)
        min_set_size = min(len(s1), len(s2)) if s1 and s2 else 0
        overlap_ratio = (overlap_count / min_set_size) if min_set_size > 0 else 0.0
        jaccard = (len(inter) / len(union)) if union else 0.0
        # Optional numeric-range density (disabled by default)
        if s1 and s2:
            r_lo = max(min(s1), min(s2))
            r_hi = min(max(s1), max(s2))
            if r_hi >= r_lo:
                range_size = (r_hi - r_lo + 1)
                density = (overlap_count / range_size) if range_size > 0 else 0.0
            else:
                density = 0.0
        else:
            density = 0.0
        force_accept = (
            overlap_count >= self.STRONG_IPID_MIN_OVERLAP
            and overlap_ratio >= self.STRONG_IPID_MIN_RATIO
            and jaccard >= self.STRONG_IPID_MIN_JACCARD
            and (self.STRONG_IPID_MIN_DENSITY <= 0.0 or density >= self.STRONG_IPID_MIN_DENSITY)
        )

        # Determine if we should use payload features
        # Don't use payload if either connection is header-only
        use_payload = use_payload and not (conn1.is_header_only or conn2.is_header_only)

        # Score individual features
        raw_score = 0.0
        available_weight = 0.0
        evidence_parts = []

        # 1. SYN options
        syn_score, syn_avail = self._score_syn_options(conn1, conn2)
        raw_score += syn_score
        available_weight += syn_avail
        if syn_score > 0:
            evidence_parts.append("synopt")

        # 2. Client ISN
        isn_c_score, isn_c_avail = self._score_isn_client(conn1, conn2)
        raw_score += isn_c_score
        available_weight += isn_c_avail
        if isn_c_score > 0:
            evidence_parts.append("isnC")

        # 3. Server ISN
        isn_s_score, isn_s_avail = self._score_isn_server(conn1, conn2)
        raw_score += isn_s_score
        available_weight += isn_s_avail
        if isn_s_score > 0:
            evidence_parts.append("isnS")

        # 4. TCP timestamp
        ts_score, ts_avail = self._score_timestamp(conn1, conn2)
        raw_score += ts_score
        available_weight += ts_avail
        if ts_score > 0:
            evidence_parts.append("ts")

        # 5. Payload features (if enabled)
        if use_payload:
            # Client payload
            payload_c_score, payload_c_avail = self._score_payload_client(conn1, conn2)
            raw_score += payload_c_score
            available_weight += payload_c_avail
            if payload_c_score > 0:
                evidence_parts.append("dataC")

            # Server payload
            payload_s_score, payload_s_avail = self._score_payload_server(conn1, conn2)
            raw_score += payload_s_score
            available_weight += payload_s_avail
            if payload_s_score > 0:
                evidence_parts.append("dataS")

        # 6. Length signature
        length_score, length_avail, length_sim = self._score_length_signature(conn1, conn2)
        raw_score += length_score
        available_weight += length_avail
        if length_score > 0:
            evidence_parts.append(f"shape({length_sim:.2f})")

        # 7. IPID (already matched, add weight)
        raw_score += self.WEIGHT_IPID
        available_weight += self.WEIGHT_IPID
        evidence_parts.append("ipid*" if force_accept else "ipid")

        # Calculate normalized score
        if available_weight > 0:
            normalized_score = raw_score / available_weight
        else:
            normalized_score = 0.0

        evidence = " ".join(evidence_parts)

        return MatchScore(
            normalized_score=normalized_score,
            raw_score=raw_score,
            available_weight=available_weight,
            ipid_match=ipid_match,
            evidence=evidence,
            force_accept=force_accept,
        )

    def _check_5tuple(self, conn1: TcpConnection, conn2: TcpConnection) -> bool:
        """
        Check if 5-tuple matches (direction-independent).

        Two connections match if they have the same normalized 5-tuple,
        regardless of which side is labeled as client/server.

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            True if normalized 5-tuples match, False otherwise

        Example:
            conn1: 8.42.96.45:35101 <-> 8.67.2.125:26302
            conn2: 8.67.2.125:26302 <-> 8.42.96.45:35101
            → Match ✅ (same connection, different direction)
        """
        return conn1.get_normalized_5tuple() == conn2.get_normalized_5tuple()

    def _check_3tuple(self, conn1: TcpConnection, conn2: TcpConnection) -> bool:
        """
        Check if 3-tuple (port pair) matches (direction-independent).

        Two connections match if they have the same TCP port pair,
        regardless of IP addresses or which side is labeled as client/server.
        This is useful for NAT scenarios where IP addresses change but ports remain the same.

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            True if normalized port pairs match, False otherwise

        Example:
            conn1: 10.0.0.1:8080 <-> 192.168.1.1:443
            conn2: 172.16.0.1:443 <-> 10.10.10.1:8080
            → Match ✅ (same port pair: 443, 8080)

            conn1: 10.0.0.1:8080 <-> 192.168.1.1:443
            conn2: 172.16.0.1:8080 <-> 10.10.10.1:9000
            → No match ❌ (different port pairs)
        """
        return conn1.get_normalized_3tuple() == conn2.get_normalized_3tuple()

    def _check_server_port(self, conn1: TcpConnection, conn2: TcpConnection) -> bool:
        """
        Check if server port matches (direction-independent).

        This is more relaxed than 3-tuple matching, allowing client port to differ.
        Two connections match if they share at least one common port (the server port).

        This is useful for scenarios with:
        - Load balancers (F5, HAProxy) that perform SNAT (Source NAT)
        - NAT devices that change client ports
        - Proxies that establish new connections with different client ports

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            True if at least one port matches (the server port), False otherwise

        Example:
            conn1: 10.0.0.1:8080 <-> 192.168.1.1:443
            conn2: 172.16.0.1:9000 <-> 10.10.10.1:443
            → Match ✅ (common port: 443)

            conn1: 10.0.0.1:8080 <-> 192.168.1.1:443
            conn2: 172.16.0.1:9000 <-> 10.10.10.1:8443
            → No match ❌ (no common port)
        """
        # Get all ports from both connections
        ports1 = {conn1.client_port, conn1.server_port}
        ports2 = {conn2.client_port, conn2.server_port}

        # Check if there's at least one common port (the server port)
        return bool(ports1 & ports2)

    def _check_ipid(self, conn1: TcpConnection, conn2: TcpConnection) -> bool:
        """
        Check if IPID requirement is met (必要条件).

        Uses global IPID matching without direction awareness:
        - Two connections match if they share sufficient common IPID values
        - Requires BOTH minimum overlap count (2) AND minimum overlap ratio (50%)
        - Overlap ratio = intersection / min(set1, set2)
        - This prevents false matches from random IPID collisions

        IPID collision analysis:
        - IPID is 16-bit (65536 possible values)
        - Random collision probability for 2 IPIDs: ~0.003%
        - Requiring 50% overlap ratio significantly reduces false positives
        - For short connections (2-4 IPIDs), still requires at least 2 overlaps

        Why global IPID matching is safe:
        - IPID is host-specific: each host maintains its own IPID sequence
        - Different hosts rarely share common IPIDs (collision probability ~0.003%)
        - High overlap ratio (>50%) indicates same connection, regardless of direction
        - Avoids false negatives from incorrect client/server role detection
        - Same connection at different capture points should have highly overlapping IPID sets

        Network topology:
        - Transparent network: IPID unchanged
        - NAT translation: IPID unchanged
        - IPID propagates through network without modification

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            True if connections share sufficient IPIDs, False otherwise

        Example:
            conn1.ipid_set = {0x549c, 0x54a8, 0x54a9, 0x554c, 0x554d}  # 5 IPIDs
            conn2.ipid_set = {0x549c, 0x549d}  # 2 IPIDs
            → No match ❌ (only 1 overlap, need min(5,2)*0.5 = 1 overlap, but also need absolute min 2)

            conn1.ipid_set = {0x549c, 0x54a8, 0x54a9}  # 3 IPIDs
            conn2.ipid_set = {0x549c, 0x54a8, 0x54aa}  # 3 IPIDs
            → Match ✅ (2 overlaps >= 2, ratio = 2/3 = 0.67 >= 0.5)

            conn1.ipid_set = {0xabf9, 0xac00, 0xaca2, 0xaca3}  # 4 IPIDs
            conn2.ipid_set = {0xabf9, 0xac00}  # 2 IPIDs
            → Match ✅ (2 overlaps >= 2, ratio = 2/2 = 1.0 >= 0.5)

            conn1.ipid_set = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6}  # 6 IPIDs
            conn2.ipid_set = {0x1, 0x2, 0x7, 0x8}  # 4 IPIDs
            → No match ❌ (2 overlaps >= 2, but ratio = 2/4 = 0.5, need > 0.5 for safety)
        """
        # Use global IPID sets (all IPIDs from both directions)
        # This is more robust than direction-aware matching because:
        # 1. It doesn't depend on correct client/server role detection
        # 2. Different hosts have independent IPID sequences (low collision probability)
        # 3. Same connection at different capture points will have high IPID overlap
        intersection = conn1.ipid_set & conn2.ipid_set

        return self._check_ipid_overlap(intersection, conn1.ipid_set, conn2.ipid_set)

    def _check_ipid_overlap(
        self, intersection: set[int], set1: set[int], set2: set[int]
    ) -> bool:
        """
        Check if IPID overlap is sufficient.

        We operate on non-zero, de-duplicated, direction-independent sets.
        Requires BOTH conditions to be met:
        1. Absolute minimum: at least MIN_IPID_OVERLAP (2) overlapping IPIDs
        2. Relative minimum: overlap ratio >= MIN_IPID_OVERLAP_RATIO (0.5)
           where overlap_ratio = overlap_count / min(len(set1), len(set2))

        This adaptive threshold works well for connections of different lengths.
        """
        # Filter out zero IPIDs (defensive guard against builder fallback)
        s1 = {x for x in set1 if x != 0}
        s2 = {x for x in set2 if x != 0}
        if not s1 or not s2:
            return False

        # Recompute intersection on filtered sets
        inter = s1 & s2
        if not inter:
            return False

        overlap_count = len(inter)
        min_set_size = min(len(s1), len(s2))

        # Condition 1: Require absolute minimum overlap count
        if overlap_count < self.MIN_IPID_OVERLAP:
            return False

        # Condition 2: Require minimum overlap ratio (to avoid random collisions)
        overlap_ratio = overlap_count / min_set_size
        if overlap_ratio < self.MIN_IPID_OVERLAP_RATIO:
            return False

        return True

    def _check_time_overlap(self, conn1: TcpConnection, conn2: TcpConnection) -> bool:
        """
        Check if two connections have time overlap.

        Time overlap exists if the time ranges [first, last] of the two connections intersect.
        This is important for matching streams with the same 5-tuple but different time ranges.

        Time overlap formula:
        - No overlap if: conn1 ends before conn2 starts OR conn2 ends before conn1 starts
        - Overlap exists if: NOT (no overlap)

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            True if time ranges overlap, False otherwise

        Example:
            conn1: [0, 100]
            conn2: [50, 150]
            → Overlap: [50, 100] ✅

            conn1: [0, 100]
            conn2: [200, 300]
            → No overlap ❌
        """
        # Check if ranges overlap
        # No overlap if: conn1 ends before conn2 starts OR conn2 ends before conn1 starts
        no_overlap = (
            conn1.last_packet_time < conn2.first_packet_time
            or conn2.last_packet_time < conn1.first_packet_time
        )

        return not no_overlap

    def _score_syn_options(self, conn1: TcpConnection, conn2: TcpConnection) -> tuple[float, float]:
        """
        Score SYN options similarity.

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            Tuple of (score, available_weight)
        """
        if not conn1.syn_options or not conn2.syn_options:
            return 0.0, 0.0

        if conn1.syn_options == conn2.syn_options:
            return self.WEIGHT_SYN, self.WEIGHT_SYN

        return 0.0, self.WEIGHT_SYN

    def _score_isn_client(self, conn1: TcpConnection, conn2: TcpConnection) -> tuple[float, float]:
        """
        Score client ISN similarity.

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            Tuple of (score, available_weight)
        """
        # ISN is only available if SYN packet was captured
        # We use syn_options as a proxy to check if SYN packet exists
        # (ISN=0 is valid when no SYN packet, not when using absolute sequence numbers)
        if not conn1.syn_options or not conn2.syn_options:
            return 0.0, 0.0

        # Exact match (32-bit ISN should match exactly for same connection)
        if conn1.client_isn == conn2.client_isn:
            return self.WEIGHT_ISN_CLIENT, self.WEIGHT_ISN_CLIENT

        return 0.0, self.WEIGHT_ISN_CLIENT

    def _score_isn_server(self, conn1: TcpConnection, conn2: TcpConnection) -> tuple[float, float]:
        """
        Score server ISN similarity.

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            Tuple of (score, available_weight)
        """
        # Server ISN is only available if SYN-ACK packet was captured
        # We use syn_options as a proxy to check if handshake was captured
        # (ISN=0 is valid when no SYN-ACK packet, not when using absolute sequence numbers)
        if not conn1.syn_options or not conn2.syn_options:
            return 0.0, 0.0

        # Exact match (32-bit ISN should match exactly for same connection)
        if conn1.server_isn == conn2.server_isn:
            return self.WEIGHT_ISN_SERVER, self.WEIGHT_ISN_SERVER

        return 0.0, self.WEIGHT_ISN_SERVER

    def _score_timestamp(self, conn1: TcpConnection, conn2: TcpConnection) -> tuple[float, float]:
        """
        Score TCP timestamp similarity.

        Improved logic to avoid false positives:
        - If either connection has timestamp, count as available
        - Match if TSval OR TSecr matches
        - Exclude TSecr=0 matches (SYN packets always have TSecr=0, causing false positives)

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            Tuple of (score, available_weight)
        """
        # Check if either connection has timestamp
        has_ts1 = bool(conn1.tcp_timestamp_tsval or conn1.tcp_timestamp_tsecr)
        has_ts2 = bool(conn2.tcp_timestamp_tsval or conn2.tcp_timestamp_tsecr)

        # If neither has timestamp, don't count
        if not has_ts1 and not has_ts2:
            return 0.0, 0.0

        # If at least one has timestamp, count as available
        # Match if either TSval or TSecr matches
        tsval_match = (
            conn1.tcp_timestamp_tsval
            and conn2.tcp_timestamp_tsval
            and conn1.tcp_timestamp_tsval == conn2.tcp_timestamp_tsval
        )
        # Exclude TSecr=0 to avoid false positives from SYN packets
        # (all SYN packets have TSecr=0 since they haven't received a timestamp yet)
        tsecr_match = (
            conn1.tcp_timestamp_tsecr
            and conn2.tcp_timestamp_tsecr
            and conn1.tcp_timestamp_tsecr != "0"  # Exclude TSecr=0
            and conn1.tcp_timestamp_tsecr == conn2.tcp_timestamp_tsecr
        )

        if tsval_match or tsecr_match:
            return self.WEIGHT_TIMESTAMP, self.WEIGHT_TIMESTAMP

        return 0.0, self.WEIGHT_TIMESTAMP

    def _score_payload_client(
        self, conn1: TcpConnection, conn2: TcpConnection
    ) -> tuple[float, float]:
        """
        Score client payload hash similarity.

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            Tuple of (score, available_weight)
        """
        if not conn1.client_payload_md5 or not conn2.client_payload_md5:
            return 0.0, 0.0

        if conn1.client_payload_md5 == conn2.client_payload_md5:
            return self.WEIGHT_PAYLOAD_CLIENT, self.WEIGHT_PAYLOAD_CLIENT

        return 0.0, self.WEIGHT_PAYLOAD_CLIENT

    def _score_payload_server(
        self, conn1: TcpConnection, conn2: TcpConnection
    ) -> tuple[float, float]:
        """
        Score server payload hash similarity.

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            Tuple of (score, available_weight)
        """
        if not conn1.server_payload_md5 or not conn2.server_payload_md5:
            return 0.0, 0.0

        if conn1.server_payload_md5 == conn2.server_payload_md5:
            return self.WEIGHT_PAYLOAD_SERVER, self.WEIGHT_PAYLOAD_SERVER

        return 0.0, self.WEIGHT_PAYLOAD_SERVER

    def _score_length_signature(
        self, conn1: TcpConnection, conn2: TcpConnection
    ) -> tuple[float, float, float]:
        """
        Score length signature similarity using Jaccard similarity.

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            Tuple of (score, available_weight, similarity)
        """
        if not conn1.length_signature or not conn2.length_signature:
            return 0.0, 0.0, 0.0

        # Calculate Jaccard similarity
        similarity = self._calculate_jaccard_similarity(
            conn1.length_signature, conn2.length_signature
        )

        # Score if similarity >= threshold
        if similarity >= self.LENGTH_SIG_THRESHOLD:
            return self.WEIGHT_LENGTH_SIG, self.WEIGHT_LENGTH_SIG, similarity

        return 0.0, self.WEIGHT_LENGTH_SIG, similarity

    def _calculate_jaccard_similarity(self, sig1: str, sig2: str) -> float:
        """
        Calculate Jaccard similarity of length signatures.

        Jaccard similarity = |A ∩ B| / |A ∪ B|

        Args:
            sig1: Length signature 1 (e.g., "C:100 S:200 C:50")
            sig2: Length signature 2

        Returns:
            Jaccard similarity (0.0-1.0)
        """
        if not sig1 or not sig2:
            return 0.0

        # Split into tokens
        tokens1 = set(sig1.split())
        tokens2 = set(sig2.split())

        if not tokens1 or not tokens2:
            return 0.0

        # Calculate intersection and union
        intersection = len(tokens1 & tokens2)
        union = len(tokens1 | tokens2)

        if union == 0:
            return 0.0

        return intersection / union


    def _ttl_close(self, conn1: TcpConnection, conn2: TcpConnection, max_delta: int = 16) -> tuple[bool, bool]:
        """Return (can_evaluate, close) for TTL similarity.

        We consider TTL comparable if either client_ttl or server_ttl exists on both sides.
        Close if absolute difference <= max_delta.
        """
        can_eval = False
        close = False
        if conn1.client_ttl and conn2.client_ttl:
            can_eval = True
            if abs(conn1.client_ttl - conn2.client_ttl) <= max_delta:
                close = True
        if not close and conn1.server_ttl and conn2.server_ttl:
            can_eval = True
            if abs(conn1.server_ttl - conn2.server_ttl) <= max_delta:
                close = True
        return can_eval, close

    def _is_microflow(self, conn1: TcpConnection, conn2: TcpConnection) -> bool:
        """Check microflow trigger: very short by packets or duration."""
        pkt_cond = min(conn1.packet_count, conn2.packet_count) <= self.MICROFLOW_TRIGGER_MAX_PACKETS
        dur1 = max(0.0, conn1.last_packet_time - conn1.first_packet_time)
        dur2 = max(0.0, conn2.last_packet_time - conn2.first_packet_time)
        dur_cond = min(dur1, dur2) <= self.MICROFLOW_TRIGGER_MAX_DURATION
        return pkt_cond or dur_cond

    def score_microflow(self, conn1: TcpConnection, conn2: TcpConnection) -> MatchScore | None:
        """
        Microflow auto-accept path for 1-3 packet or sub-2s flows.

        Requirements (automatic, no human intervention):
        - Port intersects AND time ranges overlap
        - Microflow trigger (packets <= 3 or duration <= 2s)
        - At least 1 common IPID
        - Strong handshake evidence via weighted features (SYN options, client ISN, TS, TTL, length signature)
          reaching MICROFLOW_THRESHOLD

        Returns MatchScore with microflow_accept=True if accepted; otherwise None.
        """
        # Basic pre-checks
        if not self._check_server_port(conn1, conn2):
            return None
        if not self._check_time_overlap(conn1, conn2):
            return None
        if not self._is_microflow(conn1, conn2):
            return None

        # Require at least 1 overlapping IPID
        if len(conn1.ipid_set & conn2.ipid_set) < 1:
            return None

        score = 0.0
        avail = 0.0
        evidence_parts: list[str] = ["micro"]

        # SYN options
        if conn1.syn_options and conn2.syn_options:
            avail += self.MICRO_W_SYN
            if conn1.syn_options == conn2.syn_options:
                score += self.MICRO_W_SYN
                evidence_parts.append("synopt")

        # Client ISN (only meaningful if SYN exists)
        if conn1.syn_options and conn2.syn_options:
            avail += self.MICRO_W_ISN
            if conn1.client_isn == conn2.client_isn:
                score += self.MICRO_W_ISN
                evidence_parts.append("isnC")

        # TCP timestamp exact match (stricter than normal availability rule)
        # Exclude TSecr=0 to avoid false positives from SYN packets
        has_ts1 = bool(conn1.tcp_timestamp_tsval or conn1.tcp_timestamp_tsecr)
        has_ts2 = bool(conn2.tcp_timestamp_tsval or conn2.tcp_timestamp_tsecr)
        if has_ts1 and has_ts2:
            avail += self.MICRO_W_TS
            tsval_match = (
                conn1.tcp_timestamp_tsval
                and conn2.tcp_timestamp_tsval
                and conn1.tcp_timestamp_tsval == conn2.tcp_timestamp_tsval
            )
            # Exclude TSecr=0 to avoid false positives from SYN packets
            tsecr_match = (
                conn1.tcp_timestamp_tsecr
                and conn2.tcp_timestamp_tsecr
                and conn1.tcp_timestamp_tsecr != "0"  # Exclude TSecr=0
                and conn1.tcp_timestamp_tsecr == conn2.tcp_timestamp_tsecr
            )
            if tsval_match or tsecr_match:
                score += self.MICRO_W_TS
                evidence_parts.append("ts")

        # TTL closeness
        can_ttl, ttl_close = self._ttl_close(conn1, conn2)
        if can_ttl:
            avail += self.MICRO_W_TTL
            if ttl_close:
                score += self.MICRO_W_TTL
                evidence_parts.append("ttl")

        # Length signature similarity (if present)
        if conn1.length_signature and conn2.length_signature:
            avail += self.MICRO_W_LEN
            similarity = self._calculate_jaccard_similarity(conn1.length_signature, conn2.length_signature)
            if similarity >= self.LENGTH_SIG_THRESHOLD:
                score += self.MICRO_W_LEN
                evidence_parts.append(f"shape({similarity:.2f})")

        if avail <= 0.0:
            return None

        normalized = score / avail
        if normalized < self.MICROFLOW_THRESHOLD:
            return None

        # Build MatchScore (microflow accepted)
        evidence_parts.append("ipid(1)")
        return MatchScore(
            normalized_score=normalized,
            raw_score=score,
            available_weight=avail,
            ipid_match=False,
            evidence=" ".join(evidence_parts),
            microflow_accept=True,
        )

