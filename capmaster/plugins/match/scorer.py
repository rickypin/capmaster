"""Connection matching scoring algorithm."""

from dataclasses import dataclass

from capmaster.plugins.match.connection import TcpConnection


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

    def is_valid_match(self, threshold: float = 0.60) -> bool:
        """
        Check if this is a valid match.

        Args:
            threshold: Minimum normalized score required (default: 0.60)

        Returns:
            True if score meets threshold and IPID requirement is met
        """
        return self.ipid_match and self.normalized_score >= threshold


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
        # Check 3-tuple requirement (必要条件, direction-independent)
        # Only requires TCP port pair to match, IP addresses can differ (for NAT scenarios)
        if not self._check_3tuple(conn1, conn2):
            return MatchScore(
                normalized_score=0.0,
                raw_score=0.0,
                available_weight=0.0,
                ipid_match=False,
                evidence="no-3tuple",
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
        evidence_parts.append("ipid")

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

    def _check_ipid(self, conn1: TcpConnection, conn2: TcpConnection) -> bool:
        """
        Check if IPID requirement is met (必要条件).

        Uses flexible IPID matching: two connections match if they share
        at least one common IPID value across all their packets.

        This allows matching streams where:
        - One long stream contains multiple shorter streams' IPIDs
        - Streams have the same 5-tuple but different time ranges

        Based on network topology analysis:
        - Transparent network: IPID unchanged
        - NAT translation: IPID unchanged

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            True if connections share at least one IPID, False otherwise

        Example:
            conn1.ipid_set = {61507, 9053}
            conn2.ipid_set = {61507, 14265}
            → Match ✅ (share IPID 61507)

            conn1.ipid_set = {61507}
            conn2.ipid_set = {14265}
            → No match ❌ (no common IPID)
        """
        # Check if there's any intersection between IPID sets
        return bool(conn1.ipid_set & conn2.ipid_set)

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
        # NOTE: ISN can be 0 (relative sequence number), so we check syn_options
        # to determine if SYN packet was present. If no SYN packet, ISN is not available.
        if not conn1.syn_options or not conn2.syn_options:
            return 0.0, 0.0

        # Exact match
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
        # NOTE: ISN can be 0 (relative sequence number), so we check syn_options
        # to determine if SYN packet was present. If no SYN packet, ISN is not available.
        if not conn1.syn_options or not conn2.syn_options:
            return 0.0, 0.0

        # Exact match
        if conn1.server_isn == conn2.server_isn:
            return self.WEIGHT_ISN_SERVER, self.WEIGHT_ISN_SERVER

        return 0.0, self.WEIGHT_ISN_SERVER

    def _score_timestamp(self, conn1: TcpConnection, conn2: TcpConnection) -> tuple[float, float]:
        """
        Score TCP timestamp similarity.

        Matching original script logic:
        - If either connection has timestamp, count as available
        - Match if TSval OR TSecr matches

        Args:
            conn1: First connection
            conn2: Second connection

        Returns:
            Tuple of (score, available_weight)
        """
        # Check if either connection has timestamp (matching original script)
        has_ts1 = bool(conn1.tcp_timestamp_tsval or conn1.tcp_timestamp_tsecr)
        has_ts2 = bool(conn2.tcp_timestamp_tsval or conn2.tcp_timestamp_tsecr)

        # If neither has timestamp, don't count
        if not has_ts1 and not has_ts2:
            return 0.0, 0.0

        # If at least one has timestamp, count as available (matching original script)
        # Match if either TSval or TSecr matches
        tsval_match = (
            conn1.tcp_timestamp_tsval
            and conn2.tcp_timestamp_tsval
            and conn1.tcp_timestamp_tsval == conn2.tcp_timestamp_tsval
        )
        tsecr_match = (
            conn1.tcp_timestamp_tsecr
            and conn2.tcp_timestamp_tsecr
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
