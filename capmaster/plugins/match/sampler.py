"""Connection sampling strategies for large datasets."""

from collections.abc import Sequence

from capmaster.plugins.match.connection import TcpConnection


class ConnectionSampler:
    """
    Sample connections for matching when dataset is too large.

    This class implements time-based stratified sampling to reduce the
    number of connections while preserving important connections
    (header-only, special ports, etc.).
    """

    # Special ports that should always be preserved
    SPECIAL_PORTS = {
        20,
        21,  # FTP
        22,  # SSH
        23,  # Telnet
        25,  # SMTP
        53,  # DNS
        80,
        443,  # HTTP/HTTPS
        110,
        143,  # POP3/IMAP
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        27017,  # MongoDB
    }

    def __init__(self, threshold: int = 1000, sample_rate: float = 0.5):
        """
        Initialize the sampler.

        Args:
            threshold: Number of connections above which sampling is triggered
            sample_rate: Fraction of connections to keep (0.0 to 1.0)
        """
        self.threshold = threshold
        self.sample_rate = sample_rate

    def should_sample(self, connections: Sequence[TcpConnection]) -> bool:
        """
        Determine if sampling should be applied.

        Args:
            connections: List of connections

        Returns:
            True if sampling should be applied
        """
        return len(connections) > self.threshold

    def sample(self, connections: Sequence[TcpConnection]) -> list[TcpConnection]:
        """
        Sample connections using time-based stratified sampling.

        Args:
            connections: List of connections to sample

        Returns:
            Sampled list of connections
        """
        if not self.should_sample(connections):
            return list(connections)

        # Separate protected and regular connections
        protected = []
        regular = []

        for conn in connections:
            if self._is_protected(conn):
                protected.append(conn)
            else:
                regular.append(conn)

        # Sort regular connections by timestamp
        regular.sort(key=lambda c: c.syn_timestamp)

        # Apply time-based stratified sampling
        sampled_regular = self._stratified_sample(regular)

        # Combine protected and sampled connections
        result = protected + sampled_regular

        return result

    def _is_protected(self, connection: TcpConnection) -> bool:
        """
        Check if a connection should be protected from sampling.

        Args:
            connection: Connection to check

        Returns:
            True if connection should be protected
        """
        # Protect header-only connections
        if connection.is_header_only:
            return True

        # Protect connections on special ports
        if connection.server_port in self.SPECIAL_PORTS:
            return True

        return False

    def _stratified_sample(self, connections: list[TcpConnection]) -> list[TcpConnection]:
        """
        Apply time-based stratified sampling.

        Divides the time range into strata and samples from each stratum.

        Args:
            connections: Sorted list of connections (by timestamp)

        Returns:
            Sampled list of connections
        """
        if not connections:
            return []

        # Calculate number of connections to keep
        target_count = int(len(connections) * self.sample_rate)
        if target_count == 0:
            target_count = 1

        # Divide into time strata
        num_strata = min(10, len(connections))  # Use up to 10 strata
        stratum_size = len(connections) // num_strata

        sampled: list[TcpConnection] = []

        for i in range(num_strata):
            start_idx = i * stratum_size
            end_idx = start_idx + stratum_size if i < num_strata - 1 else len(connections)

            stratum = connections[start_idx:end_idx]

            # Sample from this stratum
            stratum_target = max(1, len(stratum) * target_count // len(connections))
            step = max(1, len(stratum) // stratum_target)

            for j in range(0, len(stratum), step):
                if len(sampled) < target_count:
                    sampled.append(stratum[j])

        return sampled

    def get_sampling_stats(
        self, original: Sequence[TcpConnection], sampled: Sequence[TcpConnection]
    ) -> dict:
        """
        Get statistics about the sampling operation.

        Args:
            original: Original list of connections
            sampled: Sampled list of connections

        Returns:
            Dictionary with sampling statistics
        """
        protected_count = sum(1 for c in sampled if self._is_protected(c))

        return {
            "original_count": len(original),
            "sampled_count": len(sampled),
            "protected_count": protected_count,
            "regular_count": len(sampled) - protected_count,
            "reduction_rate": 1.0 - (len(sampled) / len(original)) if original else 0.0,
        }
