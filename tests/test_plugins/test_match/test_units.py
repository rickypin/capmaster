"""Unit tests for Match plugin core modules."""

from __future__ import annotations

from pathlib import Path

import pytest

from capmaster.core.connection.extractor import TcpFieldExtractor
from capmaster.core.connection.matcher import BucketStrategy, ConnectionMatcher
from capmaster.core.connection.models import TcpConnection, TcpPacket
from capmaster.core.connection.scorer import ConnectionScorer, MatchScore
from capmaster.plugins.match.plugin import MatchPlugin
from capmaster.plugins.match.sampler import ConnectionSampler


def create_test_connection(**kwargs) -> TcpConnection:
    """
    Helper function to create a TcpConnection with default values.

    This simplifies test code by providing sensible defaults for all required fields.
    """
    defaults = {
        "stream_id": 0,
        "protocol": 6,  # TCP
        "client_ip": "192.168.1.1",
        "client_port": 12345,
        "server_ip": "10.0.0.1",
        "server_port": 80,
        "syn_timestamp": 1234567890.0,
        "syn_options": "",
        "client_isn": 0,
        "server_isn": 0,
        "tcp_timestamp_tsval": "",
        "tcp_timestamp_tsecr": "",
        "client_payload_md5": "",
        "server_payload_md5": "",
        "length_signature": "",
        "is_header_only": False,
        "ipid_first": 0,
        "ipid_set": set(),
        "client_ipid_set": set(),
        "server_ipid_set": set(),
        "first_packet_time": 1234567890.0,
        "last_packet_time": 1234567890.0,
        "packet_count": 1,
    }
    defaults.update(kwargs)
    return TcpConnection(**defaults)


@pytest.mark.unit
class TestTcpConnection:
    """Test TcpConnection dataclass."""

    def test_create_connection(self):
        """Test creating a TcpConnection instance."""
        conn = TcpConnection(
            stream_id=1,
            protocol=6,  # TCP
            client_ip="192.168.1.1",
            client_port=12345,
            server_ip="10.0.0.1",
            server_port=80,
            syn_timestamp=1234567890.0,
            syn_options="mss=1460;ws=7;sack=1;ts=1",
            client_isn=1000000,
            server_isn=2000000,
            tcp_timestamp_tsval="12345",
            tcp_timestamp_tsecr="67890",
            client_payload_md5="abc123",
            server_payload_md5="def456",
            length_signature="C:100 S:200 C:50",
            is_header_only=False,
            ipid_first=54321,
            ipid_set={54321, 54322, 54323},
            client_ipid_set={54321, 54322},
            server_ipid_set={54323},
            first_packet_time=1234567890.0,
            last_packet_time=1234567900.0,
            packet_count=10,
        )

        assert conn.stream_id == 1
        assert conn.protocol == 6
        assert conn.client_ip == "192.168.1.1"
        assert conn.client_port == 12345
        assert conn.server_ip == "10.0.0.1"
        assert conn.server_port == 80
        assert conn.syn_options == "mss=1460;ws=7;sack=1;ts=1"
        assert conn.client_isn == 1000000
        assert conn.server_isn == 2000000
        assert conn.is_header_only is False
        assert conn.packet_count == 10


@pytest.mark.unit
class TestTcpPacket:
    """Test TcpPacket dataclass."""

    def test_create_packet(self):
        """Test creating a TcpPacket instance."""
        packet = TcpPacket(
            frame_number=1,
            stream_id=0,
            protocol=6,  # TCP
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            flags="0x002",
            seq=1000000,
            ack=0,
            options="020405b4",
            length=0,
            ip_id=54321,
            timestamp=1234567890.0,
        )

        assert packet.frame_number == 1
        assert packet.stream_id == 0
        assert packet.protocol == 6
        assert packet.src_ip == "192.168.1.1"
        assert packet.dst_ip == "10.0.0.1"
        assert packet.flags == "0x002"


@pytest.mark.unit
class TestConnectionSampler:
    """Test ConnectionSampler."""

    @pytest.fixture
    def sampler(self) -> ConnectionSampler:
        """Create a ConnectionSampler instance."""
        return ConnectionSampler(threshold=10, sample_rate=0.5)

    @pytest.fixture
    def sample_connections(self) -> list[TcpConnection]:
        """Create sample connections for testing."""
        connections = []
        for i in range(20):
            conn = create_test_connection(
                stream_id=i,
                client_ip=f"192.168.1.{i}",
                client_port=10000 + i,
                server_port=80,
                syn_timestamp=1234567890.0 + i * 10,
                syn_options="mss=1460",
                client_isn=1000000 + i,
                server_isn=2000000 + i,
                tcp_timestamp_tsval=str(i),
                tcp_timestamp_tsecr="0",
                client_payload_md5=f"hash{i}",
                server_payload_md5=f"hash{i}",
                length_signature=f"C:{i*10}",
                ipid_first=i,
                ipid_set={i},
            )
            connections.append(conn)
        return connections

    def test_should_sample_below_threshold(self, sampler: ConnectionSampler):
        """Test that sampling is not triggered below threshold."""
        connections = [create_test_connection(stream_id=i) for i in range(5)]
        assert not sampler.should_sample(connections)

    def test_should_sample_above_threshold(self, sampler: ConnectionSampler, sample_connections: list[TcpConnection]):
        """Test that sampling is triggered above threshold."""
        assert sampler.should_sample(sample_connections)

    def test_sample_returns_fewer_connections(self, sampler: ConnectionSampler):
        """Test that sampling reduces the number of connections."""
        # Create connections with non-special ports to ensure they can be sampled
        connections = []
        for i in range(20):
            conn = create_test_connection(
                stream_id=i,
                client_ip=f"192.168.1.{i}",
                client_port=10000 + i,
                server_port=8000 + i,  # Non-special ports
                syn_timestamp=1234567890.0 + i * 10,
                syn_options="mss=1460",
                client_isn=1000000 + i,
                server_isn=2000000 + i,
                tcp_timestamp_tsval=str(i),
                tcp_timestamp_tsecr="0",
                client_payload_md5=f"hash{i}",
                server_payload_md5=f"hash{i}",
                length_signature=f"C:{i*10}",
                ipid_first=i,
                ipid_set={i},
            )
            connections.append(conn)

        sampled = sampler.sample(connections)
        assert len(sampled) < len(connections)

    def test_sample_preserves_header_only(self, sampler: ConnectionSampler):
        """Test that header-only connections are preserved."""
        connections = []
        for i in range(20):
            conn = create_test_connection(
                stream_id=i,
                client_ip=f"192.168.1.{i}",
                client_port=10000 + i,
                server_port=80,
                syn_timestamp=1234567890.0 + i * 10,
                is_header_only=(i == 5),  # One header-only connection
            )
            connections.append(conn)

        sampled = sampler.sample(connections)
        # Header-only connection should be preserved
        header_only_in_sample = any(c.is_header_only for c in sampled)
        assert header_only_in_sample


@pytest.mark.unit
class TestConnectionScorer:
    """Test ConnectionScorer."""

    @pytest.fixture
    def scorer(self) -> ConnectionScorer:
        """Create a ConnectionScorer instance."""
        return ConnectionScorer()

    @pytest.fixture
    def conn1(self) -> TcpConnection:
        """Create first test connection."""
        return create_test_connection(
            stream_id=1,
            client_ip="192.168.1.1",
            client_port=12345,
            server_ip="10.0.0.1",
            server_port=80,
            syn_timestamp=1234567890.0,
            syn_options="mss=1460;ws=7;sack=1;ts=1",
            client_isn=1000000,
            server_isn=2000000,
            tcp_timestamp_tsval="12345",
            tcp_timestamp_tsecr="67890",
            client_payload_md5="abc123",
            server_payload_md5="def456",
            length_signature="C:100 S:200 C:50",
            ipid_first=54321,
            ipid_set={54321, 54322, 54323},  # Need at least 2 IPIDs for matching
            client_ipid_set={54321, 54322},
            server_ipid_set={54323},
        )

    @pytest.fixture
    def conn2_identical(self, conn1: TcpConnection) -> TcpConnection:
        """Create identical connection (different IPs, same ports for 3-tuple match)."""
        return create_test_connection(
            stream_id=2,
            client_ip="172.16.0.1",  # Different IP (NAT scenario)
            client_port=conn1.client_port,  # Same port for 3-tuple match
            server_ip="10.0.0.2",  # Different server IP
            server_port=conn1.server_port,  # Same port for 3-tuple match
            syn_timestamp=1234567891.0,
            syn_options=conn1.syn_options,  # Same fingerprint
            client_isn=conn1.client_isn,
            server_isn=conn1.server_isn,
            tcp_timestamp_tsval=conn1.tcp_timestamp_tsval,
            tcp_timestamp_tsecr=conn1.tcp_timestamp_tsecr,
            client_payload_md5=conn1.client_payload_md5,
            server_payload_md5=conn1.server_payload_md5,
            length_signature=conn1.length_signature,
            ipid_first=conn1.ipid_first,
            ipid_set=conn1.ipid_set,
            client_ipid_set=conn1.client_ipid_set,
            server_ipid_set=conn1.server_ipid_set,
        )

    def test_score_identical_connections(self, scorer: ConnectionScorer, conn1: TcpConnection, conn2_identical: TcpConnection):
        """Test scoring identical connections."""
        score = scorer.score(conn1, conn2_identical)
        
        assert isinstance(score, MatchScore)
        assert score.ipid_match is True
        assert score.normalized_score > 0.9  # Should be very high
        assert score.raw_score > 0
        assert score.available_weight > 0

    def test_score_no_ipid_match(self, scorer: ConnectionScorer, conn1: TcpConnection):
        """Test scoring when IPID doesn't match."""
        conn2 = create_test_connection(
            stream_id=2,
            client_ip="172.16.0.1",
            client_port=conn1.client_port,  # Same port for 3-tuple match
            server_ip="10.0.0.2",
            server_port=conn1.server_port,  # Same port for 3-tuple match
            syn_timestamp=1234567891.0,
            syn_options=conn1.syn_options,
            client_isn=conn1.client_isn,
            server_isn=conn1.server_isn,
            tcp_timestamp_tsval=conn1.tcp_timestamp_tsval,
            tcp_timestamp_tsecr=conn1.tcp_timestamp_tsecr,
            client_payload_md5=conn1.client_payload_md5,
            server_payload_md5=conn1.server_payload_md5,
            length_signature=conn1.length_signature,
            ipid_first=99999,  # Different IPID
            ipid_set={99999},  # No overlap with conn1
        )
        
        score = scorer.score(conn1, conn2)
        
        # IPID is required, so score should be 0
        assert score.ipid_match is False
        assert score.normalized_score == 0.0
        assert score.evidence == "no-ipid"

    def test_score_partial_match(self, scorer: ConnectionScorer, conn1: TcpConnection):
        """Test scoring with partial feature match."""
        conn2 = create_test_connection(
            stream_id=2,
            client_ip="172.16.0.1",
            client_port=conn1.client_port,  # Same port for 3-tuple match
            server_ip="10.0.0.2",
            server_port=conn1.server_port,  # Same port for 3-tuple match
            syn_timestamp=1234567891.0,
            syn_options=conn1.syn_options,  # Match
            client_isn=conn1.client_isn,  # Match
            server_isn=999999,  # Different
            tcp_timestamp_tsval="",  # Different
            tcp_timestamp_tsecr="",
            client_payload_md5="",  # Different
            server_payload_md5="",
            length_signature="",  # Different
            ipid_first=conn1.ipid_first,  # Match
            ipid_set=conn1.ipid_set,  # Match
        )
        
        score = scorer.score(conn1, conn2)

        assert score.ipid_match is True
        assert 0.0 < score.normalized_score < 1.0  # Partial match
        assert score.raw_score > 0


@pytest.mark.integration
class TestMatchPlugin:
    """Test MatchPlugin integration."""

    @pytest.fixture
    def plugin(self) -> MatchPlugin:
        """Create a MatchPlugin instance."""
        return MatchPlugin()

    @pytest.fixture
    def test_case_dir(self) -> Path:
        """Return path to test case directory."""
        test_dir = Path("cases/TC-001-1-20160407")
        if not test_dir.exists():
            pytest.skip(f"Test case directory not found: {test_dir}")
        return test_dir

    def test_plugin_name(self, plugin: MatchPlugin):
        """Test that plugin has correct name."""
        assert plugin.name == "match"

    def test_execute_with_test_case(self, plugin: MatchPlugin, test_case_dir: Path, tmp_path: Path):
        """Test executing match on a test case directory."""
        output_file = tmp_path / "matches.txt"

        # Execute the plugin
        exit_code = plugin.execute(
            input_path=test_case_dir,
            output_file=output_file,
            bucket_strategy="auto",
            score_threshold=0.3,
        )

        # Check that execution succeeded
        assert exit_code == 0, "Plugin execution failed"

        # Check that output file was created
        assert output_file.exists(), "Output file was not created"

        # Check that output file has content
        content = output_file.read_text()
        assert len(content) > 0, "Output file is empty"

    def test_execute_with_no_sampling(self, plugin: MatchPlugin, test_case_dir: Path, tmp_path: Path):
        """Test executing match with sampling disabled (default behavior)."""
        output_file = tmp_path / "matches_no_sampling.txt"

        # Execute the plugin with enable_sampling=False (default)
        exit_code = plugin.execute(
            input_path=test_case_dir,
            output_file=output_file,
            bucket_strategy="auto",
            score_threshold=0.3,
            enable_sampling=False,
        )

        # Check that execution succeeded
        assert exit_code == 0, "Plugin execution failed"

        # Check that output file was created
        assert output_file.exists(), "Output file was not created"

    def test_execute_with_custom_sampling_params(self, plugin: MatchPlugin, test_case_dir: Path, tmp_path: Path):
        """Test executing match with custom sampling parameters."""
        output_file = tmp_path / "matches_custom_sampling.txt"

        # Execute the plugin with custom sampling parameters
        exit_code = plugin.execute(
            input_path=test_case_dir,
            output_file=output_file,
            bucket_strategy="auto",
            score_threshold=0.3,
            enable_sampling=True,
            sample_threshold=5000,
            sample_rate=0.3,
        )

        # Check that execution succeeded
        assert exit_code == 0, "Plugin execution failed"

        # Check that output file was created
        assert output_file.exists(), "Output file was not created"

    def test_execute_with_invalid_input(self, plugin: MatchPlugin, tmp_path: Path):
        """Test executing match with invalid input."""
        # Test with non-existent directory
        non_existent = tmp_path / "non_existent"
        output_file = tmp_path / "matches.txt"

        with pytest.raises(FileNotFoundError):
            plugin.execute(
                input_path=non_existent,
                output_file=output_file,
            )


@pytest.mark.integration
class TestConnectionMatcher:
    """Test ConnectionMatcher."""

    @pytest.fixture
    def matcher(self) -> ConnectionMatcher:
        """Create a ConnectionMatcher instance."""
        return ConnectionMatcher(
            bucket_strategy=BucketStrategy.AUTO,
            score_threshold=0.5,
        )

    @pytest.fixture
    def connections_a(self) -> list[TcpConnection]:
        """Create connections for side A."""
        return [
            create_test_connection(
                stream_id=1,
                client_ip="192.168.1.1",
                client_port=12345,
                server_ip="10.0.0.1",
                server_port=80,
                syn_timestamp=1234567890.0,
                syn_options="mss=1460;ws=7;sack=1;ts=1",
                client_isn=1000000,
                server_isn=2000000,
                tcp_timestamp_tsval="12345",
                tcp_timestamp_tsecr="67890",
                client_payload_md5="abc123",
                server_payload_md5="def456",
                length_signature="C:100 S:200 C:50",
                ipid_first=54321,
                ipid_set={54321},
            ),
        ]

    @pytest.fixture
    def connections_b(self) -> list[TcpConnection]:
        """Create connections for side B (matching)."""
        return [
            create_test_connection(
                stream_id=1,
                client_ip="172.16.0.1",  # Different IP (NAT)
                client_port=12345,  # Same port for 3-tuple match
                server_ip="10.0.0.2",  # Different server IP
                server_port=80,  # Same port for 3-tuple match
                syn_timestamp=1234567891.0,
                syn_options="mss=1460;ws=7;sack=1;ts=1",  # Same fingerprint
                client_isn=1000000,
                server_isn=2000000,
                tcp_timestamp_tsval="12345",
                tcp_timestamp_tsecr="67890",
                client_payload_md5="abc123",
                server_payload_md5="def456",
                length_signature="C:100 S:200 C:50",
                ipid_first=54321,
                ipid_set={54321},
            ),
        ]

    def test_match_connections(
        self,
        matcher: ConnectionMatcher,
        connections_a: list[TcpConnection],
        connections_b: list[TcpConnection],
    ):
        """Test matching connections."""
        matches = matcher.match(connections_a, connections_b)

        # Should find at least one match
        assert len(matches) > 0, "Should find at least one match"

        # Check match structure
        match = matches[0]
        assert match.conn1 == connections_a[0]
        assert match.conn2 == connections_b[0]
        assert match.score.normalized_score >= 0.5


@pytest.mark.unit
class TestMicroflowScoring:
    """Test microflow auto-accept functionality."""

    def test_microflow_auto_accept_with_strong_handshake(self):
        """Test microflow auto-accept for short flows with strong handshake evidence."""
        # Create two microflows (3 packets each) with strong handshake evidence
        conn1 = create_test_connection(
            syn_options="mss=1460;ws=7;sack=1;ts=1",
            client_isn=1000000,
            server_isn=2000000,
            tcp_timestamp_tsval="12345",
            tcp_timestamp_tsecr="67890",
            length_signature="C:100 S:200",
            ipid_set={54321},  # Only 1 common IPID (relaxed requirement)
            packet_count=3,
            first_packet_time=1234567890.0,
            last_packet_time=1234567890.5,
            client_ttl=64,
            server_ttl=128,
        )

        conn2 = create_test_connection(
            syn_options="mss=1460;ws=7;sack=1;ts=1",
            client_isn=1000000,
            server_isn=2000000,
            tcp_timestamp_tsval="12345",
            tcp_timestamp_tsecr="67890",
            length_signature="C:100 S:200",
            ipid_set={54321},  # Same IPID
            packet_count=3,
            first_packet_time=1234567890.0,
            last_packet_time=1234567890.5,
            client_ttl=64,
            server_ttl=128,
        )

        scorer = ConnectionScorer()
        micro_score = scorer.score_microflow(conn1, conn2)

        # Should be accepted by microflow rule
        assert micro_score is not None
        assert micro_score.microflow_accept is True
        assert micro_score.is_valid_match(0.60)
        assert "micro" in micro_score.evidence
        assert "synopt" in micro_score.evidence
        assert "isnC" in micro_score.evidence

    def test_microflow_reject_insufficient_evidence(self):
        """Test microflow rejection when handshake evidence is insufficient."""
        # Create two microflows with weak handshake evidence
        conn1 = create_test_connection(
            syn_options="",  # No SYN options
            client_isn=0,
            server_isn=0,
            tcp_timestamp_tsval="",
            tcp_timestamp_tsecr="",
            length_signature="",
            ipid_set={54321},
            packet_count=2,
            first_packet_time=1234567890.0,
            last_packet_time=1234567890.5,
        )

        conn2 = create_test_connection(
            syn_options="",
            client_isn=0,
            server_isn=0,
            tcp_timestamp_tsval="",
            tcp_timestamp_tsecr="",
            length_signature="",
            ipid_set={54321},
            packet_count=2,
            first_packet_time=1234567890.0,
            last_packet_time=1234567890.5,
        )

        scorer = ConnectionScorer()
        micro_score = scorer.score_microflow(conn1, conn2)

        # Should be rejected due to insufficient evidence
        assert micro_score is None

    def test_microflow_reject_no_ipid_overlap(self):
        """Test microflow rejection when no IPID overlap."""
        conn1 = create_test_connection(
            syn_options="mss=1460;ws=7;sack=1;ts=1",
            client_isn=1000000,
            ipid_set={54321},
            packet_count=2,
        )

        conn2 = create_test_connection(
            syn_options="mss=1460;ws=7;sack=1;ts=1",
            client_isn=1000000,
            ipid_set={99999},  # Different IPID
            packet_count=2,
        )

        scorer = ConnectionScorer()
        micro_score = scorer.score_microflow(conn1, conn2)

        # Should be rejected due to no IPID overlap
        assert micro_score is None

    def test_microflow_trigger_by_packet_count(self):
        """Test microflow trigger by packet count (<=3 packets)."""
        conn1 = create_test_connection(
            syn_options="mss=1460",
            client_isn=1000000,
            ipid_set={54321},
            packet_count=3,  # Exactly 3 packets
            first_packet_time=1234567890.0,
            last_packet_time=1234567900.0,  # Long duration, but packet count triggers
        )

        conn2 = create_test_connection(
            syn_options="mss=1460",
            client_isn=1000000,
            ipid_set={54321},
            packet_count=3,
            first_packet_time=1234567890.0,
            last_packet_time=1234567900.0,
        )

        scorer = ConnectionScorer()
        micro_score = scorer.score_microflow(conn1, conn2)

        # Should be accepted (packet count triggers microflow)
        assert micro_score is not None
        assert micro_score.microflow_accept is True


@pytest.mark.unit
class TestStrongIPIDAcceptance:
    """Test strong IPID acceptance (force_accept flag)."""

    def test_strong_ipid_force_accept(self):
        """Test strong IPID acceptance with 10+ overlapping IPIDs and 80%+ ratio."""
        # Create connections with strong IPID overlap (12 overlapping out of 15 total)
        ipid_set_large = set(range(54321, 54321 + 15))  # 15 IPIDs
        ipid_set_overlap = set(range(54321, 54321 + 12))  # 12 overlapping IPIDs (80%)

        conn1 = create_test_connection(
            syn_options="mss=1460",
            client_isn=1000000,
            ipid_set=ipid_set_large,
        )

        conn2 = create_test_connection(
            syn_options="mss=1460",
            client_isn=1000000,
            ipid_set=ipid_set_overlap,
        )

        scorer = ConnectionScorer()
        score = scorer.score(conn1, conn2)

        # Should have force_accept=True due to strong IPID overlap
        assert score.force_accept is True
        assert score.ipid_match is True
        assert "ipid*" in score.evidence  # * indicates strong IPID
        assert score.is_valid_match(0.60)

    def test_weak_ipid_no_force_accept(self):
        """Test that weak IPID overlap does not trigger force_accept."""
        # Create connections with weak IPID overlap (only 2 IPIDs)
        conn1 = create_test_connection(
            syn_options="mss=1460",
            client_isn=1000000,
            ipid_set={54321, 54322},
        )

        conn2 = create_test_connection(
            syn_options="mss=1460",
            client_isn=1000000,
            ipid_set={54321, 54322},
        )

        scorer = ConnectionScorer()
        score = scorer.score(conn1, conn2)

        # Should NOT have force_accept=True
        assert score.force_accept is False
        assert score.ipid_match is True
        assert "ipid*" not in score.evidence

    def test_strong_ipid_bypasses_threshold(self):
        """Test that strong IPID can bypass normalized score threshold."""
        # Create connections with strong IPID but weak other features
        ipid_set_large = set(range(54321, 54321 + 15))
        ipid_set_overlap = set(range(54321, 54321 + 12))

        conn1 = create_test_connection(
            syn_options="mss=1460",
            client_isn=1000000,
            ipid_set=ipid_set_large,
            # Weak other features
            tcp_timestamp_tsval="",
            client_payload_md5="",
            server_payload_md5="",
            length_signature="",
        )

        conn2 = create_test_connection(
            syn_options="mss=9999",  # Different SYN options
            client_isn=9999999,  # Different ISN
            ipid_set=ipid_set_overlap,
            tcp_timestamp_tsval="",
            client_payload_md5="",
            server_payload_md5="",
            length_signature="",
        )

        scorer = ConnectionScorer()
        score = scorer.score(conn1, conn2)

        # Should be accepted despite low normalized score
        assert score.force_accept is True
        assert score.is_valid_match(0.60)  # Accepted even if normalized_score < 0.60

