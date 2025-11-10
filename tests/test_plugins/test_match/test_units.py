"""Unit tests for Match plugin core modules."""

from __future__ import annotations

from pathlib import Path

import pytest

from capmaster.plugins.match.connection import TcpConnection, TcpPacket
from capmaster.plugins.match.extractor import TcpFieldExtractor
from capmaster.plugins.match.matcher import BucketStrategy, ConnectionMatcher
from capmaster.plugins.match.plugin import MatchPlugin
from capmaster.plugins.match.sampler import ConnectionSampler
from capmaster.plugins.match.scorer import ConnectionScorer, MatchScore


@pytest.mark.integration
class TestTcpConnection:
    """Test TcpConnection dataclass."""

    def test_create_connection(self):
        """Test creating a TcpConnection instance."""
        conn = TcpConnection(
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
            is_header_only=False,
            ipid_first=54321,
        )
        
        assert conn.stream_id == 1
        assert conn.client_ip == "192.168.1.1"
        assert conn.client_port == 12345
        assert conn.server_ip == "10.0.0.1"
        assert conn.server_port == 80
        assert conn.syn_options == "mss=1460;ws=7;sack=1;ts=1"
        assert conn.client_isn == 1000000
        assert conn.server_isn == 2000000
        assert conn.is_header_only is False


@pytest.mark.integration
class TestTcpPacket:
    """Test TcpPacket dataclass."""

    def test_create_packet(self):
        """Test creating a TcpPacket instance."""
        packet = TcpPacket(
            frame_number=1,
            stream_id=0,
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
        assert packet.src_ip == "192.168.1.1"
        assert packet.dst_ip == "10.0.0.1"
        assert packet.flags == "0x002"


@pytest.mark.integration
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
            conn = TcpConnection(
                stream_id=i,
                client_ip=f"192.168.1.{i}",
                client_port=10000 + i,
                server_ip="10.0.0.1",
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
                is_header_only=False,
                ipid_first=i,
            )
            connections.append(conn)
        return connections

    def test_should_sample_below_threshold(self, sampler: ConnectionSampler):
        """Test that sampling is not triggered below threshold."""
        connections = [TcpConnection(
            stream_id=i,
            client_ip="192.168.1.1",
            client_port=10000,
            server_ip="10.0.0.1",
            server_port=80,
            syn_timestamp=1234567890.0,
            syn_options="",
            client_isn=0,
            server_isn=0,
            tcp_timestamp_tsval="",
            tcp_timestamp_tsecr="",
            client_payload_md5="",
            server_payload_md5="",
            length_signature="",
            is_header_only=False,
            ipid_first=0,
        ) for i in range(5)]
        
        assert not sampler.should_sample(connections)

    def test_should_sample_above_threshold(self, sampler: ConnectionSampler, sample_connections: list[TcpConnection]):
        """Test that sampling is triggered above threshold."""
        assert sampler.should_sample(sample_connections)

    def test_sample_returns_fewer_connections(self, sampler: ConnectionSampler):
        """Test that sampling reduces the number of connections."""
        # Create connections with non-special ports to ensure they can be sampled
        connections = []
        for i in range(20):
            conn = TcpConnection(
                stream_id=i,
                client_ip=f"192.168.1.{i}",
                client_port=10000 + i,
                server_ip="10.0.0.1",
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
                is_header_only=False,
                ipid_first=i,
            )
            connections.append(conn)

        sampled = sampler.sample(connections)
        assert len(sampled) < len(connections)

    def test_sample_preserves_header_only(self, sampler: ConnectionSampler):
        """Test that header-only connections are preserved."""
        connections = []
        for i in range(20):
            conn = TcpConnection(
                stream_id=i,
                client_ip=f"192.168.1.{i}",
                client_port=10000 + i,
                server_ip="10.0.0.1",
                server_port=80,
                syn_timestamp=1234567890.0 + i * 10,
                syn_options="",
                client_isn=0,
                server_isn=0,
                tcp_timestamp_tsval="",
                tcp_timestamp_tsecr="",
                client_payload_md5="",
                server_payload_md5="",
                length_signature="",
                is_header_only=(i == 5),  # One header-only connection
                ipid_first=0,
            )
            connections.append(conn)
        
        sampled = sampler.sample(connections)
        # Header-only connection should be preserved
        header_only_in_sample = any(c.is_header_only for c in sampled)
        assert header_only_in_sample


@pytest.mark.integration
class TestConnectionScorer:
    """Test ConnectionScorer."""

    @pytest.fixture
    def scorer(self) -> ConnectionScorer:
        """Create a ConnectionScorer instance."""
        return ConnectionScorer()

    @pytest.fixture
    def conn1(self) -> TcpConnection:
        """Create first test connection."""
        return TcpConnection(
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
            is_header_only=False,
            ipid_first=54321,
        )

    @pytest.fixture
    def conn2_identical(self, conn1: TcpConnection) -> TcpConnection:
        """Create identical connection (different IPs/ports)."""
        return TcpConnection(
            stream_id=2,
            client_ip="172.16.0.1",  # Different IP (NAT scenario)
            client_port=54321,  # Different port
            server_ip="10.0.0.2",  # Different server IP
            server_port=80,
            syn_timestamp=1234567891.0,
            syn_options=conn1.syn_options,  # Same fingerprint
            client_isn=conn1.client_isn,
            server_isn=conn1.server_isn,
            tcp_timestamp_tsval=conn1.tcp_timestamp_tsval,
            tcp_timestamp_tsecr=conn1.tcp_timestamp_tsecr,
            client_payload_md5=conn1.client_payload_md5,
            server_payload_md5=conn1.server_payload_md5,
            length_signature=conn1.length_signature,
            is_header_only=False,
            ipid_first=conn1.ipid_first,
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
        conn2 = TcpConnection(
            stream_id=2,
            client_ip="172.16.0.1",
            client_port=54321,
            server_ip="10.0.0.2",
            server_port=80,
            syn_timestamp=1234567891.0,
            syn_options=conn1.syn_options,
            client_isn=conn1.client_isn,
            server_isn=conn1.server_isn,
            tcp_timestamp_tsval=conn1.tcp_timestamp_tsval,
            tcp_timestamp_tsecr=conn1.tcp_timestamp_tsecr,
            client_payload_md5=conn1.client_payload_md5,
            server_payload_md5=conn1.server_payload_md5,
            length_signature=conn1.length_signature,
            is_header_only=False,
            ipid_first=99999,  # Different IPID
        )
        
        score = scorer.score(conn1, conn2)
        
        # IPID is required, so score should be 0
        assert score.ipid_match is False
        assert score.normalized_score == 0.0
        assert score.evidence == "no-ipid"

    def test_score_partial_match(self, scorer: ConnectionScorer, conn1: TcpConnection):
        """Test scoring with partial feature match."""
        conn2 = TcpConnection(
            stream_id=2,
            client_ip="172.16.0.1",
            client_port=54321,
            server_ip="10.0.0.2",
            server_port=80,
            syn_timestamp=1234567891.0,
            syn_options=conn1.syn_options,  # Match
            client_isn=conn1.client_isn,  # Match
            server_isn=999999,  # Different
            tcp_timestamp_tsval="",  # Different
            tcp_timestamp_tsecr="",
            client_payload_md5="",  # Different
            server_payload_md5="",
            length_signature="",  # Different
            is_header_only=False,
            ipid_first=conn1.ipid_first,  # Match
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
        """Test executing match with sampling disabled."""
        output_file = tmp_path / "matches_no_sampling.txt"

        # Execute the plugin with no_sampling=True
        exit_code = plugin.execute(
            input_path=test_case_dir,
            output_file=output_file,
            bucket_strategy="auto",
            score_threshold=0.3,
            no_sampling=True,
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
            sampling_threshold=5000,
            sampling_rate=0.3,
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

        exit_code = plugin.execute(
            input_path=non_existent,
            output_file=output_file,
        )

        # Should fail gracefully
        assert exit_code != 0, "Should fail with non-existent input"


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
            TcpConnection(
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
                is_header_only=False,
                ipid_first=54321,
            ),
        ]

    @pytest.fixture
    def connections_b(self) -> list[TcpConnection]:
        """Create connections for side B (matching)."""
        return [
            TcpConnection(
                stream_id=1,
                client_ip="172.16.0.1",  # Different IP (NAT)
                client_port=54321,  # Different port
                server_ip="10.0.0.2",  # Different server IP
                server_port=80,
                syn_timestamp=1234567891.0,
                syn_options="mss=1460;ws=7;sack=1;ts=1",  # Same fingerprint
                client_isn=1000000,
                server_isn=2000000,
                tcp_timestamp_tsval="12345",
                tcp_timestamp_tsecr="67890",
                client_payload_md5="abc123",
                server_payload_md5="def456",
                length_signature="C:100 S:200 C:50",
                is_header_only=False,
                ipid_first=54321,
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

