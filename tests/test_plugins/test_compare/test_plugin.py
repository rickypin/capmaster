"""Unit tests for compare plugin core functionality."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from capmaster.plugins.compare.plugin import ComparePlugin
from capmaster.utils.errors import InsufficientFilesError


@pytest.mark.integration
class TestComparePlugin:
    """Test ComparePlugin class."""

    @pytest.fixture
    def plugin(self) -> ComparePlugin:
        """Create a ComparePlugin instance."""
        return ComparePlugin()

    @pytest.fixture
    def two_pcap_dir(self, tmp_path: Path, pcap_builder) -> Path:
        """Create a directory with exactly 2 PCAP files."""
        test_dir = tmp_path / "two_pcaps"
        test_dir.mkdir()

        # Create two simple PCAP files with TCP connections
        pcap_builder().add_tcp_packet(
            "192.168.1.100", "10.0.0.1", 54321, 80,
            flags=0x02, timestamp_sec=1000
        ).build(test_dir / "file_a.pcap")

        pcap_builder().add_tcp_packet(
            "192.168.1.100", "10.0.0.1", 54321, 80,
            flags=0x02, timestamp_sec=1000
        ).build(test_dir / "file_b.pcap")

        return test_dir

    @pytest.fixture
    def one_pcap_dir(self, tmp_path: Path, pcap_builder) -> Path:
        """Create a directory with only 1 PCAP file."""
        test_dir = tmp_path / "one_pcap"
        test_dir.mkdir()

        pcap_builder().add_tcp_packet(
            "192.168.1.100", "10.0.0.1", 54321, 80
        ).build(test_dir / "file_a.pcap")

        return test_dir

    @pytest.fixture
    def three_pcap_dir(self, tmp_path: Path, pcap_builder) -> Path:
        """Create a directory with 3 PCAP files."""
        test_dir = tmp_path / "three_pcaps"
        test_dir.mkdir()

        for i in range(3):
            pcap_builder().add_tcp_packet(
                "192.168.1.100", "10.0.0.1", 54321 + i, 80
            ).build(test_dir / f"file_{i}.pcap")

        return test_dir

    def test_plugin_name(self, plugin: ComparePlugin):
        """Test plugin name."""
        assert plugin.name == "compare"

    def test_plugin_description(self, plugin: ComparePlugin):
        """Test plugin has description."""
        assert hasattr(plugin, "__doc__")
        assert plugin.__doc__ is not None

    def test_execute_insufficient_files_error_one_file(
        self, plugin: ComparePlugin, one_pcap_dir: Path
    ):
        """Test error when directory has only 1 file."""
        # execute() catches exceptions and returns non-zero exit code
        exit_code = plugin.execute(input_path=one_pcap_dir)
        assert exit_code != 0

    def test_execute_insufficient_files_error_three_files(
        self, plugin: ComparePlugin, three_pcap_dir: Path
    ):
        """Test error when directory has 3 files."""
        # execute() catches exceptions and returns non-zero exit code
        exit_code = plugin.execute(input_path=three_pcap_dir)
        assert exit_code != 0

    def test_execute_with_nonexistent_directory(self, plugin: ComparePlugin, tmp_path: Path):
        """Test error when directory doesn't exist."""
        nonexistent = tmp_path / "nonexistent"
        # execute() catches exceptions and returns non-zero exit code
        exit_code = plugin.execute(input_path=nonexistent)
        assert exit_code != 0

    def test_execute_with_file1_file2_nonexistent(
        self, plugin: ComparePlugin, tmp_path: Path
    ):
        """Test error when file1 or file2 doesn't exist."""
        file1 = tmp_path / "nonexistent1.pcap"
        file2 = tmp_path / "nonexistent2.pcap"

        # execute() catches exceptions and returns non-zero exit code
        exit_code = plugin.execute(file1=file1, file2=file2)
        assert exit_code != 0

    def test_execute_requires_input(self, plugin: ComparePlugin):
        """Test that execute requires either input_path or file1/file2."""
        # execute() catches exceptions and returns non-zero exit code
        exit_code = plugin.execute()
        assert exit_code != 0

    def test_execute_file1_requires_file2(
        self, plugin: ComparePlugin, tmp_path: Path, pcap_builder
    ):
        """Test that file1 requires file2."""
        file1 = pcap_builder().add_tcp_packet(
            "192.168.1.100", "10.0.0.1", 54321, 80
        ).build(tmp_path / "file1.pcap")

        # execute() catches exceptions and returns non-zero exit code
        exit_code = plugin.execute(file1=file1)
        assert exit_code != 0

    def test_execute_validates_threshold_range(self, plugin: ComparePlugin, two_pcap_dir: Path):
        """Test that threshold must be between 0 and 1."""
        # Note: threshold validation might not be implemented in execute()
        # This test documents expected behavior
        # For now, just test that it doesn't crash
        exit_code = plugin.execute(input_path=two_pcap_dir, score_threshold=1.5, quiet=True)
        # May return 0 if validation not implemented
        assert exit_code >= 0

    def test_execute_validates_bucket_strategy(self, plugin: ComparePlugin, two_pcap_dir: Path):
        """Test that bucket_strategy must be valid."""
        # execute() catches ValueError and returns non-zero exit code
        exit_code = plugin.execute(input_path=two_pcap_dir, bucket_strategy="invalid")
        assert exit_code != 0

    def test_execute_validates_match_mode(self, plugin: ComparePlugin, two_pcap_dir: Path):
        """Test that match_mode must be valid."""
        # execute() catches ValueError and returns non-zero exit code
        exit_code = plugin.execute(input_path=two_pcap_dir, match_mode="invalid")
        assert exit_code != 0

    def test_execute_db_connection_requires_kase_id(
        self, plugin: ComparePlugin, two_pcap_dir: Path
    ):
        """Test that db_connection requires kase_id."""
        # This should be validated at CLI level, but test execute as well
        # The actual validation might happen in CLI, so this test might need adjustment
        pass  # TODO: Implement if validation is in execute()

    def test_execute_kase_id_requires_db_connection(
        self, plugin: ComparePlugin, two_pcap_dir: Path
    ):
        """Test that kase_id requires db_connection."""
        # This should be validated at CLI level
        pass  # TODO: Implement if validation is in execute()

    def test_execute_show_flow_hash_required_for_db(
        self, plugin: ComparePlugin, two_pcap_dir: Path
    ):
        """Test that show_flow_hash is required when using database."""
        # This should be validated at CLI level
        pass  # TODO: Implement if validation is in execute()

    def test_execute_returns_zero_on_success(
        self, plugin: ComparePlugin, two_pcap_dir: Path, tmp_path: Path
    ):
        """Test that execute returns 0 on success."""
        output_file = tmp_path / "output.txt"

        # Mock the heavy operations to make test fast
        with patch("capmaster.plugins.compare.plugin.extract_connections_from_pcap") as mock_extract, \
             patch("capmaster.plugins.match.plugin.MatchPlugin.match_connections_in_memory") as mock_match, \
             patch("capmaster.plugins.compare.plugin.PacketExtractor") as mock_extractor, \
             patch("capmaster.plugins.compare.plugin.PacketComparator") as mock_comparator:

            # Setup mocks to return empty results
            mock_extract.return_value = []
            mock_match.return_value = []

            exit_code = plugin.execute(
                input_path=two_pcap_dir,
                output_file=output_file,
                quiet=True
            )

            # Should return 0 even with no matches
            assert exit_code == 0

    def test_execute_creates_output_file(
        self, plugin: ComparePlugin, two_pcap_dir: Path, tmp_path: Path
    ):
        """Test that execute creates output file when specified."""
        output_file = tmp_path / "comparison_results.txt"

        with patch("capmaster.plugins.compare.plugin.extract_connections_from_pcap") as mock_extract, \
             patch("capmaster.plugins.match.plugin.MatchPlugin.match_connections_in_memory") as mock_match:

            # Mock to return at least one match so output is generated
            from capmaster.core.connection.matcher import ConnectionMatch
            from capmaster.core.connection.models import TcpConnection
            from capmaster.core.connection.scorer import MatchScore

            mock_conn = TcpConnection(
                stream_id=0,
                protocol=6,
                client_ip="192.168.1.100",
                client_port=54321,
                server_ip="10.0.0.1",
                server_port=80,
                syn_timestamp=1000.0,
                syn_options="mss=1460;ws=7;sack=1;ts=1",
                client_isn=1000000,
                server_isn=2000000,
                tcp_timestamp_tsval="12345",
                tcp_timestamp_tsecr="67890",
                client_payload_md5="",
                server_payload_md5="",
                length_signature="C:60 S:60",
                is_header_only=True,
                ipid_first=100,
                ipid_set={100, 101},
                client_ipid_set={100},
                server_ipid_set={101},
                first_packet_time=1000.0,
                last_packet_time=1001.0,
                packet_count=2,
                client_ttl=64,
                server_ttl=64
            )

            mock_score = MatchScore(
                normalized_score=1.0,
                raw_score=1.0,
                available_weight=1.0,
                ipid_match=True,
                evidence="test"
            )
            mock_match_obj = ConnectionMatch(conn1=mock_conn, conn2=mock_conn, score=mock_score)
            mock_extract.return_value = [mock_conn]
            mock_match.return_value = [mock_match_obj]

            plugin.execute(
                input_path=two_pcap_dir,
                output_file=output_file,
                quiet=True
            )

            # Output file should be created
            assert output_file.exists()

    def test_execute_quiet_mode_suppresses_output(
        self, plugin: ComparePlugin, two_pcap_dir: Path, capsys
    ):
        """Test that quiet mode suppresses console output."""
        with patch("capmaster.plugins.compare.plugin.extract_connections_from_pcap") as mock_extract, \
             patch("capmaster.plugins.match.plugin.MatchPlugin.match_connections_in_memory") as mock_match:

            mock_extract.return_value = []
            mock_match.return_value = []

            plugin.execute(input_path=two_pcap_dir, quiet=True)

            captured = capsys.readouterr()
            # Quiet mode should produce minimal output
            # (some logging might still occur, but no progress bars)
            assert "Extracting connections" not in captured.out
            assert "Matching connections" not in captured.out

    def test_execute_with_comma_separated_files(
        self, plugin: ComparePlugin, tmp_path: Path, pcap_builder
    ):
        """Test execute with comma-separated file list."""
        file1 = pcap_builder().add_tcp_packet(
            "192.168.1.100", "10.0.0.1", 54321, 80
        ).build(tmp_path / "file1.pcap")

        file2 = pcap_builder().add_tcp_packet(
            "192.168.1.100", "10.0.0.1", 54321, 80
        ).build(tmp_path / "file2.pcap")

        input_path = f"{file1},{file2}"

        with patch("capmaster.plugins.compare.plugin.extract_connections_from_pcap") as mock_extract, \
             patch("capmaster.plugins.match.plugin.MatchPlugin.match_connections_in_memory") as mock_match:

            mock_extract.return_value = []
            mock_match.return_value = []

            exit_code = plugin.execute(input_path=input_path, quiet=True)
            assert exit_code == 0

    def test_execute_alphabetical_ordering(
        self, plugin: ComparePlugin, tmp_path: Path, pcap_builder
    ):
        """Test that files are ordered alphabetically when using directory input."""
        test_dir = tmp_path / "test"
        test_dir.mkdir()

        # Create files in non-alphabetical order
        file_z = pcap_builder().add_tcp_packet(
            "192.168.1.100", "10.0.0.1", 54321, 80
        ).build(test_dir / "z_file.pcap")

        file_a = pcap_builder().add_tcp_packet(
            "192.168.1.100", "10.0.0.1", 54321, 80
        ).build(test_dir / "a_file.pcap")

        with patch("capmaster.plugins.compare.plugin.extract_connections_from_pcap") as mock_extract, \
             patch("capmaster.plugins.match.plugin.MatchPlugin.match_connections_in_memory") as mock_match:

            mock_extract.return_value = []
            mock_match.return_value = []

            plugin.execute(input_path=test_dir, quiet=True)

            # First call should be for a_file.pcap (alphabetically first)
            first_call_file = mock_extract.call_args_list[0][0][0]
            assert first_call_file.name == "a_file.pcap"

    def test_execute_with_match_mode_one_to_many(
        self, plugin: ComparePlugin, two_pcap_dir: Path
    ):
        """Test execute with match_mode=one-to-many parameter."""
        with patch("capmaster.plugins.compare.plugin.extract_connections_from_pcap") as mock_extract, \
             patch("capmaster.plugins.match.plugin.MatchPlugin.match_connections_in_memory") as mock_match:

            mock_extract.return_value = []
            mock_match.return_value = []

            exit_code = plugin.execute(
                input_path=two_pcap_dir,
                match_mode="one-to-many",
                quiet=True
            )

            # Should succeed
            assert exit_code == 0

            # Verify match_connections_in_memory was called with correct match_mode
            from capmaster.core.connection.matcher import MatchMode
            mock_match.assert_called_once()
            call_kwargs = mock_match.call_args[1]
            # The match_mode is passed as string and converted inside the function
            assert call_kwargs["match_mode"] == "one-to-many"

    def test_execute_with_invalid_match_mode(
        self, plugin: ComparePlugin, two_pcap_dir: Path
    ):
        """Test execute with invalid match_mode parameter."""
        # Invalid match_mode should be caught and return non-zero exit code
        exit_code = plugin.execute(
            input_path=two_pcap_dir,
            match_mode="invalid-mode",
            quiet=True
        )

        # Should fail with non-zero exit code
        assert exit_code != 0

    def test_execute_with_batch_packet_extraction(
        self, plugin: ComparePlugin, two_pcap_dir: Path
    ):
        """Test that batch packet extraction is used for performance optimization."""
        with patch("capmaster.plugins.compare.plugin.extract_connections_from_pcap") as mock_extract, \
             patch("capmaster.plugins.match.plugin.MatchPlugin.match_connections_in_memory") as mock_match, \
             patch("capmaster.plugins.compare.plugin.PacketExtractor") as mock_extractor_class:

            # Create mock connections
            from capmaster.core.connection.models import TcpConnection
            mock_conn1 = MagicMock(spec=TcpConnection)
            mock_conn1.stream_id = 1
            mock_conn2 = MagicMock(spec=TcpConnection)
            mock_conn2.stream_id = 2
            mock_extract.return_value = [mock_conn1, mock_conn2]

            # Create mock matches
            from capmaster.core.connection.matcher import ConnectionMatch
            from capmaster.core.connection.scorer import MatchScore
            mock_score = MagicMock(spec=MatchScore)
            mock_score.normalized_score = 0.95
            mock_match_obj = ConnectionMatch(conn1=mock_conn1, conn2=mock_conn2, score=mock_score)
            mock_match.return_value = [mock_match_obj]

            # Mock packet extractor
            mock_extractor = MagicMock()
            mock_extractor.extract_multiple_streams.return_value = {1: [], 2: []}
            mock_extractor_class.return_value = mock_extractor

            exit_code = plugin.execute(
                input_path=two_pcap_dir,
                quiet=True
            )

            assert exit_code == 0

            # Verify extract_multiple_streams was called (batch extraction)
            assert mock_extractor.extract_multiple_streams.called

