"""Unit tests for MatchPlugin database and JSON write operations."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch, call
import pytest

from capmaster.plugins.match.plugin import MatchPlugin


@pytest.mark.unit
class TestMatchPluginWriteToDatabase:
    """Test MatchPlugin._write_to_database method."""

    @pytest.fixture
    def plugin(self) -> MatchPlugin:
        """Create a MatchPlugin instance."""
        return MatchPlugin()

    @pytest.fixture
    def mock_db_writer(self) -> MagicMock:
        """Create a mock MatchDatabaseWriter."""
        mock_writer = MagicMock()
        mock_writer.__enter__ = MagicMock(return_value=mock_writer)
        mock_writer.__exit__ = MagicMock(return_value=None)
        return mock_writer

    def test_write_to_database_with_empty_endpoint_stats(
        self, plugin: MatchPlugin, caplog
    ):
        """Test that empty endpoint_stats skips database operations."""
        with patch('capmaster.plugins.match.db_writer.MatchDatabaseWriter') as mock_writer_class:
            # Call _write_to_database with empty list
            plugin._write_to_database(
                db_connection="postgresql://user:pass@localhost:5432/testdb",
                kase_id=137,
                endpoint_stats=[],  # Empty list
                file1=Path("file1.pcap"),
                file2=Path("file2.pcap"),
                pcap_id_mapping={},
            )

            # Verify that MatchDatabaseWriter was NOT instantiated
            mock_writer_class.assert_not_called()

            # Verify warning was logged
            assert "No endpoint pairs found in match results" in caplog.text
            assert "Skipping database write operation" in caplog.text

    def test_write_to_database_with_valid_endpoint_stats(
        self, plugin: MatchPlugin, mock_db_writer: MagicMock
    ):
        """Test that valid endpoint_stats triggers database operations."""
        # Create mock endpoint stats
        mock_stats = [MagicMock()]  # Non-empty list

        with patch('capmaster.plugins.match.db_writer.MatchDatabaseWriter', return_value=mock_db_writer):
            plugin._write_to_database(
                db_connection="postgresql://user:pass@localhost:5432/testdb",
                kase_id=137,
                endpoint_stats=mock_stats,
                file1=Path("file1.pcap"),
                file2=Path("file2.pcap"),
                pcap_id_mapping={},
            )

            # Verify that database operations were called
            mock_db_writer.ensure_table_exists.assert_called_once()
            mock_db_writer.clear_table_data.assert_called_once()
            mock_db_writer.write_endpoint_stats.assert_called_once()
            mock_db_writer.commit.assert_called_once()

    def test_write_to_database_preserves_existing_data_on_empty_stats(
        self, plugin: MatchPlugin, mock_db_writer: MagicMock
    ):
        """Test that empty stats preserves existing database data."""
        with patch('capmaster.plugins.match.db_writer.MatchDatabaseWriter', return_value=mock_db_writer):
            # Call with empty stats
            plugin._write_to_database(
                db_connection="postgresql://user:pass@localhost:5432/testdb",
                kase_id=137,
                endpoint_stats=[],
                file1=Path("file1.pcap"),
                file2=Path("file2.pcap"),
            )

            # Verify that clear_table_data was NOT called (preserves existing data)
            mock_db_writer.clear_table_data.assert_not_called()
            mock_db_writer.write_endpoint_stats.assert_not_called()
            mock_db_writer.commit.assert_not_called()

    def test_write_to_database_with_pcap_id_mapping(
        self, plugin: MatchPlugin, mock_db_writer: MagicMock
    ):
        """Test database write with pcap_id_mapping."""
        mock_stats = [MagicMock()]
        pcap_id_mapping = {"file1.pcap": 0, "file2.pcap": 1}

        with patch('capmaster.plugins.match.db_writer.MatchDatabaseWriter', return_value=mock_db_writer):
            plugin._write_to_database(
                db_connection="postgresql://user:pass@localhost:5432/testdb",
                kase_id=137,
                endpoint_stats=mock_stats,
                file1=Path("file1.pcap"),
                file2=Path("file2.pcap"),
                pcap_id_mapping=pcap_id_mapping,
            )

            # Verify write_endpoint_stats was called with correct mapping
            call_args = mock_db_writer.write_endpoint_stats.call_args
            assert call_args[1]['pcap_id_mapping'] == pcap_id_mapping


@pytest.mark.unit
class TestMatchPluginWriteToJSON:
    """Test MatchPlugin._write_to_json method."""

    @pytest.fixture
    def plugin(self) -> MatchPlugin:
        """Create a MatchPlugin instance."""
        return MatchPlugin()

    def test_write_to_json_with_empty_endpoint_stats(
        self, plugin: MatchPlugin, tmp_path: Path, caplog
    ):
        """Test that empty endpoint_stats skips JSON write."""
        output_file = tmp_path / "output.json"

        with patch('capmaster.plugins.match.db_writer.MatchDatabaseWriter') as mock_writer_class:
            # Call _write_to_json with empty list
            plugin._write_to_json(
                output_file=output_file,
                endpoint_stats=[],  # Empty list
                file1=Path("file1.pcap"),
                file2=Path("file2.pcap"),
                pcap_id_mapping={},
            )

            # Verify that write_endpoint_stats_to_json was NOT called
            mock_writer_class.write_endpoint_stats_to_json.assert_not_called()

            # Verify output file was NOT created
            assert not output_file.exists()

            # Verify warning was logged
            assert "No endpoint pairs found in match results" in caplog.text
            assert "Skipping JSON file write operation" in caplog.text

    def test_write_to_json_with_valid_endpoint_stats(
        self, plugin: MatchPlugin, tmp_path: Path
    ):
        """Test that valid endpoint_stats triggers JSON write."""
        output_file = tmp_path / "output.json"
        mock_stats = [MagicMock()]

        with patch('capmaster.plugins.match.db_writer.MatchDatabaseWriter') as mock_writer_class:
            # Mock the static method to return success
            mock_writer_class.write_endpoint_stats_to_json.return_value = 10

            plugin._write_to_json(
                output_file=output_file,
                endpoint_stats=mock_stats,
                file1=Path("file1.pcap"),
                file2=Path("file2.pcap"),
                pcap_id_mapping={},
            )

            # Verify that write_endpoint_stats_to_json was called
            mock_writer_class.write_endpoint_stats_to_json.assert_called_once()

    def test_write_to_json_with_pcap_id_mapping(
        self, plugin: MatchPlugin, tmp_path: Path
    ):
        """Test JSON write with pcap_id_mapping."""
        output_file = tmp_path / "output.json"
        mock_stats = [MagicMock()]
        pcap_id_mapping = {"file1.pcap": 0, "file2.pcap": 1}

        with patch('capmaster.plugins.match.db_writer.MatchDatabaseWriter') as mock_writer_class:
            mock_writer_class.write_endpoint_stats_to_json.return_value = 10

            plugin._write_to_json(
                output_file=output_file,
                endpoint_stats=mock_stats,
                file1=Path("file1.pcap"),
                file2=Path("file2.pcap"),
                pcap_id_mapping=pcap_id_mapping,
            )

            # Verify write_endpoint_stats_to_json was called with correct mapping
            call_args = mock_writer_class.write_endpoint_stats_to_json.call_args
            assert call_args[1]['pcap_id_mapping'] == pcap_id_mapping

    def test_write_to_json_handles_exceptions(
        self, plugin: MatchPlugin, tmp_path: Path
    ):
        """Test that JSON write handles exceptions properly."""
        output_file = tmp_path / "output.json"
        mock_stats = [MagicMock()]

        with patch('capmaster.plugins.match.db_writer.MatchDatabaseWriter') as mock_writer_class:
            # Mock the static method to raise an exception
            mock_writer_class.write_endpoint_stats_to_json.side_effect = Exception("Write failed")

            # Should raise the exception
            with pytest.raises(Exception, match="Write failed"):
                plugin._write_to_json(
                    output_file=output_file,
                    endpoint_stats=mock_stats,
                    file1=Path("file1.pcap"),
                    file2=Path("file2.pcap"),
                )


@pytest.mark.unit
class TestMatchPluginEmptyStatsScenarios:
    """Test various scenarios that could result in empty endpoint_stats."""

    @pytest.fixture
    def plugin(self) -> MatchPlugin:
        """Create a MatchPlugin instance."""
        return MatchPlugin()

    def test_no_matches_results_in_empty_stats(self, plugin: MatchPlugin):
        """Test that no matches results in empty endpoint_stats."""
        # This is a conceptual test - in practice, _output_endpoint_stats
        # would return an empty list if there are no matches
        from capmaster.plugins.match.endpoint_stats import EndpointStatsCollector
        from capmaster.plugins.match.server_detector import ServerDetector

        detector = ServerDetector()
        collector = EndpointStatsCollector(detector)

        # Don't add any matches
        collector.finalize()
        stats = collector.get_stats()

        # Should return empty list
        assert stats == []

    def test_database_write_skipped_when_no_matches(
        self, plugin: MatchPlugin, caplog
    ):
        """Test complete flow: no matches -> empty stats -> skip database write."""
        with patch('capmaster.plugins.match.db_writer.MatchDatabaseWriter') as mock_writer_class:
            # Simulate the scenario where _output_endpoint_stats returns empty list
            empty_stats = []

            plugin._write_to_database(
                db_connection="postgresql://user:pass@localhost:5432/testdb",
                kase_id=137,
                endpoint_stats=empty_stats,
                file1=Path("file1.pcap"),
                file2=Path("file2.pcap"),
            )

            # Database writer should not be instantiated
            mock_writer_class.assert_not_called()

            # Warning should be logged
            assert "No endpoint pairs found" in caplog.text
            assert "preserve existing data" in caplog.text

    def test_json_write_skipped_when_no_matches(
        self, plugin: MatchPlugin, tmp_path: Path, caplog
    ):
        """Test complete flow: no matches -> empty stats -> skip JSON write."""
        output_file = tmp_path / "output.json"

        with patch('capmaster.plugins.match.db_writer.MatchDatabaseWriter') as mock_writer_class:
            # Simulate the scenario where _output_endpoint_stats returns empty list
            empty_stats = []

            plugin._write_to_json(
                output_file=output_file,
                endpoint_stats=empty_stats,
                file1=Path("file1.pcap"),
                file2=Path("file2.pcap"),
            )

            # JSON write should not be called
            mock_writer_class.write_endpoint_stats_to_json.assert_not_called()

            # File should not be created
            assert not output_file.exists()

            # Warning should be logged
            assert "No endpoint pairs found" in caplog.text
            assert "Skipping JSON file write" in caplog.text

