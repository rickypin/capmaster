"""Tests for OutputManager."""

from pathlib import Path

import pytest

from capmaster.core.output_manager import OutputManager


@pytest.mark.integration
class TestOutputManager:
    """Test cases for OutputManager."""

    def test_create_output_dir_default_for_file(self, tmp_path: Path) -> None:
        """Test creating default output directory for a file."""
        input_file = tmp_path / "test.pcap"
        input_file.touch()

        output_dir = OutputManager.create_output_dir(input_file)

        assert output_dir == tmp_path / "statistics"
        assert output_dir.exists()
        assert output_dir.is_dir()

    def test_create_output_dir_default_for_directory(self, tmp_path: Path) -> None:
        """Test creating default output directory for a directory input."""
        input_dir = tmp_path / "data"
        input_dir.mkdir()

        output_dir = OutputManager.create_output_dir(input_dir)

        assert output_dir == input_dir / "statistics"
        assert output_dir.exists()
        assert output_dir.is_dir()

    def test_create_output_dir_custom(self, tmp_path: Path) -> None:
        """Test creating custom output directory."""
        input_file = tmp_path / "test.pcap"
        input_file.touch()

        custom_output = tmp_path / "custom_output"
        output_dir = OutputManager.create_output_dir(input_file, custom_output)

        assert output_dir == custom_output
        assert output_dir.exists()
        assert output_dir.is_dir()

    def test_create_output_dir_nested_custom(self, tmp_path: Path) -> None:
        """Test creating nested custom output directory."""
        input_file = tmp_path / "test.pcap"
        input_file.touch()

        custom_output = tmp_path / "level1" / "level2" / "output"
        output_dir = OutputManager.create_output_dir(input_file, custom_output)

        assert output_dir == custom_output
        assert output_dir.exists()
        assert output_dir.is_dir()

    def test_create_output_dir_already_exists(self, tmp_path: Path) -> None:
        """Test creating output directory when it already exists."""
        input_file = tmp_path / "test.pcap"
        input_file.touch()

        output_dir = tmp_path / "statistics"
        output_dir.mkdir()

        # Should not raise error
        result = OutputManager.create_output_dir(input_file)

        assert result == output_dir
        assert output_dir.exists()

    def test_get_output_path(self, tmp_path: Path) -> None:
        """Test generating output file path."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        path = OutputManager.get_output_path(
            output_dir, "test", 1, "tcp-conversations.txt"
        )

        assert path == output_dir / "test-1-tcp-conversations.txt"

    def test_get_output_path_with_sequence(self, tmp_path: Path) -> None:
        """Test generating output file path with different sequences."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        path1 = OutputManager.get_output_path(output_dir, "test", 1, "stats.txt")
        path2 = OutputManager.get_output_path(output_dir, "test", 2, "stats.txt")

        assert path1 == output_dir / "test-1-stats.txt"
        assert path2 == output_dir / "test-2-stats.txt"

    def test_get_base_name_pcap(self) -> None:
        """Test extracting base name from .pcap file."""
        input_file = Path("test.pcap")

        base_name = OutputManager.get_base_name(input_file)

        assert base_name == "test"

    def test_get_base_name_pcapng(self) -> None:
        """Test extracting base name from .pcapng file."""
        input_file = Path("test.pcapng")

        base_name = OutputManager.get_base_name(input_file)

        assert base_name == "test"

    def test_get_base_name_with_path(self) -> None:
        """Test extracting base name from file with path."""
        input_file = Path("/path/to/data.pcap")

        base_name = OutputManager.get_base_name(input_file)

        assert base_name == "data"

    def test_get_base_name_complex_name(self) -> None:
        """Test extracting base name from complex filename."""
        input_file = Path("my-test-file.pcap")

        base_name = OutputManager.get_base_name(input_file)

        assert base_name == "my-test-file"

    def test_get_base_name_no_extension(self) -> None:
        """Test extracting base name from file without pcap extension."""
        input_file = Path("test.txt")

        base_name = OutputManager.get_base_name(input_file)

        assert base_name == "test.txt"

    def test_get_base_name_multiple_dots(self) -> None:
        """Test extracting base name from filename with multiple dots."""
        input_file = Path("test.backup.pcap")

        base_name = OutputManager.get_base_name(input_file)

        assert base_name == "test.backup"

