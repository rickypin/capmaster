"""Tests for clean plugin."""

from pathlib import Path

import pytest

from capmaster.plugins.clean.plugin import (
    CleanPlugin,
    _find_statistics_dirs,
    _format_size,
    _get_dir_size,
)


@pytest.mark.integration
class TestCleanPlugin:
    """Test cases for CleanPlugin."""

    def test_plugin_name(self) -> None:
        """Test plugin name."""
        plugin = CleanPlugin()
        assert plugin.name == "clean"

    def test_find_statistics_dirs_recursive(self, tmp_path: Path) -> None:
        """Test finding statistics directories recursively."""
        # Create directory structure
        (tmp_path / "dir1" / "statistics").mkdir(parents=True)
        (tmp_path / "dir2" / "statistics").mkdir(parents=True)
        (tmp_path / "dir1" / "subdir" / "statistics").mkdir(parents=True)
        (tmp_path / "other").mkdir()

        # Find statistics directories
        stats_dirs = _find_statistics_dirs(tmp_path, recursive=True)

        assert len(stats_dirs) == 3
        assert tmp_path / "dir1" / "statistics" in stats_dirs
        assert tmp_path / "dir2" / "statistics" in stats_dirs
        assert tmp_path / "dir1" / "subdir" / "statistics" in stats_dirs

    def test_find_statistics_dirs_non_recursive(self, tmp_path: Path) -> None:
        """Test finding statistics directories non-recursively."""
        # Create directory structure
        (tmp_path / "statistics").mkdir()
        (tmp_path / "dir1" / "statistics").mkdir(parents=True)

        # Find statistics directories (non-recursive)
        stats_dirs = _find_statistics_dirs(tmp_path, recursive=False)

        assert len(stats_dirs) == 1
        assert tmp_path / "statistics" in stats_dirs

    def test_find_statistics_dirs_none_found(self, tmp_path: Path) -> None:
        """Test when no statistics directories exist."""
        (tmp_path / "dir1").mkdir()
        (tmp_path / "dir2").mkdir()

        stats_dirs = _find_statistics_dirs(tmp_path, recursive=True)

        assert len(stats_dirs) == 0

    def test_find_statistics_dirs_nonexistent_path(self, tmp_path: Path) -> None:
        """Test with non-existent path."""
        nonexistent = tmp_path / "does_not_exist"

        stats_dirs = _find_statistics_dirs(nonexistent, recursive=True)

        assert len(stats_dirs) == 0

    def test_get_dir_size(self, tmp_path: Path) -> None:
        """Test calculating directory size."""
        stats_dir = tmp_path / "statistics"
        stats_dir.mkdir()

        # Create some files
        (stats_dir / "file1.txt").write_text("Hello" * 100)  # 500 bytes
        (stats_dir / "file2.txt").write_text("World" * 200)  # 1000 bytes

        size = _get_dir_size(stats_dir)

        assert size == 1500

    def test_get_dir_size_with_subdirs(self, tmp_path: Path) -> None:
        """Test calculating directory size with subdirectories."""
        stats_dir = tmp_path / "statistics"
        stats_dir.mkdir()
        (stats_dir / "subdir").mkdir()

        (stats_dir / "file1.txt").write_text("A" * 100)
        (stats_dir / "subdir" / "file2.txt").write_text("B" * 200)

        size = _get_dir_size(stats_dir)

        assert size == 300

    def test_get_dir_size_empty_dir(self, tmp_path: Path) -> None:
        """Test calculating size of empty directory."""
        stats_dir = tmp_path / "statistics"
        stats_dir.mkdir()

        size = _get_dir_size(stats_dir)

        assert size == 0

    def test_format_size_bytes(self) -> None:
        """Test formatting size in bytes."""
        assert _format_size(500) == "500.00 B"

    def test_format_size_kilobytes(self) -> None:
        """Test formatting size in kilobytes."""
        assert _format_size(1024) == "1.00 KB"
        assert _format_size(1536) == "1.50 KB"

    def test_format_size_megabytes(self) -> None:
        """Test formatting size in megabytes."""
        assert _format_size(1024 * 1024) == "1.00 MB"
        assert _format_size(1024 * 1024 * 2.5) == "2.50 MB"

    def test_format_size_gigabytes(self) -> None:
        """Test formatting size in gigabytes."""
        assert _format_size(1024 * 1024 * 1024) == "1.00 GB"

    def test_execute_dry_run(self, tmp_path: Path) -> None:
        """Test execute with dry run."""
        # Create statistics directory
        stats_dir = tmp_path / "statistics"
        stats_dir.mkdir()
        (stats_dir / "file.txt").write_text("test")

        plugin = CleanPlugin()
        exit_code = plugin.execute(
            input_path=tmp_path,
            recursive=True,
            dry_run=True,
            auto_confirm=True,
        )

        # Should succeed
        assert exit_code == 0

        # Directory should still exist (dry run)
        assert stats_dir.exists()

    def test_execute_delete_with_auto_confirm(self, tmp_path: Path) -> None:
        """Test execute with actual deletion (auto-confirm)."""
        # Create statistics directory
        stats_dir = tmp_path / "statistics"
        stats_dir.mkdir()
        (stats_dir / "file.txt").write_text("test")

        plugin = CleanPlugin()
        exit_code = plugin.execute(
            input_path=tmp_path,
            recursive=True,
            dry_run=False,
            auto_confirm=True,
        )

        # Should succeed
        assert exit_code == 0

        # Directory should be deleted
        assert not stats_dir.exists()

    def test_execute_multiple_directories(self, tmp_path: Path) -> None:
        """Test execute with multiple statistics directories."""
        # Create multiple statistics directories
        (tmp_path / "dir1" / "statistics").mkdir(parents=True)
        (tmp_path / "dir2" / "statistics").mkdir(parents=True)
        (tmp_path / "dir1" / "statistics" / "file1.txt").write_text("test1")
        (tmp_path / "dir2" / "statistics" / "file2.txt").write_text("test2")

        plugin = CleanPlugin()
        exit_code = plugin.execute(
            input_path=tmp_path,
            recursive=True,
            dry_run=False,
            auto_confirm=True,
        )

        # Should succeed
        assert exit_code == 0

        # Both directories should be deleted
        assert not (tmp_path / "dir1" / "statistics").exists()
        assert not (tmp_path / "dir2" / "statistics").exists()

        # Parent directories should still exist
        assert (tmp_path / "dir1").exists()
        assert (tmp_path / "dir2").exists()

    def test_execute_no_statistics_dirs(self, tmp_path: Path) -> None:
        """Test execute when no statistics directories exist."""
        (tmp_path / "dir1").mkdir()

        plugin = CleanPlugin()
        exit_code = plugin.execute(
            input_path=tmp_path,
            recursive=True,
            dry_run=False,
            auto_confirm=True,
        )

        # Should succeed (nothing to delete)
        assert exit_code == 0

    def test_execute_non_recursive(self, tmp_path: Path) -> None:
        """Test execute with non-recursive mode."""
        # Create statistics directories
        (tmp_path / "statistics").mkdir()
        (tmp_path / "dir1" / "statistics").mkdir(parents=True)
        (tmp_path / "statistics" / "file.txt").write_text("test")
        (tmp_path / "dir1" / "statistics" / "file.txt").write_text("test")

        plugin = CleanPlugin()
        exit_code = plugin.execute(
            input_path=tmp_path,
            recursive=False,
            dry_run=False,
            auto_confirm=True,
        )

        # Should succeed
        assert exit_code == 0

        # Only top-level statistics should be deleted
        assert not (tmp_path / "statistics").exists()
        assert (tmp_path / "dir1" / "statistics").exists()

