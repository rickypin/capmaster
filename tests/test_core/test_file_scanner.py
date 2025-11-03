"""Tests for PcapScanner."""

import tempfile
from pathlib import Path

import pytest

from capmaster.core.file_scanner import PcapScanner


class TestPcapScanner:
    """Test cases for PcapScanner."""

    def test_is_valid_pcap_with_pcap_extension(self, tmp_path: Path) -> None:
        """Test validation of .pcap file."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"dummy content")

        assert PcapScanner.is_valid_pcap(pcap_file) is True

    def test_is_valid_pcap_with_pcapng_extension(self, tmp_path: Path) -> None:
        """Test validation of .pcapng file."""
        pcap_file = tmp_path / "test.pcapng"
        pcap_file.write_bytes(b"dummy content")

        assert PcapScanner.is_valid_pcap(pcap_file) is True

    def test_is_valid_pcap_with_invalid_extension(self, tmp_path: Path) -> None:
        """Test validation fails for non-PCAP extension."""
        txt_file = tmp_path / "test.txt"
        txt_file.write_bytes(b"dummy content")

        assert PcapScanner.is_valid_pcap(txt_file) is False

    def test_is_valid_pcap_with_empty_file(self, tmp_path: Path) -> None:
        """Test validation fails for empty file."""
        pcap_file = tmp_path / "empty.pcap"
        pcap_file.touch()

        assert PcapScanner.is_valid_pcap(pcap_file) is False

    def test_is_valid_pcap_case_insensitive(self, tmp_path: Path) -> None:
        """Test validation is case-insensitive for extensions."""
        pcap_file = tmp_path / "test.PCAP"
        pcap_file.write_bytes(b"dummy content")

        assert PcapScanner.is_valid_pcap(pcap_file) is True

    def test_scan_single_file(self, tmp_path: Path) -> None:
        """Test scanning a single PCAP file."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"dummy content")

        files = PcapScanner.scan([str(pcap_file)])

        assert len(files) == 1
        assert files[0] == pcap_file

    def test_scan_nonexistent_file(self) -> None:
        """Test scanning a nonexistent file raises error."""
        with pytest.raises(FileNotFoundError):
            PcapScanner.scan(["/nonexistent/file.pcap"])

    def test_scan_directory_non_recursive(self, tmp_path: Path) -> None:
        """Test scanning a directory without recursion."""
        # Create files in root
        pcap1 = tmp_path / "test1.pcap"
        pcap1.write_bytes(b"content1")
        pcap2 = tmp_path / "test2.pcapng"
        pcap2.write_bytes(b"content2")
        txt_file = tmp_path / "readme.txt"
        txt_file.write_bytes(b"text")

        # Create subdirectory with file (should be ignored)
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        pcap3 = subdir / "test3.pcap"
        pcap3.write_bytes(b"content3")

        files = PcapScanner.scan([str(tmp_path)], recursive=False)

        assert len(files) == 2
        assert pcap1 in files
        assert pcap2 in files
        assert pcap3 not in files

    def test_scan_directory_recursive(self, tmp_path: Path) -> None:
        """Test scanning a directory with recursion."""
        # Create files in root
        pcap1 = tmp_path / "test1.pcap"
        pcap1.write_bytes(b"content1")

        # Create subdirectory with files
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        pcap2 = subdir / "test2.pcap"
        pcap2.write_bytes(b"content2")

        # Create nested subdirectory
        nested = subdir / "nested"
        nested.mkdir()
        pcap3 = nested / "test3.pcapng"
        pcap3.write_bytes(b"content3")

        files = PcapScanner.scan([str(tmp_path)], recursive=True)

        assert len(files) == 3
        assert pcap1 in files
        assert pcap2 in files
        assert pcap3 in files

    def test_scan_multiple_paths(self, tmp_path: Path) -> None:
        """Test scanning multiple paths."""
        dir1 = tmp_path / "dir1"
        dir1.mkdir()
        pcap1 = dir1 / "test1.pcap"
        pcap1.write_bytes(b"content1")

        dir2 = tmp_path / "dir2"
        dir2.mkdir()
        pcap2 = dir2 / "test2.pcap"
        pcap2.write_bytes(b"content2")

        files = PcapScanner.scan([str(dir1), str(dir2)])

        assert len(files) == 2
        assert pcap1 in files
        assert pcap2 in files

    def test_scan_removes_duplicates(self, tmp_path: Path) -> None:
        """Test scanning removes duplicate files."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"content")

        # Scan the same file twice
        files = PcapScanner.scan([str(pcap_file), str(pcap_file)])

        assert len(files) == 1
        assert files[0] == pcap_file

    def test_scan_returns_sorted_results(self, tmp_path: Path) -> None:
        """Test scanning returns sorted results."""
        pcap_c = tmp_path / "c.pcap"
        pcap_c.write_bytes(b"content")
        pcap_a = tmp_path / "a.pcap"
        pcap_a.write_bytes(b"content")
        pcap_b = tmp_path / "b.pcap"
        pcap_b.write_bytes(b"content")

        files = PcapScanner.scan([str(tmp_path)])

        assert files == [pcap_a, pcap_b, pcap_c]

    def test_scan_ignores_invalid_files(self, tmp_path: Path) -> None:
        """Test scanning ignores invalid files."""
        valid_pcap = tmp_path / "valid.pcap"
        valid_pcap.write_bytes(b"content")

        empty_pcap = tmp_path / "empty.pcap"
        empty_pcap.touch()

        txt_file = tmp_path / "readme.txt"
        txt_file.write_bytes(b"text")

        files = PcapScanner.scan([str(tmp_path)])

        assert len(files) == 1
        assert files[0] == valid_pcap

