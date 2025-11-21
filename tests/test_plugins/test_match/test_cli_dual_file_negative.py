"""CLI-level negative tests for Match plugin dual-file input validation."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


@pytest.mark.integration
class TestMatchCLIDualFileValidation:
    """Validate dual-file input handling at the match CLI layer."""

    def _run_match(self, extra_args: list[str]) -> subprocess.CompletedProcess:
        """Helper to run `python -m capmaster match` with given arguments."""
        cmd = ["python", "-m", "capmaster", "match"] + extra_args
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_cli_missing_dual_file_input(self):
        """Should require either -i/--input or both --file1/--file2."""
        result = self._run_match([])

        assert result.returncode != 0
        assert "Must provide either -i/--input or both --file1 and --file2" in result.stderr

    def test_cli_input_and_dual_file_mutually_exclusive(self, tmp_path: Path):
        """-i/--input cannot be used together with --file1/--file2."""
        pcap_dir = tmp_path / "pcaps"
        pcap_dir.mkdir()

        file1 = pcap_dir / "file1.pcap"
        file2 = pcap_dir / "file2.pcap"
        file1.touch()
        file2.touch()

        result = self._run_match(
            [
                "-i",
                str(pcap_dir),
                "--file1",
                str(file1),
                "--file1-pcapid",
                "0",
                "--file2",
                str(file2),
                "--file2-pcapid",
                "1",
                "-o",
                str(tmp_path / "output.txt"),
            ]
        )

        assert result.returncode != 0
        assert "Cannot use both -i/--input and --file1/--file2 at the same time" in result.stderr

    def test_cli_dual_file_missing_pcapid(self, tmp_path: Path):
        """When using --file1/--file2, both pcapid options are required."""
        file1 = tmp_path / "file1.pcap"
        file2 = tmp_path / "file2.pcap"
        file1.touch()
        file2.touch()

        result = self._run_match(
            [
                "--file1",
                str(file1),
                "--file2",
                str(file2),
                "-o",
                str(tmp_path / "output.txt"),
            ]
        )

        assert result.returncode != 0
        assert (
            "Both --file1-pcapid and --file2-pcapid must be provided when using --file1/--file2"
            in result.stderr
        )

    def test_cli_dual_file_invalid_pcapid(self, tmp_path: Path):
        """PCAP IDs must be 0 or 1 when using dual-file input mode."""
        file1 = tmp_path / "file1.pcap"
        file2 = tmp_path / "file2.pcap"
        file1.touch()
        file2.touch()

        result = self._run_match(
            [
                "--file1",
                str(file1),
                "--file1-pcapid",
                "2",  # Invalid
                "--file2",
                str(file2),
                "--file2-pcapid",
                "0",
                "-o",
                str(tmp_path / "output.txt"),
            ]
        )

        assert result.returncode != 0
        assert "--file1-pcapid must be 0 or 1" in result.stderr

