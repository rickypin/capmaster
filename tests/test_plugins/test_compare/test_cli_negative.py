"""CLI-level negative tests for Compare plugin input validation."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


@pytest.mark.integration
class TestCompareCLIInputValidation:
    """Validate input handling at the compare CLI layer."""

    def _run_compare(self, extra_args: list[str]) -> subprocess.CompletedProcess:
        """Helper to run `python -m capmaster compare` with given arguments."""
        import sys
        cmd = [sys.executable, "-m", "capmaster", "compare"] + extra_args
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_cli_missing_input(self):
        """Should require input."""
        result = self._run_compare([])

        assert result.returncode != 0
        assert "Input file count mismatch" in result.stderr or "Missing option" in result.stderr or "Error" in result.stderr or "No valid input files found" in result.stderr

    def test_cli_input_and_file_args_mutually_exclusive(self, tmp_path: Path):
        """-i/--input cannot be used together with --fileX."""
        pcap_dir = tmp_path / "pcaps"
        pcap_dir.mkdir()

        file1 = pcap_dir / "file1.pcap"
        file1.touch()

        result = self._run_compare(
            [
                "-i",
                str(pcap_dir),
                "--file1",
                str(file1),
                "--quiet",
            ]
        )

        assert result.returncode != 0
        assert "Cannot use both -i/--input and --fileX arguments" in result.stderr

    def test_cli_too_many_files(self, tmp_path: Path):
        """Should fail if more than 6 files are provided."""
        files = []
        for i in range(7):
            f = tmp_path / f"file{i}.pcap"
            f.write_bytes(b"dummy content")
            files.append(str(f))
        
        input_str = ",".join(files)

        result = self._run_compare(
            [
                "-i",
                input_str,
                "--quiet",
            ]
        )

        assert result.returncode != 0
        assert "Too many input files" in result.stderr

