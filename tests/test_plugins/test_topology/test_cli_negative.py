from __future__ import annotations

"""CLI-level negative tests for topology plugin input validation."""

import subprocess
from pathlib import Path

import pytest


@pytest.mark.integration
class TestTopologyCLIInputValidation:
    """Validate input handling at the topology CLI layer."""

    def _run_topology(self, extra_args: list[str]) -> subprocess.CompletedProcess:
        """Helper to run `python -m capmaster topology` with given arguments."""
        import sys
        cmd = [sys.executable, "-m", "capmaster", "topology"] + extra_args
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_cli_requires_some_input(self) -> None:
        """Running without any input options should be rejected."""

        result = self._run_topology([])

        assert result.returncode != 0
        assert "Input file count mismatch" in result.stderr

    def test_cli_input_and_dual_file_mutually_exclusive(self, tmp_path: Path) -> None:
        """-i/--input cannot be used together with --file1/--file2."""

        pcap_dir = tmp_path / "pcaps"
        pcap_dir.mkdir()

        file1 = pcap_dir / "file1.pcap"
        file2 = pcap_dir / "file2.pcap"
        file1.touch()
        file2.touch()

        result = self._run_topology(
            [
                "-i",
                str(pcap_dir),
                "--file1",
                str(file1),
                "--file2",
                str(file2),
            ]
        )

        assert result.returncode != 0
        assert "Cannot use both -i/--input and --fileX arguments" in result.stderr



