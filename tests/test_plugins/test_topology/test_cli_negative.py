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

        cmd = ["python", "-m", "capmaster", "topology"] + extra_args
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_cli_requires_some_input(self) -> None:
        """Running without any input options should be rejected."""

        result = self._run_topology([])

        assert result.returncode != 0
        assert "No input specified." in result.stderr

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
        assert "Cannot combine -i/--input with --file1/--file2." in result.stderr

    def test_cli_dual_file_requires_both_files(self, tmp_path: Path) -> None:
        """When using --file1/--file2, both options are required."""

        file1 = tmp_path / "file1.pcap"
        file1.touch()

        result = self._run_topology([
            "--file1",
            str(file1),
        ])

        assert result.returncode != 0
        assert "Both --file1 and --file2 must be specified for dual capture analysis." in result.stderr

