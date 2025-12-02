"""CLI tests for comparative-analysis --packet-diff mode."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.integration
class TestComparativePacketDiffCLI:
    """Validate CLI behaviour for comparative-analysis --packet-diff mode."""

    def _run(self, extra_args: list[str]) -> subprocess.CompletedProcess:
        cmd = [sys.executable, "-m", "capmaster", "comparative-analysis"] + extra_args
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_requires_two_inputs(self, tmp_path: Path, pcap_builder) -> None:
        """packet-diff should enforce two inputs when allow-no-input is not set."""
        pcap_dir = tmp_path / "pcaps"
        pcap_dir.mkdir()
        pcap_builder().add_tcp_packet(
            "192.168.1.1",
            "10.0.0.1",
            12345,
            80,
        ).build(pcap_dir / "only_one.pcap")

        result = self._run(["--packet-diff", "-i", str(pcap_dir)])

        assert result.returncode != 0
        assert "Input file count mismatch" in result.stderr or "No valid input files" in result.stderr

    def test_packet_diff_flag_cannot_mix_with_service(self, tmp_path: Path) -> None:
        """--packet-diff cannot be combined with --service analysis."""
        topology = tmp_path / "topology.txt"
        topology.write_text("10.0.0.1:80\n")

        result = self._run(
            [
                "--packet-diff",
                "--service",
                "--topology",
                str(topology),
                "--allow-no-input",
            ]
        )

        assert result.returncode != 0
        assert "--packet-diff cannot be combined" in result.stderr

    def test_db_connection_requires_show_flow_hash(self) -> None:
        """Database options should require --show-flow-hash in packet diff mode."""
        result = self._run(
            [
                "--packet-diff",
                "--db-connection",
                "postgresql://user:pass@localhost/db",
                "--kase-id",
                "1",
                "--allow-no-input",
            ]
        )

        assert result.returncode != 0
        assert "--show-flow-hash" in result.stderr

    def test_matched_only_flag_is_accepted(self) -> None:
        """--matched-only should be accepted with packet diff mode."""
        result = self._run(
            [
                "--packet-diff",
                "--matched-only",
                "--allow-no-input",
            ]
        )

        assert result.returncode == 0

    def test_db_options_allowed_when_show_flow_hash_enabled(self) -> None:
        """Database options work when --show-flow-hash is also provided."""
        result = self._run(
            [
                "--packet-diff",
                "--show-flow-hash",
                "--db-connection",
                "postgresql://user:pass@localhost/db",
                "--kase-id",
                "1",
                "--allow-no-input",
            ]
        )

        assert result.returncode == 0
