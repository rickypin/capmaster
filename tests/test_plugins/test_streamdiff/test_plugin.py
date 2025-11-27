"""Tests for the streamdiff plugin (A-only/B-only packets per TCP stream)."""

from __future__ import annotations

from pathlib import Path

import subprocess

import pytest

from capmaster.plugins.streamdiff.plugin import StreamDiffPlugin


@pytest.mark.unit
def test_execute_requires_stream_selection(tmp_path: Path) -> None:
    """Plugin should fail with a clear error when no stream selection is provided."""

    plugin = StreamDiffPlugin()

    # Create two dummy files to satisfy DualFileInputParser, but do not provide
    # either matched-connections or explicit stream IDs. This should raise a
    # CapMasterError which is converted into a non-zero exit code.
    file1 = tmp_path / "a.pcap"
    file2 = tmp_path / "b.pcap"
    file1.write_bytes(b"dummy")
    file2.write_bytes(b"dummy")

    exit_code = plugin.execute(
        input_path=None,
        file1=file1,
        file1_pcapid=0,
        file2=file2,
        file2_pcapid=1,
    )

    assert exit_code != 0


@pytest.mark.integration
def test_cli_help_invocation() -> None:
    """Basic smoke test that the CLI command is wired and --help works."""

    result = subprocess.run(
        [
            "python",
            "-m",
            "capmaster",
            "streamdiff",
            "--help",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "streamdiff" in result.stdout
    # Help text should mention that we report only-in-A and only-in-B packets
    assert "only in A" in result.stdout or "only in B" in result.stdout

