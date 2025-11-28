"""Integration tests for streamdiff plugin using 2hops cases.

These tests exercise the happy-path end-to-end flow:

- run `capmaster match` on a 2hops case directory to produce matched-connections
- pick the first matched pair (pair-index=1)
- run `capmaster streamdiff` on the same case using that matched-connections file
- assert that streamdiff exits successfully and prints a report header

Tests will be automatically skipped if the local `2hops/` directory is not
present (since these PCAPs are not part of the repository).
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest


BASE_2HOPS_DIR = Path("2hops")


def _have_2hops_data() -> bool:
    return BASE_2HOPS_DIR.is_dir()


@pytest.mark.integration
@pytest.mark.skipif(not _have_2hops_data(), reason="2hops directory not present; skipping integration tests")
class TestStreamDiff2Hops:
    """End-to-end streamdiff integration tests on real 2hops cases."""

    def _run_match(self, case_dir: Path, out_file: Path) -> None:
        """Run `capmaster match` on a case directory and write human text output.

        We use the Markdown-style text output as the matched-connections source
        because it is stable and already consumed by parse_matched_connections.
        """

        cmd = [
            sys.executable,
            "-m",
            "capmaster",
            "match",
            "-i",
            str(case_dir),
            "-o",
            str(out_file),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert (
            result.returncode == 0
        ), f"match failed on {case_dir} with rc={result.returncode}, stderr={result.stderr}"
        assert out_file.is_file(), f"match did not create output file: {out_file}"

    def _run_streamdiff(self, case_dir: Path, matched_file: Path) -> str:
        """Run streamdiff with matched-connections and return its stdout.

        We use `--pair-index 1` simply to prove the happy path wiring from
        match -> matched-connections -> streamdiff -> report generation.
        """

        cmd = [
            sys.executable,
            "-m",
            "capmaster",
            "streamdiff",
            "-i",
            str(case_dir),
            "--matched-connections",
            str(matched_file),
            "--pair-index",
            "1",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert (
            result.returncode == 0
        ), f"streamdiff failed on {case_dir} with rc={result.returncode}, stderr={result.stderr}"
        assert result.stdout, "streamdiff produced empty stdout report"
        return result.stdout

    @pytest.mark.parametrize(
        "case_name",
        [
            "TC-001-1-20160407",
            "TC-034-3-20210604-O",
            "dbs_1112_2",
        ],
    )
    def test_streamdiff_runs_on_case_and_outputs_report(self, tmp_path: Path, case_name: str) -> None:
        """Smoke test: streamdiff runs successfully on several 2hops cases.

        This does not assert detailed packet counts; it only verifies that the
        plumbing from match -> streamdiff works and a report header is printed.
        """

        case_dir = BASE_2HOPS_DIR / case_name
        if not case_dir.is_dir():
            pytest.skip(f"2hops case directory not found: {case_dir}")

        match_out = tmp_path / f"{case_name}_match.txt"
        self._run_match(case_dir, match_out)

        report = self._run_streamdiff(case_dir, match_out)

        assert "streamdiff report: A-only/B-only packets" in report
        assert "Capture A:" in report
        assert "Capture B:" in report
        # Summary must mention both A-only and B-only counts
        assert "A-only packets" in report
        assert "B-only packets" in report

