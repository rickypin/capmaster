"""Additional integration tests for the preprocess plugin.

These tests focus on covering extra combinations of the
``dedup``, ``time-align`` and ``oneway`` flags using
real-world troubleshooting cases copied into
``tests/preprocess_cases``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from capmaster.plugins.preprocess.config import (
    PreprocessConfig,
    PreprocessRuntimeConfig,
    ToolsConfig,
)
from capmaster.plugins.preprocess.pcap_tools import get_packet_count, get_time_range
from capmaster.plugins.preprocess.pipeline import run_preprocess
from capmaster.plugins.preprocess.oneway_tools import detect_one_way_streams


# Root directory containing copied troubleshooting cases used as test data.
CASES_ROOT = Path(__file__).resolve().parents[2] / "preprocess_cases"

# Mark all tests in this module as integration tests.
pytestmark = pytest.mark.integration


def _ensure_case_dir(case_name: str) -> Path:
    """Return the case directory or skip if it is missing.

    This mirrors the behaviour in ``test_integration.py``: if the
    local developer/CI environment has not populated the
    ``tests/preprocess_cases`` directory, the tests are skipped
    instead of failing.
    """

    case_dir = CASES_ROOT / case_name
    if not case_dir.is_dir():
        pytest.skip(
            f"{case_name} case directory is missing; populate tests/preprocess_cases "
            "according to the preprocess design document before enabling this test.",
        )
    return case_dir


def test_tc0541_no_steps_pipeline_is_noop(tmp_path: Path) -> None:
    """All preprocess steps disabled should behave as a no-op (TC-054-1-20230825).

    This test explicitly disables ``dedup``, ``time-align`` and
    ``oneway`` so that the pipeline effectively copies input PCAPs
    to ``*.ready.pcap[ng]`` while still generating a report.
    Packet counts must remain unchanged.
    """

    case_dir = _ensure_case_dir("TC-054-1-20230825")

    originals = sorted(
        p for p in case_dir.iterdir() if p.suffix in {".pcap", ".pcapng"}
    )
    if not originals:
        pytest.skip(
            "No PCAP files found for TC-054-1-20230825; populate tests/preprocess_cases "
            "according to the design document before enabling this test.",
        )

    tools = ToolsConfig()
    preprocess_cfg = PreprocessConfig(
        dedup_enabled=False,
        oneway_enabled=False,
        time_align_enabled=False,
        archive_original_files=False,
    )
    runtime = PreprocessRuntimeConfig(tools=tools, preprocess=preprocess_cfg)

    output_dir = tmp_path / "out"
    final_files = run_preprocess(
        runtime=runtime,
        input_files=originals,
        output_dir=output_dir,
    )

    assert len(final_files) == len(originals)

    for original, final in zip(originals, final_files):
        orig_count = get_packet_count(tools=tools, input_file=original)
        final_count = get_packet_count(tools=tools, input_file=final)
        # With all steps disabled, preprocess must not change packet counts.
        assert final_count == orig_count

    report_path = output_dir / "preprocess_report.md"
    assert report_path.is_file(), "Expected preprocess_report.md to be generated"

    # No archive directory should be created when all steps are disabled.
    assert not (output_dir / "archive").exists()


def test_tc0612_time_align_and_oneway(tmp_path: Path) -> None:
    """Time-align + oneway filtering on ESB multi-node case (TC-061-2-20240316).

    This test exercises the ``time-align`` and ``oneway`` steps together,
    without ``dedup``. It validates both the "effective" case where there
    is a clear overlap and one-way traffic, and the "no-op" cases where
    there is no overlap and/or no one-way streams.
    """

    case_name = "TC-061-2-20240316"
    case_dir = _ensure_case_dir(case_name)

    originals = sorted(
        p for p in case_dir.iterdir() if p.suffix in {".pcap", ".pcapng"}
    )
    if len(originals) < 2:
        pytest.skip(
            f"Need at least two PCAP files for {case_name} to test time-align + oneway.",
        )

    tools = ToolsConfig()
    preprocess_cfg = PreprocessConfig(
        dedup_enabled=False,
        oneway_enabled=True,
        time_align_enabled=True,
        archive_original_files=False,
    )
    runtime = PreprocessRuntimeConfig(tools=tools, preprocess=preprocess_cfg)

    # Baseline time ranges and one-way stream count.
    original_ranges = [
        get_time_range(tools=tools, input_file=p) for p in originals
    ]
    t_start = max(r.first_ts for r in original_ranges)
    t_end = min(r.last_ts for r in original_ranges)
    has_overlap = t_start < t_end

    baseline_oneway = 0
    for src in originals:
        baseline_oneway += len(
            detect_one_way_streams(
                input_file=src,
                ack_threshold=preprocess_cfg.oneway_ack_threshold,
            ),
        )
    has_oneway = baseline_oneway > 0

    output_dir = tmp_path / "out"
    final_files = run_preprocess(
        runtime=runtime,
        input_files=originals,
        output_dir=output_dir,
        steps=["time-align", "oneway"],
    )

    assert len(final_files) == len(originals)

    total_orig = 0
    total_final = 0
    trimmed_any = False

    for original, final, orig_range in zip(originals, final_files, original_ranges):
        orig_count = get_packet_count(tools=tools, input_file=original)
        final_count = get_packet_count(tools=tools, input_file=final)
        # Neither time-align nor oneway should ever increase packet counts.
        assert final_count <= orig_count
        total_orig += orig_count
        total_final += final_count

        final_range = get_time_range(tools=tools, input_file=final)

        if has_overlap:
            # Final ranges should fall within the overall intersection window
            # and not extend beyond the original ranges.
            assert final_range.first_ts >= t_start - 1e-3
            assert final_range.last_ts <= t_end + 1e-3
            assert final_range.first_ts < final_range.last_ts
            assert final_range.first_ts >= orig_range.first_ts
            assert final_range.last_ts <= orig_range.last_ts

            if (
                final_range.first_ts > orig_range.first_ts
                or final_range.last_ts < orig_range.last_ts
            ):
                trimmed_any = True
        else:
            # No global overlap: time-align step should have behaved as a no-op
            # and left each file's time range unchanged.
            assert final_range.first_ts == pytest.approx(orig_range.first_ts, rel=0, abs=1e-3)
            assert final_range.last_ts == pytest.approx(orig_range.last_ts, rel=0, abs=1e-3)

    if has_overlap:
        # When we do have a clear overlap, at least one file should be visibly
        # trimmed by time-align.
        assert trimmed_any

    # Packet counts should only decrease when there is actual one-way traffic
    # to remove; otherwise the step acts as a no-op.
    if has_oneway:
        assert total_final < total_orig

    remaining_oneway = 0
    for final in final_files:
        remaining_oneway += len(
            detect_one_way_streams(
                input_file=final,
                ack_threshold=preprocess_cfg.oneway_ack_threshold,
            ),
        )

    if has_oneway:
        assert remaining_oneway < baseline_oneway
    else:
        assert remaining_oneway == 0

    report_path = output_dir / "preprocess_report.md"
    assert report_path.is_file(), "Expected preprocess_report.md to be generated"

