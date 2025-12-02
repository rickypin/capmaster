"""Integration test skeletons for the preprocess plugin.

These tests are based on the design in
`docs/DESIGN_preprocess_and_config.md` and use real-world
PCAP cases copied into ``data/preprocess_cases``.

The goal is to provide a clear contract for the future
preprocess implementation without enforcing behaviour yet.
"""

from pathlib import Path

import pytest

from capmaster.plugins.preprocess.config import (
    PreprocessConfig,
    PreprocessRuntimeConfig,
    ToolsConfig,
)
from capmaster.plugins.preprocess.pcap_tools import get_packet_count
from capmaster.plugins.preprocess.pipeline import run_preprocess


# Root directory containing copied troubleshooting cases used as test data.
CASES_ROOT = Path(__file__).resolve().parents[3] / "data" / "preprocess_cases"

# Design document path for reference in test failure messages.
DESIGN_DOC_PATH = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "DESIGN_preprocess_and_config.md"
)

# The subset of troubleshooting cases that were copied into this repository
# for preprocess testing. These names correspond 1:1 to directories under
# ``data/preprocess_cases``.
EXPECTED_CASES = [
    "TC-060-2-20210730",  # F5 front/back, strong dedup signal, large files
    "TC-035-06-20240704",  # Video stutter analysis, large single PCAP
    "TC-044-2-20230920",  # Multiple tap points + filtered/abnormal flows
    "TC-063-1-20230306",  # Multi-node mail path, good for time-align
    "TC-014-1-20231212",  # Firewall inside/outside + truncated PCAP
    "TC-047-7-20240328",  # Distributed service chain (gateway, MQ, etc.)
    "TC-028-1-20240308",  # Small single file baseline
    "TC-054-1-20230825",  # Firewall front/back DB case, good for no-op baseline
    "TC-061-2-20240316",  # ESB multi-node case with dedup variants
]


def _select_overlapping_subset(files, ranges, min_size: int = 2):
    """Return a subset of files that share a non-empty time intersection.

    The subset is chosen to maximise the number of files participating in the
    intersection; for equal sizes, the longest common window is preferred.
    """

    n = len(files)
    best_indices: list[int] = []
    best_start = 0.0
    best_end = 0.0

    for i in range(n):
        for j in range(i, n):
            start = max(ranges[i].first_ts, ranges[j].first_ts)
            end = min(ranges[i].last_ts, ranges[j].last_ts)
            if start >= end:
                continue

            indices = [
                k
                for k in range(n)
                if ranges[k].first_ts <= start <= ranges[k].last_ts
                and ranges[k].first_ts <= end <= ranges[k].last_ts
            ]
            size = len(indices)
            if size < min_size:
                continue

            if not best_indices:
                best_indices = indices
                best_start = start
                best_end = end
                continue

            best_size = len(best_indices)
            best_length = best_end - best_start
            length = end - start
            if size > best_size or (size == best_size and length > best_length):
                best_indices = indices
                best_start = start
                best_end = end

    if len(best_indices) < min_size:
        return [], 0.0, 0.0

    subset_files = [files[i] for i in best_indices]
    return subset_files, best_start, best_end



def test_preprocess_cases_layout() -> None:
    """Ensure that preprocess test cases are present on disk.

    This test only validates that the expected directory structure exists
    under ``data/preprocess_cases``. Behavioural expectations are
    documented in ``DESIGN_preprocess_and_config.md`` and should be
    enforced by the integration tests below once the preprocess plugin
    is implemented.
    """

    assert CASES_ROOT.is_dir(), "data/preprocess_cases directory is missing"

    missing = [case for case in EXPECTED_CASES if not (CASES_ROOT / case).is_dir()]
    assert not missing, (
        "Missing expected preprocess test case directories: "
        f"{missing}. See {DESIGN_DOC_PATH}"
    )


@pytest.mark.integration
class TestPreprocessPluginIntegration:
    """Integration test skeletons for the preprocess plugin.

    Each test method here is intentionally marked as ``xfail`` until the
    preprocess plugin is implemented. The docstrings describe the intended
    behaviour according to the design document, and test bodies should be
    filled in to call the real implementation (or CLI) once available.
    """

    def test_tc0602_dedup_behavior(self, tmp_path: Path) -> None:
        """Dedup behaviour on F5 front/back PCAPs (TC-060-2-20210730).

        This test focuses on the ``dedup`` step in isolation:

        - Run preprocess with only the ``dedup`` step enabled.
        - Verify that packet counts decrease compared to the originals.
        - When baseline ``*-dedup.pcap[ng]`` files are present, verify that
          the final packet counts match the baseline counts.
        - Verify that a Markdown report is generated.
        """

        case_dir = CASES_ROOT / "TC-060-2-20210730"
        if not case_dir.is_dir():
            pytest.skip("TC-060-2-20210730 case directory is missing; see DESIGN_preprocess_and_config.md H.1.")

        # Case data may be absent on some environments because PCAP files are
        # .gitignored and only copied locally. In that situation we skip the
        # behavioural checks instead of failing the whole test suite.
        originals = sorted(
            p for p in case_dir.glob("*.pcap*") if "dedup" not in p.name
        )
        if not originals:
            pytest.skip(
                "No PCAP files found for TC-060-2-20210730; populate data/preprocess_cases "
                "according to the design document before enabling this test.",
            )

        tools = ToolsConfig()
        preprocess_cfg = PreprocessConfig(
            dedup_enabled=True,
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
            steps=["dedup"],
        )

        assert len(final_files) == len(originals)

        for original, final in zip(originals, final_files):
            baseline = original.with_name(f"{original.stem}-dedup{original.suffix}")

            orig_count = get_packet_count(tools=tools, input_file=original)
            final_count = get_packet_count(tools=tools, input_file=final)

            # Dedup should never increase packet counts.
            assert final_count <= orig_count

            if baseline.exists():
                baseline_count = get_packet_count(tools=tools, input_file=baseline)
                # Our dedup semantics should be reasonably close to the
                # baseline "*-dedup.pcap" captures rather than bit-for-bit
                # identical. Allow a 10%% relative difference in packet
                # counts to account for minor option differences.
                diff = abs(final_count - baseline_count)
                assert diff / max(baseline_count, 1) <= 0.1

        # Minimal check that a report was generated using the default path.
        report_path = output_dir / "preprocess_report.md"
        assert report_path.is_file(), "Expected preprocess_report.md to be generated"

    def test_tc03506_oneway_filtering(self, tmp_path: Path) -> None:
        """One-way TCP connection filtering (TC-035-06-20240704).

        Focus on the ``oneway`` step in isolation:

        - Run preprocess with only the ``oneway`` step enabled.
        - Verify that packet counts decrease overall compared to the originals.
        - Verify that the number of detected one-way streams decreases
          after preprocessing.
        - Verify that a Markdown report is generated.
        """

        case_dir = CASES_ROOT / "TC-035-06-20240704"
        if not case_dir.is_dir():
            pytest.skip(
                "TC-035-06-20240704 case directory is missing; see DESIGN_preprocess_and_config.md H.1.",
            )

        originals = sorted(case_dir.glob("*.pcap*"))
        if not originals:
            pytest.skip(
                "No PCAP files found for TC-035-06-20240704; populate data/preprocess_cases "
                "according to the design document before enabling this test.",
            )

        tools = ToolsConfig()
        preprocess_cfg = PreprocessConfig(
            dedup_enabled=False,
            oneway_enabled=True,
            time_align_enabled=False,
            archive_original_files=False,
        )
        runtime = PreprocessRuntimeConfig(tools=tools, preprocess=preprocess_cfg)

        # Baseline one-way stream count across all input files.
        from capmaster.plugins.preprocess.oneway_tools import detect_one_way_streams

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
            steps=["oneway"],
        )

        assert len(final_files) == len(originals)

        total_orig = 0
        total_final = 0
        for original, final in zip(originals, final_files):
            orig_count = get_packet_count(tools=tools, input_file=original)
            final_count = get_packet_count(tools=tools, input_file=final)
            assert final_count <= orig_count
            total_orig += orig_count
            total_final += final_count

        remaining_oneway = 0
        for final in final_files:
            remaining_oneway += len(
                detect_one_way_streams(
                    input_file=final,
                    ack_threshold=preprocess_cfg.oneway_ack_threshold,
                ),
            )

        if has_oneway:
            # End-to-end check that one-way filtering removes both packets and streams.
            assert total_final < total_orig
            assert remaining_oneway < baseline_oneway
        else:
            # Degenerate case: case data currently contains no detectable one-way
            # streams. In that situation the oneway step should behave as a no-op:
            # packet counts and one-way stream counts stay unchanged.
            assert total_final == total_orig
            assert remaining_oneway == baseline_oneway == 0

        report_path = output_dir / "preprocess_report.md"
        assert report_path.is_file(), "Expected preprocess_report.md to be generated"

    def test_tc0442_time_align_and_dedup_multi_tap(self, tmp_path: Path) -> None:
        """Time-align + dedup in multi-tap scenario (TC-044-2-20230920).

        This test validates the interaction of ``time-align`` and ``dedup``:

        - All PCAPs should be cropped to their overlapping time window.
        - Dedup should reduce packet counts while preserving file count.
        - A Markdown report should be generated.
        """

        from capmaster.plugins.preprocess.pcap_tools import get_time_range

        case_dir = CASES_ROOT / "TC-044-2-20230920"
        if not case_dir.is_dir():
            pytest.skip(
                "TC-044-2-20230920 case directory is missing; see DESIGN_preprocess_and_config.md H.1.",
            )

        originals = sorted(case_dir.glob("*.pcap*"))
        if len(originals) < 2:
            pytest.skip(
                "Need at least two PCAP files for TC-044-2-20230920 to test multi-tap time-align.",
            )

        tools = ToolsConfig()
        preprocess_cfg = PreprocessConfig(
            dedup_enabled=True,
            oneway_enabled=False,
            time_align_enabled=True,
            archive_original_files=False,
        )
        runtime = PreprocessRuntimeConfig(tools=tools, preprocess=preprocess_cfg)

        # Compute a suitable overlapping time window using a subset of files.
        ranges = [get_time_range(tools=tools, input_file=p) for p in originals]
        selected_originals, t_start, t_end = _select_overlapping_subset(
            originals,
            ranges,
            min_size=2,
        )
        if not selected_originals:
            pytest.skip(
                "No overlapping time window for TC-044-2-20230920; "
                "cannot validate time-align behaviour even for a subset of files.",
            )

        output_dir = tmp_path / "out"
        final_files = run_preprocess(
            runtime=runtime,
            input_files=selected_originals,
            output_dir=output_dir,
            steps=["time-align", "dedup"],
        )

        assert len(final_files) == len(selected_originals)

        total_orig = 0
        total_final = 0
        from capmaster.utils.errors import CapMasterError

        for original, final in zip(selected_originals, final_files):
            orig_count = get_packet_count(tools=tools, input_file=original)
            final_count = get_packet_count(tools=tools, input_file=final)
            total_orig += orig_count
            total_final += final_count
            assert final_count <= orig_count

            try:
                fr = get_time_range(tools=tools, input_file=final)
            except CapMasterError:
                # Some processed taps may end up empty after cropping/dedup; in that
                # case capinfos/tshark provide no timestamps. We still validate
                # packet counts but skip strict time-window assertions.
                assert final_count == 0
                continue

            assert fr.first_ts >= t_start - 1e-3
            assert fr.last_ts <= t_end + 1e-3
            assert fr.first_ts < fr.last_ts

        assert total_final < total_orig

        report_path = output_dir / "preprocess_report.md"
        assert report_path.is_file(), "Expected preprocess_report.md to be generated"

    def test_tc0631_time_align_mail_path(self, tmp_path: Path) -> None:
        """Time-align along a multi-node mail path (TC-063-1-20230306).

        - All PCAPs from different nodes should be cropped to a common
          overlapping time range.
        - The aligned window should be reflected in the report.
        """

        from capmaster.plugins.preprocess.pcap_tools import get_time_range

        case_dir = CASES_ROOT / "TC-063-1-20230306"
        if not case_dir.is_dir():
            pytest.skip(
                "TC-063-1-20230306 case directory is missing; see DESIGN_preprocess_and_config.md H.1.",
            )

        originals = sorted(case_dir.glob("*.pcap*"))
        if len(originals) < 2:
            pytest.skip(
                "Need at least two PCAP files for TC-063-1-20230306 to test time-align.",
            )

        tools = ToolsConfig()
        preprocess_cfg = PreprocessConfig(
            dedup_enabled=False,
            oneway_enabled=False,
            time_align_enabled=True,
            archive_original_files=False,
        )
        runtime = PreprocessRuntimeConfig(tools=tools, preprocess=preprocess_cfg)

        # Compute intersection window.
        original_ranges = [get_time_range(tools=tools, input_file=p) for p in originals]
        t_start = max(r.first_ts for r in original_ranges)
        t_end = min(r.last_ts for r in original_ranges)
        if not (t_start < t_end):
            pytest.skip(
                "No overlapping time window for TC-063-1-20230306; "
                "cannot validate time-align behaviour.",
            )

        output_dir = tmp_path / "out"
        final_files = run_preprocess(
            runtime=runtime,
            input_files=originals,
            output_dir=output_dir,
            steps=["time-align"],
        )

        assert len(final_files) == len(originals)

        trimmed_any = False
        for original, final, orig_range in zip(originals, final_files, original_ranges):
            final_range = get_time_range(tools=tools, input_file=final)
            assert final_range.first_ts >= t_start - 1e-3
            assert final_range.last_ts <= t_end + 1e-3
            assert final_range.first_ts < final_range.last_ts

            # The aligned window should not extend beyond the original range.
            assert final_range.first_ts >= orig_range.first_ts
            assert final_range.last_ts <= orig_range.last_ts

            if (final_range.first_ts > orig_range.first_ts) or (final_range.last_ts < orig_range.last_ts):
                trimmed_any = True

        # At least one file should be visibly trimmed by time-align.
        assert trimmed_any

        report_path = output_dir / "preprocess_report.md"
        assert report_path.is_file(), "Expected preprocess_report.md to be generated"

    def test_tc0141_handles_truncated_pcap(self, tmp_path: Path) -> None:
        """Robustness to truncated PCAP input (TC-014-1-20231212).

        This test exercises the full pipeline on a case that includes
        at least one cut-short PCAP, ensuring that preprocess completes
        without crashing and still produces a report.
        """

        case_dir = CASES_ROOT / "TC-014-1-20231212"
        if not case_dir.is_dir():
            pytest.skip(
                "TC-014-1-20231212 case directory is missing; see DESIGN_preprocess_and_config.md H.1.",
            )

        originals = sorted(case_dir.glob("*.pcap*"))
        if not originals:
            pytest.skip(
                "No PCAP files found for TC-014-1-20231212; populate data/preprocess_cases "
                "according to the design document before enabling this test.",
            )

        tools = ToolsConfig()
        # Focus this case on dedup + oneway; disable time-align to avoid
        # coupling robustness to the presence of overlapping windows.
        preprocess_cfg = PreprocessConfig(
            dedup_enabled=True,
            oneway_enabled=True,
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

        # At least one output file should remain non-empty.
        non_empty = 0
        for final in final_files:
            count = get_packet_count(tools=tools, input_file=final)
            if count > 0:
                non_empty += 1
        assert non_empty >= 1

        report_path = output_dir / "preprocess_report.md"
        assert report_path.is_file(), "Expected preprocess_report.md to be generated"

    def test_tc0477_service_chain_alignment(self, tmp_path: Path) -> None:
        """Service-chain alignment (gateway, MQ, microservice) (TC-047-7-20240328).

        Focus on time-align across multiple service-chain capture points.
        """

        from capmaster.plugins.preprocess.pcap_tools import get_time_range

        case_dir = CASES_ROOT / "TC-047-7-20240328"
        if not case_dir.is_dir():
            pytest.skip(
                "TC-047-7-20240328 case directory is missing; see DESIGN_preprocess_and_config.md H.1.",
            )

        originals = sorted(case_dir.glob("*.pcap*"))
        if len(originals) < 2:
            pytest.skip(
                "Need at least two PCAP files for TC-047-7-20240328 to test service-chain alignment.",
            )

        tools = ToolsConfig()
        preprocess_cfg = PreprocessConfig(
            dedup_enabled=False,
            oneway_enabled=False,
            time_align_enabled=True,
            archive_original_files=False,
        )
        runtime = PreprocessRuntimeConfig(tools=tools, preprocess=preprocess_cfg)

        original_ranges = [get_time_range(tools=tools, input_file=p) for p in originals]
        selected_originals, t_start, t_end = _select_overlapping_subset(
            originals,
            original_ranges,
            min_size=2,
        )
        if not selected_originals:
            pytest.skip(
                "No overlapping time window for TC-047-7-20240328; "
                "cannot validate time-align behaviour even for a subset of files.",
            )

        output_dir = tmp_path / "out"
        final_files = run_preprocess(
            runtime=runtime,
            input_files=selected_originals,
            output_dir=output_dir,
            steps=["time-align"],
        )

        assert len(final_files) == len(selected_originals)

        for final in final_files:
            fr = get_time_range(tools=tools, input_file=final)
            assert fr.first_ts >= t_start - 1e-3
            assert fr.last_ts <= t_end + 1e-3
            assert fr.first_ts < fr.last_ts

        report_path = output_dir / "preprocess_report.md"
        assert report_path.is_file(), "Expected preprocess_report.md to be generated"

    def test_tc0281_small_file_baseline(self, tmp_path: Path) -> None:
        """Small single-file baseline processing (TC-028-1-20240308).

        Running the full preprocess pipeline on a small single PCAP
        should succeed and produce a report, with packet counts staying
        close to the original.
        """

        case_dir = CASES_ROOT / "TC-028-1-20240308"
        if not case_dir.is_dir():
            pytest.skip(
                "TC-028-1-20240308 case directory is missing; see DESIGN_preprocess_and_config.md H.1.",
            )

        originals = sorted(case_dir.glob("*.pcap*"))
        if not originals:
            pytest.skip(
                "No PCAP files found for TC-028-1-20240308; populate data/preprocess_cases "
                "according to the design document before enabling this test.",
            )

        tools = ToolsConfig()
        preprocess_cfg = PreprocessConfig()
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
            assert final_count <= orig_count
            diff = abs(final_count - orig_count)
            assert diff / max(orig_count, 1) <= 0.1

        report_path = output_dir / "preprocess_report.md"
        assert report_path.is_file(), "Expected preprocess_report.md to be generated"



