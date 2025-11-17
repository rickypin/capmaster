from pathlib import Path

import pytest

from capmaster.plugins.preprocess.config import PreprocessConfig, PreprocessRuntimeConfig, ToolsConfig
from capmaster.plugins.preprocess.pipeline import PreprocessContext
from capmaster.plugins.preprocess.reporting import (
    maybe_write_report,
    _format_timestamp_for_report,
)


@pytest.mark.usefixtures("tmp_path")
def test_maybe_write_report_uses_human_readable_timestamps_and_filenames(tmp_path, monkeypatch):
    """Report table should show human-readable times and only filenames.

    This test patches packet count and time range helpers so that we can
    validate the formatting logic in :func:`maybe_write_report` without
    invoking external tools like capinfos/tshark.
    """

    tools = ToolsConfig()
    preprocess_cfg = PreprocessConfig()
    runtime = PreprocessRuntimeConfig(tools=tools, preprocess=preprocess_cfg)

    output_dir = tmp_path / "out"
    output_dir.mkdir(parents=True, exist_ok=True)

    tmp_dir = tmp_path / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    input_dir = tmp_path / "input"
    input_dir.mkdir(parents=True, exist_ok=True)

    original = input_dir / "example.pcap"
    original.touch()

    final = output_dir / "example.ready.pcap"
    final.touch()

    context = PreprocessContext(
        runtime=runtime,
        input_files=[original],
        output_dir=output_dir,
        tmp_dir=tmp_dir,
    )

    def fake_get_packet_count(*, tools, input_file, timeout=None):  # noqa: ARG001
        return 123

    def fake_get_time_range(*, tools, input_file, timeout=None):  # noqa: ARG001
        # Use fixed timestamps so that we can assert on the formatted output.
        from capmaster.plugins.preprocess.pcap_tools import TimeRange

        return TimeRange(first_ts=1709877640.248336, last_ts=1709877649.607136)

    monkeypatch.setattr(
        "capmaster.plugins.preprocess.reporting.get_packet_count",
        fake_get_packet_count,
    )
    monkeypatch.setattr(
        "capmaster.plugins.preprocess.reporting.get_time_range",
        fake_get_time_range,
    )

    # When
    maybe_write_report(context, steps=["time-align+dedup"], final_files=[final])

    # Then
    report_path = output_dir / "preprocess_report.md"
    assert report_path.is_file()

    report = report_path.read_text(encoding="utf-8")

    # The table should use only filenames, not full paths, for original/final.
    assert str(original) not in report
    assert str(final) not in report
    assert original.name in report
    assert final.name in report

    # Raw epoch timestamps should not appear in the report.
    assert "1709877640.248336" not in report
    assert "1709877649.607136" not in report

    # Instead, we expect the helper's human-readable representation.
    first_human = _format_timestamp_for_report(1709877640.248336)
    last_human = _format_timestamp_for_report(1709877649.607136)
    assert first_human in report
    assert last_human in report

