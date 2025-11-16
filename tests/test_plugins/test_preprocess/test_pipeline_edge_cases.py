"""Unit tests for preprocess pipeline edge-case behaviour.

These tests focus on situations where the configured preprocess steps
have little or no effect on the input PCAPs, to ensure the pipeline
behaves as expected:

- No overlapping time window for time-align.
- No one-way TCP streams for oneway filtering.
- No steps enabled at all (no-op run) but report generation requested.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from capmaster.plugins.preprocess import pipeline as preprocess_pipeline
from capmaster.plugins.preprocess import reporting as preprocess_reporting
from capmaster.plugins.preprocess.config import (
    PreprocessConfig,
    PreprocessRuntimeConfig,
    ToolsConfig,
)
from capmaster.utils.errors import CapMasterError


def _make_dummy_pcap(tmp_path: Path, name: str, content: bytes = b"dummy") -> Path:
    """Create a small dummy file to stand in for a PCAP capture."""

    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / name
    path.write_bytes(content)
    return path


def test_time_align_no_overlap_skips_step_and_preserves_files(tmp_path, monkeypatch):
    """No overlap: time-align should skip and leave inputs unchanged.

    When ``time_align_allow_empty`` is ``False`` and the input PCAP files
    have no overlapping time window, the time-align step should not raise
    an error. Instead, it should log a warning and behave as a no-op so
    that later steps (or finalisation) can still run.
    """

    input_dir = tmp_path / "in"
    f1 = _make_dummy_pcap(input_dir, "a.pcap", b"one")
    f2 = _make_dummy_pcap(input_dir, "b.pcap", b"two")

    tools = ToolsConfig()
    cfg = PreprocessConfig(
        time_align_enabled=True,
        dedup_enabled=False,
        oneway_enabled=False,
        archive_original=False,
        report_enabled=False,
    )
    runtime = PreprocessRuntimeConfig(tools=tools, preprocess=cfg)

    def fake_get_time_range(*, tools: ToolsConfig, input_file: Path):  # type: ignore[override]
        # Return non-overlapping windows so that t_start >= t_end.
        if input_file == f1:
            return preprocess_pipeline.TimeRange(0.0, 10.0)
        return preprocess_pipeline.TimeRange(20.0, 30.0)

    monkeypatch.setattr(preprocess_pipeline, "get_time_range", fake_get_time_range)

    out_dir = tmp_path / "out"
    outputs = preprocess_pipeline.run_preprocess(
        runtime=runtime,
        input_files=[f1, f2],
        output_dir=out_dir,
        steps=[preprocess_pipeline.STEP_TIME_ALIGN],
    )

    assert [p.name for p in outputs] == ["a.preprocessed.pcap", "b.preprocessed.pcap"]
    assert (out_dir / "a.preprocessed.pcap").read_bytes() == b"one"
    assert (out_dir / "b.preprocessed.pcap").read_bytes() == b"two"


def test_oneway_no_streams_copies_input_unchanged(tmp_path, monkeypatch):
    """No one-way streams: oneway step should behave as a no-op.

    When ``detect_one_way_streams`` finds no streams to remove, the
    oneway step should simply copy the original PCAP to the intermediate
    output without invoking the heavy filter operation.
    """

    input_dir = tmp_path / "in"
    src = _make_dummy_pcap(input_dir, "a.pcap", b"payload")

    tools = ToolsConfig()
    cfg = PreprocessConfig(
        time_align_enabled=False,
        dedup_enabled=False,
        oneway_enabled=True,
        archive_original=False,
        report_enabled=False,
    )
    runtime = PreprocessRuntimeConfig(tools=tools, preprocess=cfg)

    def fake_detect_one_way_streams(*, input_file: Path, ack_threshold: int):  # type: ignore[override]
        assert input_file == src
        return []

    def fake_filter_pcap_excluding_streams(*, input_file: Path, output_file: Path, exclude_streams):  # type: ignore[override]
        raise AssertionError("filter_pcap_excluding_streams should not be called when there are no streams")

    monkeypatch.setattr(preprocess_pipeline, "detect_one_way_streams", fake_detect_one_way_streams)
    monkeypatch.setattr(
        preprocess_pipeline,
        "filter_pcap_excluding_streams",
        fake_filter_pcap_excluding_streams,
    )

    out_dir = tmp_path / "out"
    outputs = preprocess_pipeline.run_preprocess(
        runtime=runtime,
        input_files=[src],
        output_dir=out_dir,
        steps=[preprocess_pipeline.STEP_ONEWAY],
    )

    assert len(outputs) == 1
    out = outputs[0]
    assert out.name == "a.preprocessed.pcap"
    assert out.read_bytes() == b"payload"


def test_no_steps_config_keeps_original_and_emits_report(tmp_path, monkeypatch):
    """All steps disabled: keep original PCAP and still write a report.

    When all preprocess steps (time-align, dedup, oneway) are disabled for
    a given run but reporting is enabled, the pipeline should simply copy
    the original PCAPs to the output directory, avoid archiving, and
    still emit a Markdown report.
    """

    input_dir = tmp_path / "in"
    src = _make_dummy_pcap(input_dir, "a.pcap", b"data")

    tools = ToolsConfig()
    cfg = PreprocessConfig(
        time_align_enabled=False,
        dedup_enabled=False,
        oneway_enabled=False,
        archive_original=False,
        archive_compress=False,
        report_enabled=True,
    )
    runtime = PreprocessRuntimeConfig(tools=tools, preprocess=cfg)

    def fake_maybe_write_report(context, *, steps, final_files):  # type: ignore[override]
        # Minimal stub that simulates report generation without invoking
        # external tools such as capinfos/tshark.
        report_path = context.output_dir / "preprocess_report.md"
        report_path.write_text("dummy report", encoding="utf-8")

    monkeypatch.setattr(preprocess_pipeline, "maybe_write_report", fake_maybe_write_report)

    out_dir = tmp_path / "out"
    outputs = preprocess_pipeline.run_preprocess(
        runtime=runtime,
        input_files=[src],
        output_dir=out_dir,
    )

    assert len(outputs) == 1
    out = outputs[0]
    assert out.name == "a.preprocessed.pcap"
    assert out.read_bytes() == b"data"

    # No archive directory should be created when archive_original is False.
    assert not (out_dir / "archive").exists()

    # Report should have been written by the stub.
    report_path = out_dir / "preprocess_report.md"
    assert report_path.is_file()




def test_archive_skipped_when_no_effective_changes(tmp_path, monkeypatch):
    """archive_original=True but no changes: do not create an archive.

    This exercises the per-file archiving logic: a run where all PCAPs are
    effectively untouched should not produce an archive directory even when
    the archive flag is enabled.
    """

    input_dir = tmp_path / "in"
    src = _make_dummy_pcap(input_dir, "a.pcap", b"data")

    tools = ToolsConfig()
    cfg = PreprocessConfig(
        time_align_enabled=False,
        dedup_enabled=False,
        oneway_enabled=False,
        archive_original=True,
        archive_compress=False,
        report_enabled=False,
    )
    runtime = PreprocessRuntimeConfig(tools=tools, preprocess=cfg)

    def fake_get_packet_count(*, tools: ToolsConfig, input_file: Path) -> int:  # type: ignore[override]
        assert input_file.exists()
        return 100

    def fake_get_time_range(*, tools: ToolsConfig, input_file: Path):  # type: ignore[override]
        assert input_file.exists()
        return preprocess_pipeline.TimeRange(0.0, 10.0)

    monkeypatch.setattr(preprocess_pipeline, "get_packet_count", fake_get_packet_count)
    monkeypatch.setattr(preprocess_pipeline, "get_time_range", fake_get_time_range)

    out_dir = tmp_path / "out"
    outputs = preprocess_pipeline.run_preprocess(
        runtime=runtime,
        input_files=[src],
        output_dir=out_dir,
    )

    assert [p.name for p in outputs] == ["a.preprocessed.pcap"]
    # No archive directory should be created because nothing effectively changed.
    assert not (out_dir / "archive").exists()


def test_archive_only_for_files_with_effective_changes(tmp_path, monkeypatch):
    """Archive originals only for files whose stats indicate real changes.

    This test also validates that the Markdown report marks only the
    effectively changed file as archived.
    """

    input_dir = tmp_path / "in"
    a = _make_dummy_pcap(input_dir, "a.pcap", b"a-data")
    b = _make_dummy_pcap(input_dir, "b.pcap", b"b-data")

    tools = ToolsConfig()
    cfg = PreprocessConfig(
        time_align_enabled=False,
        dedup_enabled=False,
        oneway_enabled=False,
        archive_original=True,
        archive_compress=False,
        report_enabled=True,
    )
    runtime = PreprocessRuntimeConfig(tools=tools, preprocess=cfg)

    def fake_get_packet_count(*, tools: ToolsConfig, input_file: Path) -> int:  # type: ignore[override]
        name = input_file.name
        if name.startswith("a") and name.endswith(".preprocessed.pcap"):
            return 80
        if name.startswith("a"):
            return 100
        # b.* files: keep packet count unchanged
        return 50

    def fake_get_time_range(*, tools: ToolsConfig, input_file: Path):  # type: ignore[override]
        name = input_file.name
        if name.startswith("a") and name.endswith(".preprocessed.pcap"):
            return preprocess_pipeline.TimeRange(1.0, 9.0)
        if name.startswith("a"):
            return preprocess_pipeline.TimeRange(0.0, 10.0)
        # For b, keep identical range before/after.
        return preprocess_pipeline.TimeRange(0.0, 5.0)

    monkeypatch.setattr(preprocess_pipeline, "get_packet_count", fake_get_packet_count)
    monkeypatch.setattr(preprocess_pipeline, "get_time_range", fake_get_time_range)

    # The reporting module uses its own imports of get_packet_count/get_time_range;
    # patch them so that report generation does not invoke external tools.
    def fake_report_get_packet_count(*, tools: ToolsConfig, input_file: Path) -> int:  # type: ignore[override]
        return fake_get_packet_count(tools=tools, input_file=input_file)

    def fake_report_get_time_range(*, tools: ToolsConfig, input_file: Path):  # type: ignore[override]
        return fake_get_time_range(tools=tools, input_file=input_file)

    monkeypatch.setattr(
        preprocess_reporting,
        "get_packet_count",
        fake_report_get_packet_count,
    )
    monkeypatch.setattr(
        preprocess_reporting,
        "get_time_range",
        fake_report_get_time_range,
    )

    out_dir = tmp_path / "out"
    outputs = preprocess_pipeline.run_preprocess(
        runtime=runtime,
        input_files=[a, b],
        output_dir=out_dir,
    )

    assert sorted(p.name for p in outputs) == [
        "a.preprocessed.pcap",
        "b.preprocessed.pcap",
    ]

    archive_dir = out_dir / "archive"
    # Only "a.pcap" should be archived; "b.pcap" had no effective changes.
    assert (archive_dir / "a.pcap").is_file()
    assert not (archive_dir / "b.pcap").exists()

    # The report should include an "Archived" column reflecting the same
    # per-file decisions as the on-disk archive structure.
    report_path = out_dir / "preprocess_report.md"
    assert report_path.is_file()
    lines = report_path.read_text(encoding="utf-8").splitlines()

    header = next(line for line in lines if line.startswith("| Original path"))
    assert "Archived" in header

    row_a = next(
        line
        for line in lines
        if "a.pcap" in line and "a.preprocessed.pcap" in line
    )
    row_b = next(
        line
        for line in lines
        if "b.pcap" in line and "b.preprocessed.pcap" in line
    )

    assert "| yes |" in row_a
    assert "| no |" in row_b


def test_time_align_allow_empty_generates_empty_files(tmp_path, monkeypatch):
    """When time_align_allow_empty=True, non-overlapping inputs produce empty outputs.

    The pipeline should not error even if the intersection window is empty; instead it
    should generate empty PCAPs that are still treated as valid outputs for downstream
    steps.
    """

    input_dir = tmp_path / "in"
    f1 = _make_dummy_pcap(input_dir, "a.pcap", b"one")
    f2 = _make_dummy_pcap(input_dir, "b.pcap", b"two")

    tools = ToolsConfig()
    cfg = PreprocessConfig(
        time_align_enabled=True,
        dedup_enabled=False,
        oneway_enabled=False,
        archive_original=False,
        report_enabled=False,
        time_align_allow_empty=True,
    )
    runtime = PreprocessRuntimeConfig(tools=tools, preprocess=cfg)

    def fake_get_time_range(*, tools: ToolsConfig, input_file: Path):  # type: ignore[override]
        # Return non-overlapping windows so that intersection is empty.
        if input_file == f1:
            return preprocess_pipeline.TimeRange(0.0, 10.0)
        return preprocess_pipeline.TimeRange(20.0, 30.0)

    calls: list[tuple[Path, Path, float, float]] = []

    def fake_run_editcap_time_crop(
        *,
        tools: ToolsConfig,
        input_file: Path,
        output_file: Path,
        start_time: float,
        end_time: float,
        timeout: float | None = None,
    ) -> None:  # type: ignore[override]
        # Record arguments and create an empty file to simulate an empty PCAP.
        calls.append((input_file, output_file, start_time, end_time))
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_bytes(b"")

    monkeypatch.setattr(preprocess_pipeline, "get_time_range", fake_get_time_range)
    monkeypatch.setattr(
        preprocess_pipeline,
        "run_editcap_time_crop",
        fake_run_editcap_time_crop,
    )

    out_dir = tmp_path / "out"
    outputs = preprocess_pipeline.run_preprocess(
        runtime=runtime,
        input_files=[f1, f2],
        output_dir=out_dir,
        steps=[preprocess_pipeline.STEP_TIME_ALIGN],
    )

    # We still get two outputs, but they are empty PCAP files.
    assert [p.name for p in outputs] == [
        "a.preprocessed.pcap",
        "b.preprocessed.pcap",
    ]
    for out in outputs:
        assert out.read_bytes() == b""

    # Both inputs should have been processed with a "0..-1" crop window.
    assert len(calls) == 2
    for (_, _, start, end) in calls:
        assert start == 0.0
        assert end == -1.0



def test_archive_compress_creates_tarball_when_archive_exists(tmp_path, monkeypatch):
    """archive_compress=True should create a compressed archive when there are originals.

    This focuses on the compression behaviour itself. The detailed logic that decides
    which files are archived is covered by separate tests.
    """

    input_dir = tmp_path / "in"
    src = _make_dummy_pcap(input_dir, "a.pcap", b"data")

    tools = ToolsConfig()
    cfg = PreprocessConfig(
        time_align_enabled=False,
        dedup_enabled=False,
        oneway_enabled=False,
        archive_original=True,
        archive_compress=True,
        report_enabled=False,
    )
    runtime = PreprocessRuntimeConfig(tools=tools, preprocess=cfg)

    def fake_archive_changed_originals(context, final_files):  # type: ignore[override]
        # Create a simple archive directory with one file so that the compression
        # logic has something to work with.
        archive_dir = context.output_dir / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        for src in context.input_files:
            dest = archive_dir / src.name
            dest.write_bytes(b"orig")

    monkeypatch.setattr(
        preprocess_pipeline,
        "_archive_changed_originals",
        fake_archive_changed_originals,
    )

    make_archive_calls: list[tuple[str, str, Path | None]] = []

    def fake_make_archive(base_name: str, format: str, root_dir=None):
        make_archive_calls.append((base_name, format, root_dir))
        # Simulate returning the path to the created .tar.gz file.
        return str(Path(base_name).with_suffix(".tar.gz"))

    monkeypatch.setattr(preprocess_pipeline.shutil, "make_archive", fake_make_archive)

    out_dir = tmp_path / "out"
    outputs = preprocess_pipeline.run_preprocess(
        runtime=runtime,
        input_files=[src],
        output_dir=out_dir,
    )

    assert [p.name for p in outputs] == ["a.preprocessed.pcap"]

    archive_dir = out_dir / "archive"
    assert archive_dir.is_dir()
    assert (archive_dir / "a.pcap").is_file()

    # Compression should have been invoked exactly once with gztar format.
    assert len(make_archive_calls) == 1
    base_name, format, root_dir = make_archive_calls[0]
    assert format == "gztar"
    assert Path(base_name).name == "archive"
    assert Path(base_name).parent == out_dir
    assert root_dir == archive_dir



def test_report_uses_na_when_stats_collection_fails(tmp_path, monkeypatch):
    """Report should still be generated and use N/A when stats gathering fails.

    Errors while collecting per-file statistics (CapMasterError) must not abort the
    pipeline; instead, the report should gracefully fall back to N/A values.
    """

    input_dir = tmp_path / "in"
    src = _make_dummy_pcap(input_dir, "a.pcap", b"data")

    tools = ToolsConfig()
    cfg = PreprocessConfig(
        time_align_enabled=False,
        dedup_enabled=False,
        oneway_enabled=False,
        archive_original=True,
        archive_compress=False,
        report_enabled=True,
    )
    runtime = PreprocessRuntimeConfig(tools=tools, preprocess=cfg)

    def failing_get_packet_count(*, tools: ToolsConfig, input_file: Path) -> int:  # type: ignore[override]
        raise CapMasterError("capinfos failed", "hint")

    def failing_get_time_range(*, tools: ToolsConfig, input_file: Path):  # type: ignore[override]
        raise CapMasterError("capinfos failed", "hint")

    # Ensure both the pipeline and reporting modules see the same failures.
    monkeypatch.setattr(preprocess_pipeline, "get_packet_count", failing_get_packet_count)
    monkeypatch.setattr(preprocess_pipeline, "get_time_range", failing_get_time_range)
    monkeypatch.setattr(preprocess_reporting, "get_packet_count", failing_get_packet_count)
    monkeypatch.setattr(preprocess_reporting, "get_time_range", failing_get_time_range)

    out_dir = tmp_path / "out"
    outputs = preprocess_pipeline.run_preprocess(
        runtime=runtime,
        input_files=[src],
        output_dir=out_dir,
    )

    assert [p.name for p in outputs] == ["a.preprocessed.pcap"]

    report_path = out_dir / "preprocess_report.md"
    assert report_path.is_file()
    lines = report_path.read_text(encoding="utf-8").splitlines()

    row = next(
        line
        for line in lines
        if "a.pcap" in line and "a.preprocessed.pcap" in line
    )

    # All numeric/stat fields should be N/A when stats gathering fails.
    assert "| N/A | N/A | N/A | N/A | N/A | N/A |" in row

