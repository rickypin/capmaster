from __future__ import annotations

"""Tests for empty-match behavior in the topology runner.

These tests focus on the behavior toggle that controls what happens when the
matched_connections file does not yield any usable cross-capture matches.
"""

from pathlib import Path

import pytest

from capmaster.plugins.topology.runner import _run_dual_capture_pipeline
from capmaster.utils.errors import CapMasterError


@pytest.mark.unit
def test_dual_pipeline_no_pairs_default_error(monkeypatch, tmp_path: Path) -> None:
    """Default behavior should be to raise when no connection pairs are found."""

    file_a = tmp_path / "a.pcap"
    file_b = tmp_path / "b.pcap"
    matched_file = tmp_path / "matched.txt"

    file_a.touch()
    file_b.touch()
    matched_file.write_text("dummy")

    # Simulate an empty matched_connections file.
    monkeypatch.setattr(
        "capmaster.plugins.topology.runner.parse_matched_connections",
        lambda _path: [],
    )

    with pytest.raises(CapMasterError) as excinfo:
        _run_dual_capture_pipeline(
            file_a=file_a,
            file_b=file_b,
            matched_file=matched_file,
            service_list=None,
            empty_match_behavior="error",
        )

    assert "No valid connection pairs found in matched connections file." in str(
        excinfo.value
    )


@pytest.mark.unit
def test_dual_pipeline_no_pairs_fallback_single(monkeypatch, tmp_path: Path) -> None:
    """When behavior is 'fallback-single', empty pairs should trigger fallback."""

    file_a = tmp_path / "a.pcap"
    file_b = tmp_path / "b.pcap"
    matched_file = tmp_path / "matched.txt"

    file_a.touch()
    file_b.touch()
    matched_file.write_text("dummy")

    # Simulate an empty matched_connections file.
    monkeypatch.setattr(
        "capmaster.plugins.topology.runner.parse_matched_connections",
        lambda _path: [],
    )

    # Avoid invoking real PCAP parsing by stubbing the single-capture pipeline
    # and formatting helpers used by the fallback path.
    class DummySingleTopology:
        def __init__(self, file_name: str) -> None:
            self.file_name = file_name
            self.services = []

    def fake_single(
        file_path: Path,
        *,
        service_list: Path | None,
        quiet: bool = False,
    ) -> DummySingleTopology:  # type: ignore[override]
        return DummySingleTopology(file_path.name)

    def fake_format(single: DummySingleTopology, *, capture_label: str = "A") -> str:  # type: ignore[override]
        return f"SINGLE {single.file_name} ({capture_label})"

    monkeypatch.setattr(
        "capmaster.plugins.topology.runner._run_single_capture_pipeline",
        fake_single,
    )
    monkeypatch.setattr(
        "capmaster.plugins.topology.runner.format_single_topology",
        fake_format,
    )

    output = _run_dual_capture_pipeline(
        file_a=file_a,
        file_b=file_b,
        matched_file=matched_file,
        service_list=None,
        empty_match_behavior="fallback-single",
    )

    assert (
        "No matched connections detected between capture points. "
        "Falling back to per-capture topology analysis."
    ) in output
    assert "SINGLE a.pcap" in output
    assert "SINGLE b.pcap" in output


@pytest.mark.unit
def test_dual_pipeline_no_rebuilt_matches_respects_behavior(monkeypatch, tmp_path: Path) -> None:
    """Verify behavior both for error and fallback when matches cannot be rebuilt."""

    file_a = tmp_path / "a.pcap"
    file_b = tmp_path / "b.pcap"
    matched_file = tmp_path / "matched.txt"

    file_a.touch()
    file_b.touch()
    matched_file.write_text("dummy")

    # Non-empty connection_pairs so we reach the rebuild step.
    monkeypatch.setattr(
        "capmaster.plugins.topology.runner.parse_matched_connections",
        lambda _path: [object()],
    )

    # Avoid real tshark calls.
    monkeypatch.setattr(
        "capmaster.plugins.topology.runner.extract_connections_from_pcap",
        lambda _path: [object()],
    )

    # Force the rebuild step to yield no matches.
    monkeypatch.setattr(
        "capmaster.plugins.topology.runner._build_matches_from_pairs",
        lambda _pairs, _a, _b: [],
    )

    # 1) Default behavior still raises.
    with pytest.raises(CapMasterError) as excinfo:
        _run_dual_capture_pipeline(
            file_a=file_a,
            file_b=file_b,
            matched_file=matched_file,
            service_list=None,
            empty_match_behavior="error",
        )

    assert "Could not rebuild any connection matches from the provided file." in str(
        excinfo.value
    )

    # 2) Fallback behavior returns a combined single-capture report.
    class DummySingleTopology2:
        def __init__(self, file_name: str) -> None:
            self.file_name = file_name
            self.services = []

    def fake_single2(
        file_path: Path,
        *,
        service_list: Path | None,
        quiet: bool = False,
    ) -> DummySingleTopology2:  # type: ignore[override]
        return DummySingleTopology2(file_path.name)

    def fake_format2(single: DummySingleTopology2, *, capture_label: str = "A") -> str:  # type: ignore[override]
        return f"SINGLE2 {single.file_name} ({capture_label})"

    monkeypatch.setattr(
        "capmaster.plugins.topology.runner._run_single_capture_pipeline",
        fake_single2,
    )
    monkeypatch.setattr(
        "capmaster.plugins.topology.runner.format_single_topology",
        fake_format2,
    )

    output = _run_dual_capture_pipeline(
        file_a=file_a,
        file_b=file_b,
        matched_file=matched_file,
        service_list=None,
        empty_match_behavior="fallback-single",
    )

    assert "SINGLE2 a.pcap" in output
    assert "SINGLE2 b.pcap" in output

