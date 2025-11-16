from __future__ import annotations

from concurrent.futures import Future
from pathlib import Path

import pytest

import capmaster.plugins.analyze.plugin as analyze_plugin
from capmaster.plugins.analyze.plugin import AnalyzePlugin


class DummyExecutor:
    """In-process stand-in for ProcessPoolExecutor.

    It executes the submitted function immediately and wraps the result or
    exception in a real Future so that concurrent.futures.as_completed can
    iterate over them as usual.
    """

    def __init__(self, max_workers: int | None = None) -> None:  # noqa: D401 - simple initializer
        self._max_workers = max_workers

    def __enter__(self) -> "DummyExecutor":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # noqa: D401 - context manager protocol
        return False

    def submit(self, fn, *args, **kwargs) -> Future:  # type: ignore[override]
        fut: Future = Future()
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:  # pragma: no cover - trivial error path
            fut.set_exception(exc)
        else:
            fut.set_result(result)
        return fut


@pytest.mark.unit
def test_execute_returns_nonzero_when_any_worker_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """If any worker fails, execute() should return a non-zero exit code.

    This specifically exercises the concurrent branch (workers > 1) and verifies
    that failures in worker processes are not silently ignored.
    """

    plugin = AnalyzePlugin()

    # Ensure we have more than one file so that the multiprocessing branch is used.
    dummy_files = [tmp_path / "a.pcap", tmp_path / "b.pcap"]

    def fake_scan(cls, paths, recursive: bool = True, preserve_order: bool = False):  # type: ignore[override]
        return dummy_files

    # Avoid touching the real filesystem by overriding the scanner.
    monkeypatch.setattr(
        analyze_plugin.PcapScanner,
        "scan",
        classmethod(fake_scan),
    )

    # Replace ProcessPoolExecutor with our in-process dummy implementation.
    monkeypatch.setattr(
        analyze_plugin,
        "ProcessPoolExecutor",
        DummyExecutor,
    )

    # Worker that always fails to simulate an error in a child process.
    def failing_worker(*_args, **_kwargs):
        raise RuntimeError("worker failed")

    monkeypatch.setattr(analyze_plugin, "_process_single_file", failing_worker)

    exit_code = plugin.execute(
        input_path="dummy-input",
        output_dir=tmp_path,
        recursive=False,
        workers=2,
    )

    assert exit_code == 1

