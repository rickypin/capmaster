"""Preprocess pipeline context and orchestration logic.

This module provides the ``PreprocessContext`` dataclass and a
``run_preprocess`` API that executes individual preprocess steps in either
automatic mode (based on configuration toggles) or explicit mode (based
on a caller-provided step list).

The actual step handlers are intentionally minimal in this initial
implementation and will be extended to perform real work in subsequent
iterations.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
import logging
import os
import shutil
import tempfile

from capmaster.utils.errors import CapMasterError

from .config import PreprocessConfig, PreprocessRuntimeConfig
from .pcap_tools import (
    TimeRange,
    get_time_range,
    get_packet_count,
    run_editcap_dedup,
    run_editcap_time_crop,
    run_editcap_time_crop_and_dedup,
)
from .oneway_tools import detect_one_way_streams, filter_pcap_excluding_streams
from .reporting import maybe_write_report

logger = logging.getLogger(__name__)

# Step name constants used in CLI and reports
STEP_ARCHIVE_ORIGINAL = "archive-original"
STEP_TIME_ALIGN = "time-align"
STEP_DEDUP = "dedup"
STEP_ONEWAY = "oneway"
# Optimised combined step for time-align + dedup
STEP_TIME_ALIGN_DEDUP = "time-align+dedup"

StepName = str


@dataclass
class PreprocessContext:
    """Execution context for the preprocess pipeline."""

    runtime: PreprocessRuntimeConfig
    input_files: List[Path]
    output_dir: Path
    tmp_dir: Path




def _build_final_output_path(output_dir: Path, original: Path) -> Path:
    """Compute the final preprocessed output path for an input file.

    The naming follows the design doc convention:

    * ``<name>.preprocessed.pcap``
    * ``<name>.preprocessed.pcapng``
    """

    name = original.name
    if name.endswith(".pcapng"):
        base = name[:-7]
        suffix = ".pcapng"
    elif name.endswith(".pcap"):
        base = name[:-5]
        suffix = ".pcap"
    else:  # Fallback for unexpected extensions
        base = original.stem
        suffix = original.suffix

    return output_dir / f"{base}.preprocessed{suffix}"

# Type alias for step handler functions
StepHandler = Callable[[PreprocessContext, list[Path]], list[Path]]


def _archive_original_step(context: PreprocessContext, files: list[Path]) -> list[Path]:
    """Legacy archive step retained for reporting/CLI compatibility.

    Historically this step copied all original PCAPs into ``output_dir/archive``.
    Archiving is now performed after all steps have run so that we can decide
    per file whether any effective change occurred. Keeping this step as a
    no-op preserves the step name in reports and in explicit ``steps`` lists
    without changing semantics.
    """

    logger.debug(
        "archive-original step is now a no-op; archiving happens during finalisation",
    )
    return files


def _archive_changed_originals(context: PreprocessContext, final_files: list[Path]) -> None:
    """Archive only those original files whose effective content changed.

    A file is considered changed if packet count or time range differs between
    the original input and the final preprocessed output. If statistics cannot
    be obtained, the file is conservatively treated as changed so that it is
    still archived.
    """

    cfg = context.runtime.preprocess
    if not cfg.archive_original:
        return

    if not context.input_files or not final_files:
        return

    if len(context.input_files) != len(final_files):
        logger.warning(
            "Input/output file count mismatch (%d != %d); archiving all originals.",
            len(context.input_files),
            len(final_files),
        )
        changed_flags: list[bool] = [True] * len(context.input_files)
    else:
        tools = context.runtime.tools
        changed_flags = []
        for original, final in zip(context.input_files, final_files):
            try:
                orig_count = get_packet_count(tools=tools, input_file=original)
                final_count = get_packet_count(tools=tools, input_file=final)

                orig_range = get_time_range(tools=tools, input_file=original)
                final_range = get_time_range(tools=tools, input_file=final)
            except CapMasterError as exc:  # pragma: no cover - defensive
                logger.warning(
                    "Failed to collect statistics for %s / %s; archiving original conservatively: %s",
                    original,
                    final,
                    exc,
                )
                changed_flags.append(True)
                continue

            eps = 1e-6
            changed = (
                orig_count != final_count
                or abs(orig_range.first_ts - final_range.first_ts) > eps
                or abs(orig_range.last_ts - final_range.last_ts) > eps
            )
            changed_flags.append(changed)

    try:
        common_root_str = os.path.commonpath([str(p) for p in context.input_files])
        common_root = Path(common_root_str)
    except ValueError:
        common_root = None

    archive_root = context.output_dir / "archive"
    to_archive: list[tuple[Path, Path]] = []

    for src, changed in zip(context.input_files, changed_flags):
        if not changed:
            logger.info(
                "No effective preprocess changes detected for %s; skipping archive copy",
                src,
            )
            continue

        if common_root is not None:
            try:
                rel_path = src.relative_to(common_root)
            except ValueError:
                rel_path = Path(src.name)
        else:
            rel_path = Path(src.name)

        dest = archive_root / rel_path
        to_archive.append((src, dest))

    if not to_archive:
        return

    for src, dest in to_archive:
        dest.parent.mkdir(parents=True, exist_ok=True)
        logger.debug("Archiving changed original %s -> %s", src, dest)
        shutil.copy2(src, dest)


def _time_align_step(context: PreprocessContext, files: list[Path]) -> list[Path]:
    """Align multiple PCAP files to their overlapping time window.

    Behaviour follows the design document:

    * Require at least two files; otherwise log a warning and return inputs.
    * Prefer ``capinfos`` to obtain first/last timestamps, with fallback to
      ``tshark`` via :func:`get_time_range`.
    * Compute ``T_start = max(first_ts_i)`` and ``T_end = min(last_ts_i)``.
    * If ``T_start < T_end``, crop each file using ``editcap -A/-B`` and
      return the list of cropped files.
    * If ``T_start >= T_end``:
      * Raise ``CapMasterError`` when ``time_align_allow_empty`` is ``False``.
      * Otherwise, generate empty PCAP files for each input and return them.

    Note that this step keeps the number of files unchanged; it only modifies
    their contents and paths.
    """

    logger.debug("time-align step invoked for %d files", len(files))

    if len(files) < 2:
        logger.warning(
            "time-align requires at least 2 files; skipping (got %d)", len(files)
        )
        return files

    cfg = context.runtime.preprocess
    tools = context.runtime.tools
    workers = max(1, cfg.workers)

    # 1. Collect time ranges for all files, optionally in parallel.
    def _range_for(src: Path) -> tuple[Path, TimeRange]:
        tr = get_time_range(tools=tools, input_file=src)
        logger.debug(
            "Time range for %s: first_ts=%f, last_ts=%f", src, tr.first_ts, tr.last_ts
        )
        return src, tr

    if len(files) == 1 or workers == 1:
        ranges: list[tuple[Path, TimeRange]] = [_range_for(src) for src in files]
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(files))) as executor:
            ranges = list(executor.map(_range_for, files))

    # 2. Compute global overlap.
    t_start = max(tr.first_ts for _, tr in ranges)
    t_end = min(tr.last_ts for _, tr in ranges)

    logger.info(
        "Computed global overlap window: T_start=%f, T_end=%f",
        t_start,
        t_end,
    )

    if not t_start < t_end:
        # No overlap.
        if not cfg.time_align_allow_empty:
            logger.warning(
                "No overlapping time window between input PCAP files; "
                "skipping time-align step and leaving inputs unchanged.",
            )
            return files

        logger.warning(
            "No overlapping time window; generating empty PCAP outputs as per configuration.",
        )

        result_files: list[Path] = []
        for src, _ in ranges:
            suffix = src.suffix
            empty_path = context.tmp_dir / f"{src.stem}.timealign-empty{suffix}"

            # Use editcap to create an empty file (header only) by cropping a
            # window that is guaranteed to contain no packets.
            run_editcap_time_crop(
                tools=tools,
                input_file=src,
                output_file=empty_path,
                start_time=0.0,
                end_time=-1.0,
            )

            result_files.append(empty_path)

        return result_files

    # 3. Crop each file to the overlapping window, optionally in parallel.
    def _crop(src: Path) -> Path:
        suffix = src.suffix
        cropped_path = context.tmp_dir / f"{src.stem}.timealign{suffix}"
        logger.info(
            "Cropping %s to window [%f, %f] -> %s", src, t_start, t_end, cropped_path
        )
        run_editcap_time_crop(
            tools=tools,
            input_file=src,
            output_file=cropped_path,
            start_time=t_start,
            end_time=t_end,
        )
        return cropped_path

    if len(ranges) == 1 or workers == 1:
        result_files = [_crop(src) for src, _ in ranges]
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(ranges))) as executor:
            srcs = [src for src, _ in ranges]
            result_files = list(executor.map(_crop, srcs))

    return result_files



def _time_align_dedup_step(context: PreprocessContext, files: list[Path]) -> list[Path]:
    """Optimised step combining time-align and dedup in a single editcap pass.

    Semantics are equivalent to running ``time-align`` followed by ``dedup``
    in sequence; only the number of editcap passes over each file changes.
    """

    logger.debug("time-align+dedup step invoked for %d files", len(files))

    # Degenerate case: not enough files for time-align; fall back to plain dedup.
    if len(files) < 2:
        logger.warning(
            "time-align+dedup requires at least 2 files; falling back to dedup only (got %d)",
            len(files),
        )
        return _dedup_step(context, files)

    cfg = context.runtime.preprocess
    tools = context.runtime.tools
    workers = max(1, cfg.workers)

    # 1. Collect time ranges for all files, optionally in parallel.
    def _range_for(src: Path) -> tuple[Path, TimeRange]:
        tr = get_time_range(tools=tools, input_file=src)
        logger.debug(
            "[time-align+dedup] Time range for %s: first_ts=%f, last_ts=%f",
            src,
            tr.first_ts,
            tr.last_ts,
        )
        return src, tr

    if len(files) == 1 or workers == 1:
        ranges: list[tuple[Path, TimeRange]] = [_range_for(src) for src in files]
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(files))) as executor:
            ranges = list(executor.map(_range_for, files))

    # 2. Compute global overlap.
    t_start = max(tr.first_ts for _, tr in ranges)
    t_end = min(tr.last_ts for _, tr in ranges)

    logger.info(
        "Computed global overlap window (time-align+dedup): T_start=%f, T_end=%f",
        t_start,
        t_end,
    )

    if not t_start < t_end:
        # No overlap.
        if not cfg.time_align_allow_empty:
            logger.warning(
                "No overlapping time window between input PCAP files; "
                "falling back to dedup-only step.",
            )
            return _dedup_step(context, files)

        logger.warning(
            "No overlapping time window; generating empty PCAP outputs as per configuration.",
        )

        result_files: list[Path] = []
        for src, _ in ranges:
            suffix = src.suffix
            empty_path = context.tmp_dir / f"{src.stem}.timealign-empty{suffix}"

            # Use editcap to create an empty file (header only) by cropping a
            # window that is guaranteed to contain no packets.
            run_editcap_time_crop(
                tools=tools,
                input_file=src,
                output_file=empty_path,
                start_time=0.0,
                end_time=-1.0,
            )

            result_files.append(empty_path)

        return result_files

    # 3. Crop and deduplicate each file within the overlapping window, optionally in parallel.
    def _crop_and_dedup(src: Path) -> Path:
        suffix = src.suffix
        output_path = context.tmp_dir / f"{src.stem}.timealign_dedup{suffix}"
        logger.info(
            "Cropping+dedup %s to window [%f, %f] -> %s",
            src,
            t_start,
            t_end,
            output_path,
        )
        run_editcap_time_crop_and_dedup(
            tools=tools,
            input_file=src,
            output_file=output_path,
            start_time=t_start,
            end_time=t_end,
            window_packets=cfg.dedup_window_packets,
            ignore_bytes=cfg.dedup_ignore_bytes,
        )
        return output_path

    srcs = [src for src, _ in ranges]

    if len(srcs) <= 1 or workers == 1:
        result_files = [_crop_and_dedup(src) for src in srcs]
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(srcs))) as executor:
            result_files = list(executor.map(_crop_and_dedup, srcs))

    return result_files



def _dedup_step(context: PreprocessContext, files: list[Path]) -> list[Path]:
    """Deduplicate packets in each file using ``editcap``.

    This step keeps the number of files unchanged: every input file
    yields exactly one output file, with packets deduplicated according
    to ``PreprocessConfig.dedup_window_packets`` and
    ``PreprocessConfig.dedup_ignore_bytes``.
    """

    logger.debug("dedup step invoked for %d files", len(files))

    cfg = context.runtime.preprocess
    tools = context.runtime.tools
    workers = max(1, cfg.workers)

    def _process(src: Path) -> Path:
        # Intermediate files live in ``tmp_dir``. Final naming for
        # outputs is handled centrally after all steps are complete.
        suffix = src.suffix
        intermediate = context.tmp_dir / f"{src.stem}.dedup{suffix}"

        logger.info("Running dedup on %s -> %s", src, intermediate)
        run_editcap_dedup(
            tools=tools,
            input_file=src,
            output_file=intermediate,
            window_packets=cfg.dedup_window_packets,
            ignore_bytes=cfg.dedup_ignore_bytes,
        )

        return intermediate

    if len(files) <= 1 or workers == 1:
        return [_process(src) for src in files]

    with ThreadPoolExecutor(max_workers=min(workers, len(files))) as executor:
        result_files = list(executor.map(_process, files))

    return result_files


def _oneway_step(context: PreprocessContext, files: list[Path]) -> list[Path]:
    """Filter out one-way TCP connections based on ACK heuristics.

    This step reuses the TCP one-way detection logic from the filter plugin
    (``OneWayDetector``) via :mod:`capmaster.plugins.preprocess.oneway_tools`.
    For each input file, it detects one-way ``tcp.stream`` IDs using tshark
    and writes a new PCAP with those streams removed.
    """

    logger.debug("oneway step invoked for %d files", len(files))

    cfg = context.runtime.preprocess
    workers = max(1, cfg.workers)

    def _process(src: Path) -> Path:
        suffix = src.suffix
        intermediate = context.tmp_dir / f"{src.stem}.oneway{suffix}"

        logger.info("Detecting one-way TCP streams for %s", src)
        stream_ids = detect_one_way_streams(
            input_file=src,
            ack_threshold=cfg.oneway_ack_threshold,
        )

        if not stream_ids:
            logger.info("No one-way streams detected for %s; copying unchanged", src)
            shutil.copy2(src, intermediate)
        else:
            logger.info(
                "Filtering %d one-way streams from %s", len(stream_ids), src
            )
            filter_pcap_excluding_streams(
                input_file=src,
                output_file=intermediate,
                exclude_streams=stream_ids,
            )

        return intermediate

    if len(files) <= 1 or workers == 1:
        return [_process(src) for src in files]

    with ThreadPoolExecutor(max_workers=min(workers, len(files))) as executor:
        result_files = list(executor.map(_process, files))

    return result_files


STEP_HANDLERS: Mapping[StepName, StepHandler] = {
    STEP_ARCHIVE_ORIGINAL: _archive_original_step,
    STEP_TIME_ALIGN: _time_align_step,
    STEP_DEDUP: _dedup_step,
    STEP_ONEWAY: _oneway_step,
    STEP_TIME_ALIGN_DEDUP: _time_align_dedup_step,
}

# Default automatic execution order
DEFAULT_AUTOMATIC_ORDER: Sequence[StepName] = (
    STEP_ARCHIVE_ORIGINAL,
    STEP_TIME_ALIGN,
    STEP_DEDUP,
    STEP_ONEWAY,
)


def _automatic_steps(config: PreprocessConfig) -> list[StepName]:
    """Compute the step list for automatic mode.

    Steps are included in a fixed order depending on the corresponding
    enable/disable flags in ``PreprocessConfig``.
    """

    steps: list[StepName] = []

    if config.archive_original:
        steps.append(STEP_ARCHIVE_ORIGINAL)
    if config.time_align_enabled:
        steps.append(STEP_TIME_ALIGN)
    if config.dedup_enabled:
        steps.append(STEP_DEDUP)
    if config.oneway_enabled:
        steps.append(STEP_ONEWAY)

    return steps


def _optimise_steps(steps: Sequence[StepName]) -> list[StepName]:
    """Apply internal step-sequence optimisations.

    Currently this folds a consecutive ``time-align`` + ``dedup`` pair into a
    single ``time-align+dedup`` step. External semantics remain unchanged;
    only the number of editcap passes over each file is reduced.
    """

    if not steps:
        return []

    optimised: list[StepName] = []
    i = 0
    n = len(steps)

    while i < n:
        current = steps[i]
        nxt = steps[i + 1] if i + 1 < n else None

        if current == STEP_TIME_ALIGN and nxt == STEP_DEDUP:
            optimised.append(STEP_TIME_ALIGN_DEDUP)
            i += 2
            continue

        optimised.append(current)
        i += 1

    return optimised



def run_preprocess(
    runtime: PreprocessRuntimeConfig,
    input_files: Iterable[Path],
    output_dir: Path,
    *,
    steps: Sequence[StepName] | None = None,
    tmp_dir: Path | None = None,
) -> list[Path]:
    """Execute the preprocess pipeline.

    Args:
        runtime: Fully constructed runtime configuration.
        input_files: Iterable of input PCAP/PCAPNG files.
        output_dir: Directory where final preprocessed files should be
            written.
        steps: Optional explicit step sequence. If ``None`` or empty,
            automatic mode is used based on configuration flags.
        tmp_dir: Optional temporary directory to use for intermediate
            files. If not provided, a fresh directory is created and
            cleaned up automatically.

    Returns:
        List of resulting PCAP files after all steps.
    """

    output_dir.mkdir(parents=True, exist_ok=True)

    # Resolve step list: explicit vs automatic mode
    if not steps:
        steps = _automatic_steps(runtime.preprocess)

    # Apply internal optimisations such as folding time-align + dedup into a
    # single combined step. This does not change external semantics.
    steps = _optimise_steps(list(steps))

    invalid = [s for s in steps if s not in STEP_HANDLERS]
    if invalid:
        raise ValueError(f"Unknown preprocess steps: {invalid}")

    owns_tmp = False
    if tmp_dir is None:
        tmp_path_str = tempfile.mkdtemp(prefix="capmaster-preprocess-")
        tmp_dir = Path(tmp_path_str)
        owns_tmp = True

    context = PreprocessContext(
        runtime=runtime,
        input_files=[Path(p) for p in input_files],
        output_dir=output_dir,
        tmp_dir=tmp_dir,
    )

    current_files = list(context.input_files)

    try:
        for step_name in steps:
            handler = STEP_HANDLERS[step_name]
            logger.info("Running preprocess step: %s", step_name)
            current_files = handler(context, current_files)

        # Materialise final outputs in ``output_dir`` with the
        # ``<name>.preprocessed.pcap[ng]`` naming convention.

        final_files: list[Path] = []
        for original, current in zip(context.input_files, current_files):
            final_path = _build_final_output_path(context.output_dir, original)
            final_path.parent.mkdir(parents=True, exist_ok=True)

            if current != final_path:
                logger.debug("Copying final output %s -> %s", current, final_path)
                shutil.copy2(current, final_path)

            final_files.append(final_path)

        # Archive originals for files that were effectively modified.
        cfg = context.runtime.preprocess
        _archive_changed_originals(context, final_files)

        # Optionally compress the archive directory after all other outputs
        # have been written.
        if cfg.archive_original and cfg.archive_compress:
            archive_dir = context.output_dir / "archive"
            if archive_dir.exists():
                base_name = archive_dir.parent / "archive"
                try:
                    shutil.make_archive(str(base_name), "gztar", root_dir=archive_dir)
                except OSError:
                    logger.warning(
                        "Failed to create archive tarball for %s", archive_dir
                    )

        # Generate a minimal Markdown report if enabled. Report generation
        # errors should not cause the preprocess run to fail.
        maybe_write_report(context, steps=list(steps), final_files=final_files)

        return final_files
    finally:
        if owns_tmp:
            try:
                shutil.rmtree(tmp_dir)
            except OSError:
                logger.warning("Failed to clean up temporary directory: %s", tmp_dir)





