"""Markdown report generation for preprocess runs.

This module contains helpers for producing the per-run Markdown report
as described in the preprocess design document. Report generation is
best-effort and must never cause the main preprocess pipeline to fail.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING
import os
import logging

from capmaster.utils.errors import CapMasterError
from .pcap_tools import get_packet_count, get_time_range

if TYPE_CHECKING:  # pragma: no cover - type checking only
    from .pipeline import PreprocessContext, StepName


logger = logging.getLogger(__name__)


def maybe_write_report(
    context: "PreprocessContext",
    *,
    steps: list["StepName"],
    final_files: list[Path],
) -> None:
    """Generate a minimal Markdown report for a preprocess run.

    The report focuses on a few high-level aspects:

    - run overview (timestamp, steps executed),
    - effective configuration toggles,
    - per-file comparison table with packet counts, time ranges, and
      whether the original file was archived.

    Any error during report generation is logged as a warning but does not
    affect the main preprocess result.
    """

    cfg = context.runtime.preprocess
    if not cfg.report_enabled:
        return

    output_dir = context.output_dir

    if cfg.report_path:
        report_path = Path(cfg.report_path)
        if not report_path.is_absolute():
            # Treat relative paths as relative to the output directory so that
            # reports stay co-located with generated PCAPs by default.
            report_path = output_dir / report_path
    else:
        report_path = output_dir / "preprocess_report.md"

    try:
        # Collect simple per-file statistics. Failures while gathering
        # statistics are handled per file so that a single problematic PCAP
        # does not prevent report generation.
        lines: list[str] = []

        now = datetime.now(timezone.utc)
        steps_str = " -> ".join(steps) if steps else "(none)"

        lines.append("# CapMaster preprocess report")
        lines.append("")
        lines.append(f"Generated at: {now.isoformat()}")
        lines.append(f"Output directory: {output_dir}")
        lines.append(f"Steps executed: {steps_str}")
        lines.append("")

        lines.append("## Effective configuration (subset)")
        lines.append("")
        lines.append(f"- archive_original: {cfg.archive_original}")
        lines.append(f"- time_align_enabled: {cfg.time_align_enabled}")
        lines.append(f"- dedup_enabled: {cfg.dedup_enabled}")
        lines.append(f"- oneway_enabled: {cfg.oneway_enabled}")
        lines.append(f"- time_align_allow_empty: {cfg.time_align_allow_empty}")
        lines.append(f"- oneway_ack_threshold: {cfg.oneway_ack_threshold}")
        lines.append("")

        lines.append("## File comparison")
        lines.append("")
        lines.append(
            "| Original path | Final path | Packets (orig) | Packets (final) | "
            "First ts (orig) | Last ts (orig) | First ts (final) | Last ts (final) | "
            "Archived |"
        )
        lines.append(
            "| --- | --- | ---:| ---:| ---:| ---:| ---:| ---:| --- |"
        )

        tools = context.runtime.tools
        archive_dir = output_dir / "archive"

        common_root: Path | None = None
        if cfg.archive_original and archive_dir.is_dir() and context.input_files:
            try:
                common_root_str = os.path.commonpath([str(p) for p in context.input_files])
                common_root = Path(common_root_str)
            except ValueError:
                common_root = None

        for original, final in zip(context.input_files, final_files):
            archived = False
            if cfg.archive_original and archive_dir.is_dir():
                if common_root is not None:
                    try:
                        rel_path = original.relative_to(common_root)
                    except ValueError:
                        rel_path = Path(original.name)
                else:
                    rel_path = Path(original.name)

                dest = archive_dir / rel_path
                archived = dest.exists()

            archived_str = "yes" if archived else "no"

            try:
                orig_count = get_packet_count(tools=tools, input_file=original)
                final_count = get_packet_count(tools=tools, input_file=final)

                orig_tr = get_time_range(tools=tools, input_file=original)
                final_tr = get_time_range(tools=tools, input_file=final)

                row = (
                    f"| {original} | {final} | {orig_count} | {final_count} | "
                    f"{orig_tr.first_ts:.6f} | {orig_tr.last_ts:.6f} | "
                    f"{final_tr.first_ts:.6f} | {final_tr.last_ts:.6f} | {archived_str} |"
                )
            except CapMasterError as exc:
                logger.warning("Failed to collect stats for %s/%s: %s", original, final, exc)
                row = (
                    f"| {original} | {final} | N/A | N/A | N/A | N/A | N/A | N/A | "
                    f"{archived_str} |"
                )

            lines.append(row)

        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Preprocess Markdown report written to %s", report_path)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to generate preprocess report: %s", exc)

