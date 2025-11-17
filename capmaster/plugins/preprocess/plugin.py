"""Preprocess plugin for cleaning and standardising PCAP files."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

import logging
import click

from capmaster.core.file_scanner import PcapScanner
from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.preprocess.config import build_runtime_config
from capmaster.plugins.preprocess.pipeline import (
    STEP_ARCHIVE_ORIGINAL,
    STEP_DEDUP,
    STEP_ONEWAY,
    STEP_TIME_ALIGN,
    run_preprocess,
)
from capmaster.utils.errors import CapMasterError, NoPcapFilesError, handle_error
from capmaster.utils.logger import get_logger

logger = get_logger(__name__)

VALID_STEPS: Sequence[str] = (
    STEP_ARCHIVE_ORIGINAL,
    STEP_TIME_ALIGN,
    STEP_DEDUP,
    STEP_ONEWAY,
)


def _check_flag_pair(enable: bool, disable: bool, name: str) -> None:
    """Raise a CapMasterError if both enable/disable flags are set."""

    if enable and disable:
        raise CapMasterError(
            f"Cannot use both --enable-{name} and --disable-{name}",
            f"Please specify at most one of --enable-{name} or --disable-{name}.",
        )


@register_plugin
class PreprocessPlugin(PluginBase):
    """Plugin that orchestrates the preprocess pipeline."""

    @property
    def name(self) -> str:  # pragma: no cover - trivial
        return "preprocess"

    def setup_cli(self, cli_group: click.Group) -> None:
        """Register the preprocess command."""

        @cli_group.command(name="preprocess")
        @click.option(
            "-i",
            "--input",
            "input_path",
            type=str,
            required=True,
            help="Input PCAP file, directory, or comma-separated file list",
        )
        @click.option(
            "-o",
            "--output",
            "output_dir",
            type=click.Path(path_type=Path, file_okay=False),
            help="Output directory for preprocessed files",
        )
        @click.option(
            "--config",
            "config_path",
            type=click.Path(path_type=Path),
            help="Path to YAML configuration file (overrides defaults)",
        )
        @click.option(
            "--step",
            "steps",
            type=click.Choice(VALID_STEPS, case_sensitive=False),
            multiple=True,
            help="Explicit step list (archive-original,time-align,dedup,oneway)",
        )
        @click.option("--enable-dedup", is_flag=True, default=False, help="Enable dedup step")
        @click.option("--disable-dedup", is_flag=True, default=False, help="Disable dedup step")
        @click.option("--enable-oneway", is_flag=True, default=False, help="Enable oneway step")
        @click.option("--disable-oneway", is_flag=True, default=False, help="Disable oneway step")
        @click.option("--enable-time-align", is_flag=True, default=False, help="Enable time-align step")
        @click.option("--disable-time-align", is_flag=True, default=False, help="Disable time-align step")
        @click.option("--enable-archive-original", is_flag=True, default=False, help="Enable archive-original step")
        @click.option("--disable-archive-original", is_flag=True, default=False, help="Disable archive-original step")
        @click.option(
            "--dedup-window-packets",
            type=int,
            default=None,
            help="Dedup window size in packets",
        )
        @click.option(
            "--dedup-ignore-bytes",
            type=int,
            default=None,
            help="Ignore N bytes at packet end when deduplicating",
        )
        @click.option(
            "--oneway-ack-threshold",
            type=int,
            default=None,
            help="ACK threshold for oneway detection",
        )
        @click.option(
            "--enable-time-align-allow-empty",
            is_flag=True,
            default=False,
            help="Allow empty aligned result in time-align step",
        )
        @click.option(
            "--disable-time-align-allow-empty",
            is_flag=True,
            default=False,
            help="Disallow empty aligned result in time-align step",
        )
        @click.option("--archive-compress", is_flag=True, default=False, help="Compress archived originals")
        @click.option("--no-archive-compress", is_flag=True, default=False, help="Do not compress archived originals")
        @click.option(
            "-w",
            "--workers",
            type=int,
            default=None,
            help="Number of worker processes (default from config)",
        )
        @click.option("--no-report", "no_report", is_flag=True, default=False, help="Disable Markdown report")
        @click.option(
            "--report-path",
            type=click.Path(path_type=Path),
            default=None,
            help="Custom path for Markdown report",
        )
        @click.option(
            "--silent",
            "silent",
            is_flag=True,
            default=False,
            help=(
                "Silent mode: suppress info and warning logs from preprocess "
                "steps (errors are still shown)"
            ),
        )
        @click.pass_context
        def preprocess_command(  # noqa: PLR0913 - many CLI options by design
            ctx: click.Context,
            input_path: str,
            output_dir: Path | None,
            config_path: Path | None,
            steps: Sequence[str],
            enable_dedup: bool,
            disable_dedup: bool,
            enable_oneway: bool,
            disable_oneway: bool,
            enable_time_align: bool,
            disable_time_align: bool,
            enable_archive_original: bool,
            disable_archive_original: bool,
            dedup_window_packets: int | None,
            dedup_ignore_bytes: int | None,
            oneway_ack_threshold: int | None,
            enable_time_align_allow_empty: bool,
            disable_time_align_allow_empty: bool,
            archive_compress: bool,
            no_archive_compress: bool,
            workers: int | None,
            no_report: bool,
            report_path: Path | None,
            silent: bool,
        ) -> None:
            """Preprocess PCAP files before further analysis.

            This command prepares raw capture files by aligning capture times,
            deduplicating packets, detecting one-way streams, and optionally
            archiving the original inputs. The resulting PCAPs are cleaner and
            more consistent for downstream commands like ``analyze`` and
            ``match``.

            \b
            Steps:
              - archive-original: copy or move original PCAPs to a safe location
              - time-align: compute a common time window and trim captures
              - dedup: remove duplicate packets within a sliding window
              - oneway: detect and optionally remove one-way TCP streams

            \b
            Examples:
              # Run with default configuration (automatic steps from config)
              capmaster preprocess -i capture.pcap

              # Explicitly specify output directory
              capmaster preprocess -i capture.pcap -o preprocessed/

              # Process multiple files (comma-separated list)
              capmaster preprocess -i "a.pcap,b.pcap,c.pcap"

              # Run only selected steps in order
              capmaster preprocess -i capture.pcap --step archive-original --step time-align

              # Override individual settings from CLI
              capmaster preprocess -i capture.pcap --enable-dedup --dedup-window-packets 10

            \b
            Configuration:
              By default, settings are loaded from the preprocess YAML config
              file. CLI flags such as ``--enable/--disable-*``,
              ``--dedup-window-packets`` and ``--oneway-ack-threshold``
              override the configuration file values.
            """

            exit_code = self.execute(
                input_path=input_path,
                output_dir=output_dir,
                config_path=config_path,
                steps=list(steps),
                enable_dedup=enable_dedup,
                disable_dedup=disable_dedup,
                enable_oneway=enable_oneway,
                disable_oneway=disable_oneway,
                enable_time_align=enable_time_align,
                disable_time_align=disable_time_align,
                enable_archive_original=enable_archive_original,
                disable_archive_original=disable_archive_original,
                dedup_window_packets=dedup_window_packets,
                dedup_ignore_bytes=dedup_ignore_bytes,
                oneway_ack_threshold=oneway_ack_threshold,
                enable_time_align_allow_empty=enable_time_align_allow_empty,
                disable_time_align_allow_empty=disable_time_align_allow_empty,
                archive_compress=archive_compress,
                no_archive_compress=no_archive_compress,
                workers=workers,
                no_report=no_report,
                report_path=report_path,
                silent=silent,
            )
            ctx.exit(exit_code)

    def execute(  # type: ignore[override]
        self,
        input_path: str | Path,
        output_dir: Path | None = None,
        config_path: Path | None = None,
        steps: Sequence[str] | None = None,
        enable_dedup: bool = False,
        disable_dedup: bool = False,
        enable_oneway: bool = False,
        disable_oneway: bool = False,
        enable_time_align: bool = False,
        disable_time_align: bool = False,
        enable_archive_original: bool = False,
        disable_archive_original: bool = False,
        dedup_window_packets: int | None = None,
        dedup_ignore_bytes: int | None = None,
        oneway_ack_threshold: int | None = None,
        enable_time_align_allow_empty: bool = False,
        disable_time_align_allow_empty: bool = False,
        archive_compress: bool = False,
        no_archive_compress: bool = False,
        workers: int | None = None,
        no_report: bool = False,
        report_path: Path | None = None,
        silent: bool = False,
    ) -> int:
        """Execute the preprocess pipeline with merged configuration."""
        capmaster_logger = logging.getLogger("capmaster")
        previous_level = capmaster_logger.level

        if silent:
            capmaster_logger.setLevel(logging.ERROR)

        try:
            # Validate flag pairs
            _check_flag_pair(enable_dedup, disable_dedup, "dedup")
            _check_flag_pair(enable_oneway, disable_oneway, "oneway")
            _check_flag_pair(enable_time_align, disable_time_align, "time-align")
            _check_flag_pair(
                enable_archive_original,
                disable_archive_original,
                "archive-original",
            )
            _check_flag_pair(
                enable_time_align_allow_empty,
                disable_time_align_allow_empty,
                "time-align-allow-empty",
            )
            _check_flag_pair(archive_compress, no_archive_compress, "archive-compress")

            # Disallow mixing --step with enable/disable flags
            if steps:
                flag_used = any(
                    [
                        enable_dedup,
                        disable_dedup,
                        enable_oneway,
                        disable_oneway,
                        enable_time_align,
                        disable_time_align,
                        enable_archive_original,
                        disable_archive_original,
                    ]
                )
                if flag_used:
                    raise CapMasterError(
                        "Cannot mix --step with enable/disable flags",
                        "Use either --step for explicit steps or flags for automatic mode.",
                    )

            # Discover PCAP files
            input_str = str(input_path)
            input_paths = PcapScanner.parse_input(input_str)
            preserve_order = "," in input_str
            pcap_files = PcapScanner.scan(input_paths, recursive=False, preserve_order=preserve_order)

            if not pcap_files:
                raise NoPcapFilesError(Path(input_paths[0]))

            if output_dir is None:
                # Default: create "preprocessed" directory next to first input path
                base = Path(input_paths[0])
                base_dir = base if base.is_dir() else base.parent
                output_dir = base_dir / "preprocessed"

            # Build CLI overrides for configuration
            cli_overrides: dict[str, Any] = {}

            if enable_dedup:
                cli_overrides["dedup_enabled"] = True
            elif disable_dedup:
                cli_overrides["dedup_enabled"] = False

            if enable_oneway:
                cli_overrides["oneway_enabled"] = True
            elif disable_oneway:
                cli_overrides["oneway_enabled"] = False

            if enable_time_align:
                cli_overrides["time_align_enabled"] = True
            elif disable_time_align:
                cli_overrides["time_align_enabled"] = False

            if enable_archive_original:
                cli_overrides["archive_original"] = True
            elif disable_archive_original:
                cli_overrides["archive_original"] = False

            if enable_time_align_allow_empty:
                cli_overrides["time_align_allow_empty"] = True
            elif disable_time_align_allow_empty:
                cli_overrides["time_align_allow_empty"] = False

            if archive_compress:
                cli_overrides["archive_compress"] = True
            elif no_archive_compress:
                cli_overrides["archive_compress"] = False

            if dedup_window_packets is not None:
                cli_overrides["dedup_window_packets"] = dedup_window_packets
            if dedup_ignore_bytes is not None:
                cli_overrides["dedup_ignore_bytes"] = dedup_ignore_bytes
            if oneway_ack_threshold is not None:
                cli_overrides["oneway_ack_threshold"] = oneway_ack_threshold
            if workers is not None:
                cli_overrides["workers"] = workers
            if no_report:
                cli_overrides["report_enabled"] = False
            if report_path is not None:
                cli_overrides["report_path"] = str(report_path)

            runtime = build_runtime_config(config_file=config_path, cli_overrides=cli_overrides)

            # Execute pipeline (step list is None => automatic mode)
            result_files = run_preprocess(runtime, pcap_files, output_dir, steps=steps or None)

            logger.info("Preprocess completed, %d file(s) produced", len(result_files))
            return 0

        except (OSError, PermissionError) as e:
            error = CapMasterError(
                f"File system error: {e}",
                "Check file permissions and disk space.",
            )
            show_traceback = logger.getEffectiveLevel() <= logging.DEBUG
            return handle_error(error, show_traceback=show_traceback)
        except Exception as e:  # pragma: no cover - generic safety net
            show_traceback = logger.getEffectiveLevel() <= logging.DEBUG
            return handle_error(e, show_traceback=show_traceback)
        finally:
            if silent:
                capmaster_logger.setLevel(previous_level)

