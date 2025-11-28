"""Preprocess plugin for cleaning and standardising PCAP files."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

import logging
import click

from capmaster.core.file_scanner import PcapScanner
from capmaster.core.input_manager import InputManager
from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.preprocess.config import build_runtime_config
from capmaster.plugins.preprocess.pipeline import (
    STEP_DEDUP,
    STEP_ONEWAY,
    STEP_TIME_ALIGN,
    run_preprocess,
)
from capmaster.utils.cli_options import unified_input_options
from capmaster.utils.errors import CapMasterError, NoPcapFilesError, handle_error
from capmaster.utils.logger import get_logger

logger = get_logger(__name__)

VALID_STEPS: Sequence[str] = (
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

        @cli_group.command(name="preprocess", context_settings=dict(help_option_names=["-h", "--help"]))
        @unified_input_options
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
            help="Explicit step list (time-align,dedup,oneway)",
        )
        @click.option("--enable-dedup", is_flag=True, default=False, help="Enable dedup step")
        @click.option("--disable-dedup", is_flag=True, default=False, help="Disable dedup step")
        @click.option("--enable-oneway", is_flag=True, default=False, help="Enable oneway step")
        @click.option("--disable-oneway", is_flag=True, default=False, help="Disable oneway step")
        @click.option("--enable-time-align", is_flag=True, default=False, help="Enable time-align step")
        @click.option("--disable-time-align", is_flag=True, default=False, help="Disable time-align step")
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
        @click.option(
            "--archive-original-files",
            is_flag=True,
            default=False,
            help="Archive input PCAP files into archive.tar.gz and remove the originals",
        )
        @click.option(
            "--no-archive-original-files",
            is_flag=True,
            default=False,
            help="Do not archive and remove original input PCAP files",
        )
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
            input_path: str | None,
            file1: Path | None,
            file2: Path | None,
            file3: Path | None,
            file4: Path | None,
            file5: Path | None,
            file6: Path | None,
            silent_exit: bool,
            output_dir: Path | None,
            config_path: Path | None,
            steps: Sequence[str],
            enable_dedup: bool,
            disable_dedup: bool,
            enable_oneway: bool,
            disable_oneway: bool,
            enable_time_align: bool,
            disable_time_align: bool,
            dedup_window_packets: int | None,
            dedup_ignore_bytes: int | None,
            oneway_ack_threshold: int | None,
            enable_time_align_allow_empty: bool,
            disable_time_align_allow_empty: bool,
            archive_original_files: bool,
            no_archive_original_files: bool,
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
              - time-align: compute a common time window and trim captures
              - dedup: remove duplicate packets within a sliding window
              - oneway: detect and optionally remove one-way TCP streams

            Additionally, you can archive the original input PCAP files into
            a compressed tarball and remove them afterwards using the
            ``--archive-original-files`` flag.

            \b
            Examples:
              # Run with default configuration (automatic steps from config)
              capmaster preprocess -i capture.pcap

              # Explicitly specify output directory
              capmaster preprocess -i capture.pcap -o prep/

              # Process multiple files (comma-separated list)
              capmaster preprocess -i "a.pcap,b.pcap,c.pcap"

              # Run only selected steps in order
              capmaster preprocess -i capture.pcap --step time-align --step dedup

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
                file1=file1,
                file2=file2,
                file3=file3,
                file4=file4,
                file5=file5,
                file6=file6,
                silent_exit=silent_exit,
                output_dir=output_dir,
                config_path=config_path,
                steps=list(steps),
                enable_dedup=enable_dedup,
                disable_dedup=disable_dedup,
                enable_oneway=enable_oneway,
                disable_oneway=disable_oneway,
                enable_time_align=enable_time_align,
                disable_time_align=disable_time_align,
                dedup_window_packets=dedup_window_packets,
                dedup_ignore_bytes=dedup_ignore_bytes,
                oneway_ack_threshold=oneway_ack_threshold,
                enable_time_align_allow_empty=enable_time_align_allow_empty,
                disable_time_align_allow_empty=disable_time_align_allow_empty,
                archive_original_files=archive_original_files,
                no_archive_original_files=no_archive_original_files,
                workers=workers,
                no_report=no_report,
                report_path=report_path,
                silent=silent,
            )
            ctx.exit(exit_code)

    def execute(  # type: ignore[override]
        self,
        input_path: str | None = None,
        file1: Path | None = None,
        file2: Path | None = None,
        file3: Path | None = None,
        file4: Path | None = None,
        file5: Path | None = None,
        file6: Path | None = None,
        silent_exit: bool = False,
        output_dir: Path | None = None,
        config_path: Path | None = None,
        steps: Sequence[str] | None = None,
        enable_dedup: bool = False,
        disable_dedup: bool = False,
        enable_oneway: bool = False,
        disable_oneway: bool = False,
        enable_time_align: bool = False,
        disable_time_align: bool = False,
        dedup_window_packets: int | None = None,
        dedup_ignore_bytes: int | None = None,
        oneway_ack_threshold: int | None = None,
        enable_time_align_allow_empty: bool = False,
        disable_time_align_allow_empty: bool = False,
        archive_original_files: bool = False,
        no_archive_original_files: bool = False,
        workers: int | None = None,
        no_report: bool = False,
        report_path: Path | None = None,
        silent: bool = False,
        **kwargs: Any,
    ) -> int:
        """Execute the preprocess pipeline with merged configuration.

        The ``silent`` flag only affects this plugin's logger to avoid
        changing the global ``capmaster`` logger level, which could
        interfere with other commands running in the same process.
        """
        plugin_logger = logger
        previous_level = plugin_logger.level

        if silent:
            plugin_logger.setLevel(logging.ERROR)

        try:
            # Resolve inputs
            file_args = {
                1: file1, 2: file2, 3: file3, 4: file4, 5: file5, 6: file6
            }
            input_files = InputManager.resolve_inputs(input_path, file_args)
            
            # Validate for PreprocessPlugin (needs at least 1 file)
            InputManager.validate_file_count(input_files, min_files=1, silent_exit=silent_exit)
            
            pcap_files = [f.path for f in input_files]

            # Validate flag pairs
            _check_flag_pair(enable_dedup, disable_dedup, "dedup")
            _check_flag_pair(enable_oneway, disable_oneway, "oneway")
            _check_flag_pair(enable_time_align, disable_time_align, "time-align")
            _check_flag_pair(
                enable_time_align_allow_empty,
                disable_time_align_allow_empty,
                "time-align-allow-empty",
            )
            _check_flag_pair(
                archive_original_files,
                no_archive_original_files,
                "archive-original-files",
            )

            # Disallow mixing --step with enable/disable flags (for step-toggling flags only)
            if steps:
                flag_used = any(
                    [
                        enable_dedup,
                        disable_dedup,
                        enable_oneway,
                        disable_oneway,
                        enable_time_align,
                        disable_time_align,
                    ]
                )
                if flag_used:
                    raise CapMasterError(
                        "Cannot mix --step with enable/disable flags",
                        "Use either --step for explicit steps or flags for automatic mode.",
                    )

            if output_dir is None:
                # Default: write outputs next to the original input PCAPs
                if input_path:
                    # If input_path is a directory, use it.
                    p = Path(input_path.split(',')[0].strip())
                    if p.is_dir():
                        output_dir = p
                    else:
                        output_dir = p.parent
                elif pcap_files:
                    output_dir = pcap_files[0].parent
                else:
                    # Should be caught by validate_file_count, but safe fallback
                    output_dir = Path.cwd()

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

            if enable_time_align_allow_empty:
                cli_overrides["time_align_allow_empty"] = True
            elif disable_time_align_allow_empty:
                cli_overrides["time_align_allow_empty"] = False

            if archive_original_files:
                cli_overrides["archive_original_files"] = True
            elif no_archive_original_files:
                cli_overrides["archive_original_files"] = False

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

        except click.exceptions.Exit as exc:
            # Allow Click's silent-exit (exit code 0) or other explicit exits to propagate cleanly
            return exc.exit_code
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
                plugin_logger.setLevel(previous_level)

