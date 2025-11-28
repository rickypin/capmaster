"""Analyze plugin for PCAP file analysis."""

from __future__ import annotations

import logging
from contextlib import contextmanager, nullcontext
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import click
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from capmaster.core.file_scanner import PcapScanner
from capmaster.core.input_manager import InputManager
from capmaster.core.output_manager import OutputManager
from capmaster.core.protocol_detector import ProtocolDetector
from capmaster.core.tshark_wrapper import TsharkWrapper
from capmaster.plugins.analyze.executor import AnalysisExecutor
from capmaster.plugins.analyze.modules import discover_modules, get_all_modules
from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.utils.cli_options import unified_input_options
from capmaster.utils.errors import (
    NoPcapFilesError,
    OutputDirectoryError,
    TsharkExecutionError,
    TsharkNotFoundError,
    handle_error,
)
from capmaster.utils.logger import get_logger

logger = get_logger(__name__)


@contextmanager
def _silence_analyze_logger(enabled: bool):
    """Temporarily elevate logger level to suppress info/warn output."""
    if not enabled:
        yield
        return

    previous_level = logger.level
    logger.setLevel(logging.ERROR)
    try:
        yield
    finally:
        logger.setLevel(previous_level)


def _process_single_file(
    pcap_file: Path,
    output_dir: Path | None,
    output_format: str = "txt",
    selected_modules: tuple[str, ...] | None = None,
    generate_sidecar: bool = False,
) -> tuple[Path, int]:
    """
    Process a single PCAP file (used for multiprocessing).

    This function is called in worker processes. Module discovery is done once
    in the main process, but may need to be repeated in worker processes depending
    on the multiprocessing start method (fork vs spawn).

    Args:
        pcap_file: Path to PCAP file
        output_dir: Optional output directory
        output_format: Output format ("txt" or "md", default: "txt")
        selected_modules: Optional tuple of module names to run
    generate_sidecar: Whether to write sidecar metadata files alongside outputs

    Returns:
        Tuple of (pcap_file, number of outputs generated)
    """
    # Initialize components (each worker needs its own instances)
    # These are lightweight and necessary for process safety
    tshark = TsharkWrapper()
    protocol_detector = ProtocolDetector(tshark)
    executor = AnalysisExecutor(tshark, protocol_detector)

    # Get module classes from registry
    # If registry is empty (spawn mode), discover modules
    module_classes = get_all_modules()
    if not module_classes:
        discover_modules()
        module_classes = get_all_modules()

    modules = [module_class() for module_class in module_classes]

    # Filter modules if specific modules are requested
    if selected_modules:
        modules = [m for m in modules if m.name in selected_modules]

    # Create output directory
    output_path = OutputManager.create_output_dir(pcap_file, output_dir)

    # Execute analysis modules
    # Note: sequence parameter is no longer needed as it's handled internally per module
    results = executor.execute_modules(
        input_file=pcap_file,
        output_dir=output_path,
        modules=modules,
        output_format=output_format,
        generate_sidecar=generate_sidecar,
    )

    return (pcap_file, len(results))


@register_plugin
class AnalyzePlugin(PluginBase):
    """Plugin for analyzing PCAP files and generating statistics."""

    @property
    def name(self) -> str:
        """Plugin name."""
        return "analyze"

    def setup_cli(self, cli_group: click.Group) -> None:
        """
        Register CLI subcommand for analyze plugin.

        Args:
            cli_group: Click group to register the subcommand to
        """

        @cli_group.command(name=self.name, context_settings=dict(help_option_names=["-h", "--help"]))
        @unified_input_options
        @click.option(
            "-o",
            "--output",
            "output_dir",
            type=click.Path(path_type=Path),
            help="Output directory (default: <input_dir>/statistics/)",
        )
        @click.option(
            "-w",
            "--workers",
            type=int,
            default=1,
            help="Number of worker processes for concurrent processing (default: 1)",
        )
        @click.option(
            "-f",
            "--format",
            "output_format",
            type=click.Choice(["txt", "md"], case_sensitive=False),
            default="txt",
            help="Output file format: txt or md (default: txt)",
        )
        @click.option(
            "-m",
            "--modules",
            "selected_modules",
            multiple=True,
            type=str,
            help="Specific modules to run (e.g., -m protocol_hierarchy -m dns_stats). If not specified, run all modules.",
        )
        @click.option(
            "--sidecar",
            "generate_sidecar",
            is_flag=True,
            help="Generate a JSON sidecar (*.meta.json) for each module output.",
        )
        @click.pass_context
        def analyze_command(
            ctx: click.Context,
            input_path: str | None,
            file1: Path | None,
            file2: Path | None,
            file3: Path | None,
            file4: Path | None,
            file5: Path | None,
            file6: Path | None,
            allow_no_input: bool,
            strict: bool,
            quiet: bool,
            output_dir: Path | None,
            workers: int,
            output_format: str,
            selected_modules: tuple[str, ...],
            generate_sidecar: bool,
        ) -> None:
            """
            Analyze PCAP files and generate statistics.

            This command analyzes PCAP files and generates various statistics including:
            - Protocol hierarchy
            - TCP/UDP conversations
            - DNS, HTTP, TLS statistics
            - ICMP statistics
            - IPv4 hosts

            \b
            Examples:
              # Analyze a single PCAP file
              capmaster analyze -i capture.pcap

              # Analyze all PCAP files in a directory (non-recursive)
              capmaster analyze -i captures/

              # Analyze comma-separated file list
              capmaster analyze -i "file1.pcap,file2.pcap,file3.pcap"

              # Analyze with verbose output
              capmaster -v analyze -i capture.pcap

              # Analyze with concurrent processing (4 workers)
              capmaster analyze -i captures/ -w 4

              # Generate output in Markdown format
              capmaster analyze -i capture.pcap -f md

              # Run only specific modules
              capmaster analyze -i capture.pcap -m protocol_hierarchy
              capmaster analyze -i capture.pcap -m protocol_hierarchy -m dns_stats

            \b
            Concurrent Processing:
              Use -w/--workers to enable concurrent processing of multiple files.
              Default is 1 (sequential). Recommended: number of CPU cores.

            \b
            Module Selection:
              Use -m/--modules to run specific analysis modules.
              Can be specified multiple times to run multiple modules.
              If not specified, all available modules will be run.

            \b
            Output:
              Statistics files are saved to <input_dir>/statistics/ by default.
              Each statistic is saved in a separate file with the specified format.
              Supported formats: txt (default), md (Markdown)
            """
            exit_code = self.execute(
                input_path=input_path,
                file1=file1,
                file2=file2,
                file3=file3,
                file4=file4,
                file5=file5,
                file6=file6,
                allow_no_input=allow_no_input,
                strict=strict,
                quiet=quiet,
                output_dir=output_dir,
                workers=workers,
                output_format=output_format,
                selected_modules=selected_modules,
                generate_sidecar=generate_sidecar,
            )
            ctx.exit(exit_code)

    def execute(
        self,
        input_path: str | None = None,
        file1: Path | None = None,
        file2: Path | None = None,
        file3: Path | None = None,
        file4: Path | None = None,
        file5: Path | None = None,
        file6: Path | None = None,
        allow_no_input: bool = False,
        strict: bool = False,
        quiet: bool = False,
        output_dir: Path | None = None,
        workers: int = 1,
        output_format: str = "txt",
        selected_modules: tuple[str, ...] | None = None,
        generate_sidecar: bool = False,
        **kwargs: Any,
    ) -> int:
        """Execute analyze plugin logic."""
        effective_quiet = quiet

        with _silence_analyze_logger(effective_quiet):
            return self._execute_impl(
                input_path=input_path,
                file1=file1,
                file2=file2,
                file3=file3,
                file4=file4,
                file5=file5,
                file6=file6,
                allow_no_input=allow_no_input,
                strict=strict,
                quiet=quiet,
                output_dir=output_dir,
                workers=workers,
                output_format=output_format,
                selected_modules=selected_modules,
                generate_sidecar=generate_sidecar,
                **kwargs,
            )

    def _execute_impl(
        self,
        input_path: str | None = None,
        file1: Path | None = None,
        file2: Path | None = None,
        file3: Path | None = None,
        file4: Path | None = None,
        file5: Path | None = None,
        file6: Path | None = None,
        allow_no_input: bool = False,
        strict: bool = False,
        quiet: bool = False,
        output_dir: Path | None = None,
        workers: int = 1,
        output_format: str = "txt",
        selected_modules: tuple[str, ...] | None = None,
        generate_sidecar: bool = False,
        **kwargs: Any,
    ) -> int:
        # Resolve inputs
        file_args = {
            1: file1, 2: file2, 3: file3, 4: file4, 5: file5, 6: file6
        }
        input_files = InputManager.resolve_inputs(input_path, file_args)
        
        # Validate for AnalyzePlugin (needs at least 1 file)
        InputManager.validate_file_count(
            input_files,
            min_files=1,
            allow_no_input=allow_no_input,
        )
        
        pcap_files = [f.path for f in input_files]

        if output_dir is not None and not isinstance(output_dir, Path):
            logger.error("Output directory must be a Path object")
            return 1

        if not isinstance(workers, int) or workers < 1:
            workers = 1

        if not isinstance(output_format, str):
            output_format = "txt"

        try:
            # Initialize core components
            tshark = TsharkWrapper()

            protocol_detector = ProtocolDetector(tshark)
            executor = AnalysisExecutor(tshark, protocol_detector)

            # Discover and instantiate all analysis modules
            discover_modules()
            module_classes = get_all_modules()
            modules = [module_class() for module_class in module_classes]

            if not modules:
                logger.warning("No analysis modules found")
                return 1

            # Filter modules if specific modules are requested
            if selected_modules:
                # Get all available module names
                available_modules = {m.name for m in modules}

                # Validate that all selected modules exist
                invalid_modules = set(selected_modules) - available_modules
                if invalid_modules:
                    logger.error(f"Unknown module(s): {', '.join(sorted(invalid_modules))}")
                    logger.error(f"Available modules: {', '.join(sorted(available_modules))}")
                    return 1

                # Filter modules to only selected ones
                modules = [m for m in modules if m.name in selected_modules]
                logger.info(f"Running {len(modules)} selected module(s): {', '.join(sorted(selected_modules))}")
            else:
                logger.info(f"Loaded {len(modules)} analysis modules")

            logger.info(f"Found {len(pcap_files)} PCAP file(s)")

            # Process files with progress bar
            total_outputs = 0
            failed_files = 0

            progress_ctx = nullcontext() if quiet else Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
            )

            with progress_ctx as progress:
                # Create overall progress task
                overall_task = None
                if progress:
                    overall_task = progress.add_task(
                        f"[cyan]Analyzing {len(pcap_files)} file(s)...",
                        total=len(pcap_files)
                    )

                # Use concurrent processing if workers > 1
                if workers > 1 and len(pcap_files) > 1:
                    logger.info(f"Using {workers} worker processes")

                    with ProcessPoolExecutor(max_workers=workers) as pool:
                        # Submit all tasks
                        futures = {
                            pool.submit(
                                _process_single_file,
                                pcap_file,
                                output_dir,
                                output_format,
                                selected_modules,
                                generate_sidecar,
                            ): pcap_file
                            for pcap_file in pcap_files
                        }

                        # Process results as they complete
                        for future in as_completed(futures):
                            pcap_file = futures[future]
                            try:
                                _, num_outputs = future.result()
                                total_outputs += num_outputs
                                logger.debug(f"Completed {pcap_file.name}: {num_outputs} outputs")
                            except Exception as e:
                                failed_files += 1
                                logger.error(f"Failed to process {pcap_file.name}: {e}")

                            if progress and overall_task:
                                progress.update(overall_task, advance=1)
                else:
                    # Sequential processing
                    for file_index, pcap_file in enumerate(pcap_files, start=1):
                        # Update progress description
                        if progress and overall_task:
                            progress.update(
                                overall_task,
                                description=f"[cyan]Analyzing {pcap_file.name} ({file_index}/{len(pcap_files)})"
                            )

                        # Create output directory
                        try:
                            output_path = OutputManager.create_output_dir(pcap_file, output_dir)
                            logger.debug(f"Output directory: {output_path}")
                        except (OSError, PermissionError) as e:
                            raise OutputDirectoryError(
                                output_dir or pcap_file.parent / "statistics",
                                str(e)
                            ) from e

                        # Execute analysis modules
                        # Note: sequence parameter is no longer needed as it's handled internally per module
                        results = executor.execute_modules(
                            input_file=pcap_file,
                            output_dir=output_path,
                            modules=modules,
                            progress=progress,
                            output_format=output_format,
                            generate_sidecar=generate_sidecar,
                        )

                        total_outputs += len(results)

                        # Display results
                        logger.debug(f"Generated {len(results)} output files:")
                        for _module_name, output_file in results.items():
                            logger.debug(f"  - {output_file.name}")

                        # Update overall progress
                        if progress and overall_task:
                            progress.update(overall_task, advance=1)

            if failed_files > 0:
                logger.error(
                    f"Analysis completed with errors. "
                    f"{failed_files} of {len(pcap_files)} file(s) failed"
                )
                logger.info(
                    f"Total outputs generated from successful files: {total_outputs}"
                )
                return 1

            logger.info(f"Analysis complete. Total outputs: {total_outputs}")
            return 0

        except (TsharkNotFoundError, TsharkExecutionError, NoPcapFilesError, OutputDirectoryError) as e:
            # Expected business errors - handle gracefully
            return handle_error(e, show_traceback=False)
        except (OSError, PermissionError) as e:
            # File system errors
            from capmaster.utils.errors import CapMasterError
            error = CapMasterError(
                f"File system error: {e}",
                "Check file permissions and disk space"
            )
            return handle_error(error, show_traceback=logger.level <= 10)
        except Exception as e:
            # Unexpected errors - show traceback in debug mode
            return handle_error(e, show_traceback=logger.level <= logging.DEBUG)
