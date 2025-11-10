"""Analyze plugin for PCAP file analysis."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import click
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from capmaster.core.file_scanner import PcapScanner
from capmaster.core.output_manager import OutputManager
from capmaster.core.protocol_detector import ProtocolDetector
from capmaster.core.tshark_wrapper import TsharkWrapper
from capmaster.plugins.analyze.executor import AnalysisExecutor
from capmaster.plugins.analyze.modules import discover_modules, get_all_modules
from capmaster.plugins.base import PluginBase
from capmaster.utils.errors import (
    NoPcapFilesError,
    OutputDirectoryError,
    TsharkNotFoundError,
    handle_error,
)
from capmaster.utils.logger import get_logger

logger = get_logger(__name__)


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
    try:
        # Initialize components (each worker needs its own instances)
        # These are lightweight and necessary for thread safety
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
    except (OSError, PermissionError) as e:
        # File system errors (permissions, disk full, etc.)
        logger.error(f"File system error processing {pcap_file}: {e}")
        return (pcap_file, 0)
    except RuntimeError as e:
        # Tshark execution errors or other runtime issues
        logger.error(f"Runtime error processing {pcap_file}: {e}")
        return (pcap_file, 0)
    except Exception as e:
        # Unexpected errors - log with more detail for debugging
        logger.exception(f"Unexpected error processing {pcap_file}: {e}")
        return (pcap_file, 0)


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

        @cli_group.command(name=self.name)
        @click.option(
            "-i",
            "--input",
            "input_path",
            required=True,
            type=str,
            help="Input PCAP file, directory, or comma-separated file list",
        )
        @click.option(
            "-o",
            "--output",
            "output_dir",
            type=click.Path(path_type=Path),
            help="Output directory (default: <input_dir>/statistics/)",
        )
        @click.option(
            "-r",
            "--no-recursive",
            "no_recursive",
            is_flag=True,
            help="Do NOT recursively scan directories (default: recursive)",
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
            input_path: str,
            output_dir: Path | None,
            no_recursive: bool,
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

              # Analyze all PCAP files in a directory (recursive by default)
              capmaster analyze -i captures/

              # Analyze comma-separated file list
              capmaster analyze -i "file1.pcap,file2.pcap,file3.pcap"

              # Analyze only top-level directory (no recursion)
              capmaster analyze -i captures/ -r -o results/

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
            # Default is recursive (matching original script behavior)
            recursive = not no_recursive
            exit_code = self.execute(
                input_path=input_path,
                output_dir=output_dir,
                recursive=recursive,
                workers=workers,
                output_format=output_format,
                selected_modules=selected_modules if selected_modules else None,
                generate_sidecar=generate_sidecar,
            )
            ctx.exit(exit_code)

    def execute(self, **kwargs: Any) -> int:
        """
        Execute analyze plugin logic.

        Args:
            **kwargs: Keyword arguments including:
                - input_path: String path to input PCAP file, directory, or comma-separated file list
                - output_dir: Optional custom output directory
                - recursive: Whether to recursively scan directories (default: True)
                - workers: Number of worker processes for concurrent processing
                - output_format: Output format ("txt" or "md", default: "txt")
                - selected_modules: Optional tuple of module names to run
                - generate_sidecar: Whether to emit metadata sidecar files

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        # Extract arguments from kwargs
        input_path_raw = kwargs.get("input_path")
        output_dir = kwargs.get("output_dir")
        recursive = kwargs.get("recursive", True)  # Default to True (matching original script)
        workers = kwargs.get("workers", 1)
        output_format = kwargs.get("output_format", "txt")
        selected_modules_raw = kwargs.get("selected_modules")
        generate_sidecar = bool(kwargs.get("generate_sidecar", False))

        # Type narrowing for selected_modules
        selected_modules: tuple[str, ...] | None = None
        if selected_modules_raw is not None and isinstance(selected_modules_raw, tuple):
            selected_modules = selected_modules_raw

        # Validate and parse input_path
        if input_path_raw is None or not isinstance(input_path_raw, str):
            logger.error("Input path is required and must be a string")
            return 1

        if output_dir is not None and not isinstance(output_dir, Path):
            logger.error("Output directory must be a Path object")
            return 1

        if not isinstance(recursive, bool):
            recursive = False

        if not isinstance(workers, int) or workers < 1:
            workers = 1

        if not isinstance(output_format, str):
            output_format = "txt"

        try:
            # Initialize core components
            try:
                tshark = TsharkWrapper()
            except FileNotFoundError as e:
                raise TsharkNotFoundError() from e

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

            # Parse input path (supports comma-separated file list)
            input_paths = PcapScanner.parse_input(input_path_raw)

            # Scan for PCAP files
            pcap_files = PcapScanner.scan(input_paths, recursive=recursive)

            if not pcap_files:
                raise NoPcapFilesError(Path(input_path_raw))

            logger.info(f"Found {len(pcap_files)} PCAP file(s)")

            # Process files with progress bar
            total_outputs = 0
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
            ) as progress:
                # Create overall progress task
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
                                logger.error(f"Failed to process {pcap_file.name}: {e}")

                            progress.update(overall_task, advance=1)
                else:
                    # Sequential processing
                    for file_index, pcap_file in enumerate(pcap_files, start=1):
                        # Update progress description
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
                        progress.update(overall_task, advance=1)

            logger.info(f"Analysis complete. Total outputs: {total_outputs}")
            return 0

        except (TsharkNotFoundError, NoPcapFilesError, OutputDirectoryError) as e:
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
            import logging
            return handle_error(e, show_traceback=logger.level <= logging.DEBUG)
