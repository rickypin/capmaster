"""Analyze plugin for PCAP file analysis."""

from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

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
) -> tuple[Path, int]:
    """
    Process a single PCAP file (used for multiprocessing).

    Args:
        pcap_file: Path to PCAP file
        output_dir: Optional output directory
        output_format: Output format ("txt" or "md", default: "txt")

    Returns:
        Tuple of (pcap_file, number of outputs generated)
    """
    try:
        # Initialize components (each worker needs its own instances)
        tshark = TsharkWrapper()
        protocol_detector = ProtocolDetector(tshark)
        executor = AnalysisExecutor(tshark, protocol_detector)

        # Discover and instantiate modules
        discover_modules()
        module_classes = get_all_modules()
        modules = [module_class() for module_class in module_classes]

        # Create output directory
        output_path = OutputManager.create_output_dir(pcap_file, output_dir)

        # Execute analysis modules
        # Note: sequence parameter is no longer needed as it's handled internally per module
        results = executor.execute_modules(
            input_file=pcap_file,
            output_dir=output_path,
            modules=modules,
            output_format=output_format,
        )

        return (pcap_file, len(results))
    except Exception as e:
        logger.error(f"Error processing {pcap_file}: {e}")
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
            type=click.Path(exists=True, path_type=Path),
            help="Input PCAP file or directory",
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
        @click.pass_context
        def analyze_command(
            ctx: click.Context,
            input_path: Path,
            output_dir: Path | None,
            no_recursive: bool,
            workers: int,
            output_format: str,
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

              # Analyze only top-level directory (no recursion)
              capmaster analyze -i captures/ -r -o results/

              # Analyze with verbose output
              capmaster -v analyze -i capture.pcap

              # Analyze with concurrent processing (4 workers)
              capmaster analyze -i captures/ -w 4

              # Generate output in Markdown format
              capmaster analyze -i capture.pcap -f md

            \b
            Concurrent Processing:
              Use -w/--workers to enable concurrent processing of multiple files.
              Default is 1 (sequential). Recommended: number of CPU cores.

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
            )
            ctx.exit(exit_code)

    def execute(self, **kwargs: object) -> int:
        """
        Execute analyze plugin logic.

        Args:
            **kwargs: Keyword arguments including:
                - input_path: Path to input PCAP file or directory
                - output_dir: Optional custom output directory
                - recursive: Whether to recursively scan directories (default: True)
                - workers: Number of worker processes for concurrent processing
                - output_format: Output format ("txt" or "md", default: "txt")

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        # Extract arguments from kwargs
        input_path = kwargs.get("input_path")
        output_dir = kwargs.get("output_dir")
        recursive = kwargs.get("recursive", True)  # Default to True (matching original script)
        workers = kwargs.get("workers", 1)
        output_format = kwargs.get("output_format", "txt")

        if input_path is None or not isinstance(input_path, Path):
            logger.error("Input path is required and must be a Path object")
            return 1

        if output_dir is not None and not isinstance(output_dir, Path):
            logger.error("Output directory must be a Path object")
            return 1

        if not isinstance(recursive, bool):
            recursive = False

        if not isinstance(workers, int) or workers < 1:
            workers = 1

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

            logger.info(f"Loaded {len(modules)} analysis modules")

            # Scan for PCAP files
            pcap_files = PcapScanner.scan([str(input_path)], recursive=recursive)

            if not pcap_files:
                raise NoPcapFilesError(input_path)

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
                            pool.submit(_process_single_file, pcap_file, output_dir, output_format): pcap_file
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

        except Exception as e:
            return handle_error(e, verbose=logger.level <= 10)  # DEBUG level
