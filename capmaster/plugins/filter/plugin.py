"""
Filter plugin for removing one-way TCP connections.

This plugin identifies and removes one-way TCP connections from PCAP files.
"""

from __future__ import annotations
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import click
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from capmaster.core.file_scanner import PcapScanner
from capmaster.core.tshark_wrapper import TsharkWrapper
from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.filter.detector import OneWayDetector, TcpPacketInfo
from capmaster.utils.errors import (
    NoPcapFilesError,
    handle_error,
)
from capmaster.utils.logger import get_logger

logger = get_logger(__name__)


def _detect_one_way_streams_helper(pcap_file: Path, ack_threshold: int) -> list[int]:
    """
    Detect one-way streams in a PCAP file (helper for multiprocessing).

    Args:
        pcap_file: Path to PCAP file
        ack_threshold: ACK increment threshold

    Returns:
        List of one-way stream IDs
    """
    # Initialize TsharkWrapper
    tshark = TsharkWrapper()

    # Build tshark arguments for extracting TCP packet information
    args = [
        "-T",
        "fields",
        "-e",
        "tcp.stream",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.ack",
        "-e",
        "tcp.len",
        "-E",
        "separator=\t",
        "-Y",
        "tcp",
    ]

    try:
        result = tshark.execute(args=args, input_file=pcap_file)
    except subprocess.CalledProcessError as e:
        logger.error(f"tshark failed: {e.stderr}")
        return []

    # Parse packets and feed to detector
    detector = OneWayDetector(ack_threshold=ack_threshold)

    for line in result.stdout.strip().split("\n"):
        if not line:
            continue

        parts = line.split("\t")
        if len(parts) < 7:
            continue

        try:
            packet = TcpPacketInfo(
                stream_id=int(parts[0]),
                src_ip=parts[1],
                src_port=int(parts[2]),
                dst_ip=parts[3],
                dst_port=int(parts[4]),
                ack=int(parts[5]) if parts[5] else 0,
                tcp_len=int(parts[6]) if parts[6] else 0,
            )
            detector.add_packet(packet)
        except (ValueError, IndexError):
            continue

    # Get one-way streams
    one_way_streams = []
    for analysis in detector.analyze():
        one_way_streams.append(analysis.stream_id)

    return one_way_streams


def _filter_single_file(
    pcap_file: Path,
    output_path: Path | None,
    ack_threshold: int,
) -> tuple[Path, int]:
    """
    Filter a single PCAP file (used for multiprocessing).

    Args:
        pcap_file: Path to PCAP file
        output_path: Optional output path
        ack_threshold: ACK increment threshold

    Returns:
        Tuple of (pcap_file, number of one-way streams found)
    """
    try:
        # Determine output file
        if output_path:
            if output_path.is_dir():
                out_file = output_path / f"{pcap_file.stem}_filtered{pcap_file.suffix}"
            else:
                out_file = output_path
        else:
            out_file = pcap_file.parent / f"{pcap_file.stem}_filtered{pcap_file.suffix}"

        # Detect one-way streams
        one_way_streams = _detect_one_way_streams_helper(pcap_file, ack_threshold)

        # Filter the file
        if not one_way_streams:
            import shutil
            shutil.copy2(pcap_file, out_file)
        else:
            # Initialize TsharkWrapper
            tshark = TsharkWrapper()

            # Build display filter to exclude one-way streams
            stream_filters = [f"tcp.stream != {stream_id}" for stream_id in one_way_streams]
            display_filter = " and ".join(stream_filters)

            # Build tshark arguments for PCAP output
            args = [
                "-Y",
                display_filter,
                "-w",
                str(out_file),
            ]

            tshark.execute(args=args, input_file=pcap_file)

        return (pcap_file, len(one_way_streams))
    except (OSError, PermissionError) as e:
        # File system errors (permissions, disk full, etc.)
        logger.error(f"File system error filtering {pcap_file}: {e}")
        return (pcap_file, 0)
    except RuntimeError as e:
        # Tshark execution errors
        logger.error(f"Tshark error filtering {pcap_file}: {e}")
        return (pcap_file, 0)
    except Exception as e:
        # Unexpected errors - log with more detail
        logger.exception(f"Unexpected error filtering {pcap_file}: {e}")
        return (pcap_file, 0)


@register_plugin
class FilterPlugin(PluginBase):
    """Plugin for filtering one-way TCP connections."""

    @property
    def name(self) -> str:
        """Plugin name."""
        return "filter"

    def setup_cli(self, cli_group: click.Group) -> None:
        """Register the filter command."""

        @cli_group.command(name="filter")
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
            "output_path",
            type=click.Path(path_type=Path),
            help="Output PCAP file or directory (default: <input>_filtered.pcap)",
        )
        @click.option(
            "-t",
            "--threshold",
            type=int,
            default=20,
            help="ACK increment threshold for one-way detection (default: 20)",
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
        @click.pass_context
        def filter_command(
            ctx: click.Context,
            input_path: str,
            output_path: Path | None,
            threshold: int,
            no_recursive: bool,
            workers: int,
        ) -> None:
            """
            Remove one-way TCP connections from PCAP files.

            This command identifies and removes one-way TCP connections (connections
            where only one side is sending data) from PCAP files. This is useful for
            cleaning up packet captures that contain incomplete or asymmetric traffic.

            Detection is based on ACK increment analysis - connections where ACK values
            don't increase significantly are considered one-way.

            \b
            Examples:
              # Filter a single PCAP file
              capmaster filter -i capture.pcap

              # Filter with custom output file
              capmaster filter -i capture.pcap -o clean.pcap

              # Filter comma-separated file list
              capmaster filter -i "file1.pcap,file2.pcap,file3.pcap"

              # Filter all PCAP files in a directory (recursive by default)
              capmaster filter -i captures/ -o filtered/

              # Filter only top-level directory (no recursion)
              capmaster filter -i captures/ -r -o filtered/

              # Filter with custom ACK threshold
              capmaster filter -i capture.pcap -t 50

              # Filter with verbose output
              capmaster -v filter -i capture.pcap

              # Filter with concurrent processing (4 workers)
              capmaster filter -i captures/ -w 4

            \b
            Threshold:
              The -t/--threshold option controls the ACK increment threshold.
              Lower values are more strict (detect more one-way connections).
              Default is 20, which works well for most cases.

            \b
            Concurrent Processing:
              Use -w/--workers to enable concurrent processing of multiple files.
              Default is 1 (sequential). Recommended: number of CPU cores.

            \b
            Output:
              Filtered PCAP files are saved with '_filtered' suffix by default.
              Original files are never modified.
            """
            # Default is recursive (matching original script behavior)
            recursive = not no_recursive
            exit_code = self.execute(
                input_path=input_path,
                output_path=output_path,
                ack_threshold=threshold,
                recursive=recursive,
                workers=workers,
            )
            ctx.exit(exit_code)

    def execute(  # type: ignore[override]
        self,
        input_path: str | Path,
        output_path: Path | None = None,
        ack_threshold: int = 20,
        recursive: bool = True,
        workers: int = 1,
    ) -> int:
        """
        Execute the filter plugin.

        Args:
            input_path: Input PCAP file, directory, or comma-separated file list
            output_path: Output PCAP file or directory
            ack_threshold: ACK increment threshold
            recursive: Whether to recursively scan directories (default: True)
            workers: Number of worker processes for concurrent processing

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Parse input path (supports comma-separated file list)
            if isinstance(input_path, str):
                input_paths = PcapScanner.parse_input(input_path)
            else:
                input_paths = [str(input_path)]

            # Scan for PCAP files using PcapScanner (consistent with analyze plugin)
            pcap_files = PcapScanner.scan(input_paths, recursive=recursive)

            if not pcap_files:
                raise NoPcapFilesError(str(input_path))

            logger.info(f"Found {len(pcap_files)} PCAP file(s)")

            # Process files with progress bar
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
            ) as progress:
                overall_task = progress.add_task(
                    f"[cyan]Filtering {len(pcap_files)} file(s)...",
                    total=len(pcap_files)
                )

                # Use concurrent processing if workers > 1
                if workers > 1 and len(pcap_files) > 1:
                    logger.info(f"Using {workers} worker processes")

                    with ProcessPoolExecutor(max_workers=workers) as pool:
                        # Submit all tasks
                        futures = {
                            pool.submit(_filter_single_file, pcap_file, output_path, ack_threshold): pcap_file
                            for pcap_file in pcap_files
                        }

                        # Process results as they complete
                        for future in as_completed(futures):
                            pcap_file = futures[future]
                            try:
                                _, num_one_way = future.result()
                                logger.info(f"Completed {pcap_file.name}: {num_one_way} one-way streams")
                            except Exception as e:
                                logger.error(f"Failed to filter {pcap_file.name}: {e}")

                            progress.update(overall_task, advance=1)
                else:
                    # Sequential processing
                    for idx, pcap_file in enumerate(pcap_files, start=1):
                        progress.update(
                            overall_task,
                            description=f"[cyan]Processing {pcap_file.name} ({idx}/{len(pcap_files)})"
                        )
                        logger.info(f"Processing {pcap_file}...")

                        # Determine output file
                        if output_path:
                            if output_path.is_dir():
                                out_file = output_path / f"{pcap_file.stem}_filtered{pcap_file.suffix}"
                            else:
                                out_file = output_path
                        else:
                            out_file = pcap_file.parent / f"{pcap_file.stem}_filtered{pcap_file.suffix}"

                        # Detect one-way streams
                        detect_task = progress.add_task("[yellow]Detecting one-way streams...", total=1)
                        one_way_streams = self._detect_one_way_streams(pcap_file, ack_threshold)
                        progress.update(detect_task, advance=1)

                        if not one_way_streams:
                            logger.info("No one-way streams detected")
                            # Copy file as-is
                            import shutil

                            copy_task = progress.add_task("[green]Copying file...", total=1)
                            shutil.copy2(pcap_file, out_file)
                            progress.update(copy_task, advance=1)
                        else:
                            logger.info(f"Found {len(one_way_streams)} one-way streams")

                            # Filter the file
                            filter_task = progress.add_task("[green]Filtering PCAP...", total=1)
                            self._filter_pcap(pcap_file, out_file, one_way_streams)
                            progress.update(filter_task, advance=1)

                        logger.info(f"Output saved to: {out_file}")
                        progress.update(overall_task, advance=1)

            return 0

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

    def _detect_one_way_streams(self, pcap_file: Path, ack_threshold: int) -> list[int]:
        """
        Detect one-way TCP streams in a PCAP file.

        Args:
            pcap_file: Path to PCAP file
            ack_threshold: ACK increment threshold

        Returns:
            List of one-way stream IDs
        """
        # Extract TCP packet information
        tshark = TsharkWrapper()

        # Use tshark to extract TCP fields
        fields = [
            "tcp.stream",
            "ip.src",
            "tcp.srcport",
            "ip.dst",
            "tcp.dstport",
            "tcp.ack",
            "tcp.len",
        ]

        # Build tshark arguments
        args = ["-T", "fields", "-E", "separator=/t"]
        for field in fields:
            args.extend(["-e", field])
        args.extend(["-Y", "tcp"])

        # Create temporary file for output
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".tsv", delete=False) as tmp:
            tmp_file = Path(tmp.name)

        try:
            tshark.execute(
                args=args,
                input_file=pcap_file,
                output_file=tmp_file,
            )

            # Parse the output and detect one-way streams
            detector = OneWayDetector(ack_threshold=ack_threshold)

            with open(tmp_file, encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.strip().split("\t")
                    if len(parts) < 7:
                        continue

                    try:
                        packet = TcpPacketInfo(
                            stream_id=int(parts[0]),
                            src_ip=parts[1],
                            src_port=int(parts[2]),
                            dst_ip=parts[3],
                            dst_port=int(parts[4]),
                            ack=int(parts[5]) if parts[5] else 0,
                            tcp_len=int(parts[6]) if parts[6] else 0,
                        )
                        detector.add_packet(packet)
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Skipping invalid line: {line.strip()} ({e})")
                        continue

            # Get one-way streams
            one_way_streams = []
            for analysis in detector.analyze():
                logger.info(
                    f"One-way stream {analysis.stream_id}: "
                    f"{analysis.active_direction}, "
                    f"ACK delta={analysis.ack_delta}"
                )
                one_way_streams.append(analysis.stream_id)

            return one_way_streams

        finally:
            # Clean up temporary file
            tmp_file.unlink(missing_ok=True)

    def _filter_pcap(self, input_file: Path, output_file: Path, exclude_streams: list[int]) -> None:
        """
        Filter PCAP file to exclude specified streams.

        Args:
            input_file: Input PCAP file
            output_file: Output PCAP file
            exclude_streams: List of stream IDs to exclude
        """
        # Build tshark filter expression
        if not exclude_streams:
            # No streams to exclude, just copy
            import shutil

            shutil.copy2(input_file, output_file)
            return

        # Create filter: exclude all specified streams
        stream_filters = [f"tcp.stream != {stream_id}" for stream_id in exclude_streams]
        display_filter = " and ".join(stream_filters)

        # Use TsharkWrapper to filter
        tshark = TsharkWrapper()

        # Build tshark arguments for PCAP output
        args = [
            "-Y",
            display_filter,
            "-w",
            str(output_file),
        ]

        logger.debug(f"Filtering with display filter: {display_filter}")

        tshark.execute(args=args, input_file=input_file)
