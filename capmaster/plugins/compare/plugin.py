"""Compare plugin for packet-level TCP connection comparison."""

from __future__ import annotations
import logging
from pathlib import Path

from typing import Any

import click
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.core.input_manager import InputManager
from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.compare.packet_comparator import PacketComparator
from capmaster.plugins.compare.packet_extractor import PacketExtractor
from capmaster.utils.cli_options import validate_database_params
from capmaster.utils.errors import (
    InsufficientFilesError,
    handle_error,
)

logger = logging.getLogger(__name__)
from capmaster.plugins.compare.cli_commands import register_compare_command
from capmaster.plugins.compare.utils import to_nanoseconds, parse_tcp_flags, format_tcp_flags_change





@register_plugin
class ComparePlugin(PluginBase):
    """
    Compare TCP connections at packet level between PCAP files.

    This plugin first uses the match plugin to find matching TCP connections,
    then performs detailed packet-level comparison for each matched connection pair.

    The first file (in input order or alphabetically) is used as the baseline,
    and comparison results show differences of the second file relative to the baseline.

    Comparison includes:
    - IP ID (ipid)
    - TCP flags
    - Sequence number
    - Acknowledgment number
    """

    @property
    def name(self) -> str:
        """Plugin name (CLI subcommand)."""
        return "compare"

    def setup_cli(self, cli_group: click.Group) -> None:
        """
        Register CLI subcommand.

        Args:
            cli_group: Click group to add command to
        """

        # Delegate CLI registration to external helper to keep this module lean
        register_compare_command(self, cli_group)
        return


    def execute(  # type: ignore[override]
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
        output_file: Path | None = None,
        score_threshold: float = 0.60,
        bucket_strategy: str = "auto",
        show_flow_hash: bool = False,
        matched_only: bool = False,
        db_connection: str | None = None,
        kase_id: int | None = None,
        match_mode: str = "one-to-one",
        match_file: Path | None = None,
    ) -> int:
        """
        Execute the compare plugin.

        The first file (in input order or alphabetically) is used as the baseline,
        and comparison results show differences of the second file relative to the baseline.

        Args:
            input_path: Directory or comma-separated list of exactly 2 PCAP files (optional)
            file1: First PCAP file (baseline) (optional)
            file2: Second PCAP file (compare) (optional)
            file3-file6: Additional files (ignored)
            allow_no_input: Exit with code 0 if file count mismatch
            strict: Fail on warnings
            quiet: Suppress output
            output_file: Output file for results (None for stdout)
            score_threshold: Minimum score threshold for matching
            bucket_strategy: Bucketing strategy for matching
            show_flow_hash: Whether to calculate and display flow hash
            matched_only: Only compare packets that exist in both files with matching IPID
            db_connection: Database connection string (optional)
            kase_id: Case ID for database table name (optional)
            match_file: JSON file containing match results from match command (optional)

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Resolve inputs
            file_args = {
                1: file1, 2: file2, 3: file3, 4: file4, 5: file5, 6: file6
            }
            input_files = InputManager.resolve_inputs(input_path, file_args)
            
            # Validate for ComparePlugin (needs exactly 2 files)
            InputManager.validate_file_count(input_files, min_files=2, max_files=2, allow_no_input=allow_no_input)
            
            # Extract files
            baseline_file = input_files[0].path
            compare_file = input_files[1].path
            pcap_id_mapping = {
                str(baseline_file): input_files[0].pcapid,
                str(compare_file): input_files[1].pcapid
            }

            effective_quiet = quiet

            logger.info(f"Baseline file: {baseline_file.name}")
            logger.info(f"Compare file: {compare_file.name}")
            logger.info(f"Comparison direction: {compare_file.name} relative to {baseline_file.name}")
            if pcap_id_mapping:
                logger.info(f"PCAP ID mapping: {baseline_file.name} -> {pcap_id_mapping[str(baseline_file)]}, {compare_file.name} -> {pcap_id_mapping[str(compare_file)]}")

            # Use progress bar only if not in quiet mode
            from contextlib import nullcontext
            progress_context = nullcontext() if effective_quiet else Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
            )

            with progress_context as progress:
                # Step 1: Extract connections from both files
                extract_task = (
                    progress.add_task("[cyan]Extracting connections...", total=2)
                    if not effective_quiet
                    else None
                )

                baseline_connections = self._extract_connections(baseline_file)
                logger.info(f"Found {len(baseline_connections)} connections in {baseline_file.name}")
                if not effective_quiet:
                    progress.update(extract_task, advance=1)

                compare_connections = self._extract_connections(compare_file)
                logger.info(f"Found {len(compare_connections)} connections in {compare_file.name}")
                if not effective_quiet:
                    progress.update(extract_task, advance=1)

                # Step 2: Match connections
                match_task = (
                    progress.add_task("[yellow]Matching connections...", total=1)
                    if not effective_quiet
                    else None
                )

                if match_file:
                    # Load matches from file
                    matches = self._load_matches_from_file(
                        match_file,
                        baseline_file,
                        compare_file,
                        baseline_connections,
                        compare_connections,
                    )
                    logger.info(f"Loaded {len(matches)} matches from {match_file}")
                else:
                    # Perform matching using match plugin's in-memory method
                    # This ensures we use the same logic as the match plugin,
                    # including ServerDetector cardinality analysis
                    from capmaster.plugins.match.plugin import MatchPlugin

                    match_plugin = MatchPlugin()
                    matches = match_plugin.match_connections_in_memory(
                        baseline_connections,
                        compare_connections,
                        bucket_strategy=bucket_strategy,
                        score_threshold=score_threshold,
                        match_mode=match_mode,
                    )
                    logger.info(f"Found {len(matches)} matched connection pairs")

                if not effective_quiet:
                    progress.update(match_task, advance=1)

                if not matches:
                    logger.warning("No matching connections found")
                    return 0

                # Step 3: Compare packets for each matched connection
                compare_task = (
                    progress.add_task(
                        "[green]Comparing packets...",
                        total=len(matches),
                    )
                    if not effective_quiet
                    else None
                )

                extractor = PacketExtractor()
                comparator = PacketComparator()
                results = []

                # OPTIMIZATION: Batch extract packets for all matched connections
                # This reduces tshark invocations from 2N to 2 (one per file)
                # Collect all stream IDs from matches
                baseline_stream_ids = [match.conn1.stream_id for match in matches]
                compare_stream_ids = [match.conn2.stream_id for match in matches]

                # Extract packets for all streams in batch
                baseline_packets_by_stream = extractor.extract_multiple_streams(
                    baseline_file,
                    baseline_stream_ids,
                )
                compare_packets_by_stream = extractor.extract_multiple_streams(
                    compare_file,
                    compare_stream_ids,
                )

                # Compare packets for each matched connection
                for match in matches:
                    # Get packets for this connection from batch results
                    baseline_packets = baseline_packets_by_stream.get(match.conn1.stream_id, [])
                    compare_packets = compare_packets_by_stream.get(match.conn2.stream_id, [])

                    # Create connection identifier
                    conn_id = (
                        f"{match.conn1.client_ip}:{match.conn1.client_port} <-> "
                        f"{match.conn1.server_ip}:{match.conn1.server_port}"
                    )

                    # Compare packets (baseline vs compare)
                    result = comparator.compare(
                        baseline_packets,
                        compare_packets,
                        conn_id,
                        matched_only
                    )
                    results.append((match, baseline_packets, compare_packets, result))

                    if not effective_quiet:
                        progress.update(compare_task, advance=1)

                # Step 4: Output results
                output_task = (
                    progress.add_task("[blue]Writing results...", total=1)
                    if not effective_quiet
                    else None
                )
                self._output_results(
                    baseline_file,
                    compare_file,
                    results,
                    output_file,
                    show_flow_hash,
                    matched_only,
                    db_connection,
                    kase_id,
                    pcap_id_mapping,
                    effective_quiet,
                )
                if not effective_quiet:
                    progress.update(output_task, advance=1)

            logger.info("Comparison complete")
            return 0

        except InsufficientFilesError as e:
            # Expected business error - handle gracefully
            return handle_error(e, show_traceback=False)
        except ImportError as e:
            # Database dependency missing
            from capmaster.utils.errors import CapMasterError
            error = CapMasterError(
                f"Missing dependency: {e}",
                "Install database support with: pip install capmaster[database]"
            )
            return handle_error(error, show_traceback=False)
        except (OSError, PermissionError) as e:
            # File system errors
            from capmaster.utils.errors import CapMasterError
            error = CapMasterError(
                f"File system error: {e}",
                "Check file permissions and ensure files are accessible"
            )
            return handle_error(error, show_traceback=logger.level <= logging.DEBUG)
        except RuntimeError as e:
            # Tshark or processing errors
            from capmaster.utils.errors import CapMasterError
            error = CapMasterError(
                f"Processing error: {e}",
                "Check that PCAP files are valid and tshark is working"
            )
            return handle_error(error, show_traceback=logger.level <= logging.DEBUG)
        except Exception as e:
            # Unexpected errors - show traceback in debug mode
            return handle_error(e, show_traceback=logger.level <= logging.DEBUG)

    def _extract_connections(self, pcap_file: Path):
        """Extract TCP connections from a PCAP file."""
        return extract_connections_from_pcap(pcap_file)

    def _load_matches_from_file(
        self,
        match_file: Path,
        baseline_file: Path,
        compare_file: Path,
        baseline_connections: list,
        compare_connections: list,
    ) -> list:
        """
        Load matches from a JSON file and validate against current connections.

        Args:
            match_file: Path to JSON file containing match results
            baseline_file: Path to baseline PCAP file
            compare_file: Path to compare PCAP file
            baseline_connections: List of connections from baseline file
            compare_connections: List of connections from compare file

        Returns:
            List of ConnectionMatch objects

        Raises:
            ValueError: If match file is invalid or doesn't match current files
        """
        from capmaster.core.connection.match_serializer import MatchSerializer

        # Load matches from file
        matches, metadata = MatchSerializer.load_matches(match_file)

        # Validate file paths
        expected_file1 = str(baseline_file)
        expected_file2 = str(compare_file)
        actual_file1 = metadata.get("file1")
        actual_file2 = metadata.get("file2")

        # Check if files match (allow for different paths to same file)
        if Path(actual_file1).name != baseline_file.name or Path(actual_file2).name != compare_file.name:
            logger.warning(
                f"Match file was created for different files:\n"
                f"  Expected: {baseline_file.name}, {compare_file.name}\n"
                f"  Actual:   {Path(actual_file1).name}, {Path(actual_file2).name}\n"
                f"Proceeding anyway, but results may be incorrect."
            )

        # Create lookup maps for connections by stream_id
        baseline_map = {conn.stream_id: conn for conn in baseline_connections}
        compare_map = {conn.stream_id: conn for conn in compare_connections}

        # Validate and filter matches
        valid_matches = []
        invalid_count = 0

        for match in matches:
            stream_id1 = match.conn1.stream_id
            stream_id2 = match.conn2.stream_id

            # Check if both streams exist in current connections
            if stream_id1 not in baseline_map or stream_id2 not in compare_map:
                invalid_count += 1
                logger.debug(
                    f"Skipping match: stream {stream_id1} or {stream_id2} not found in current connections"
                )
                continue

            valid_matches.append(match)

        if invalid_count > 0:
            logger.warning(
                f"Skipped {invalid_count} matches that don't exist in current connections. "
                f"Using {len(valid_matches)} valid matches."
            )

        if not valid_matches:
            raise ValueError(
                "No valid matches found in match file. "
                "The match file may be for different PCAP files."
            )

        return valid_matches

    def _output_results(
        self,
        baseline_file: Path,
        compare_file: Path,
        results: list,
        output_file: Path | None,
        show_flow_hash: bool = False,
        matched_only: bool = False,
        db_connection: str | None = None,
        kase_id: int | None = None,
        pcap_id_mapping: dict[str, int] | None = None,
        quiet: bool = False,
    ) -> None:
        """
        Output comparison results with categorized statistics.

        The output is centered on the baseline file, showing differences
        of the compare file relative to the baseline file.

        Args:
            baseline_file: Baseline PCAP file (reference for comparison)
            compare_file: Compare PCAP file (compared against baseline)
            results: List of (match, baseline_packets, compare_packets, comparison_result) tuples
            output_file: Output file (None for stdout)
            show_flow_hash: Whether to calculate and display flow hash
            matched_only: Whether matched-only mode was used
            db_connection: Database connection string (optional)
            kase_id: Case ID for database table name (optional)
            pcap_id_mapping: Mapping from file path to pcap_id (optional)
            quiet: Suppress screen output (default: False)
        """
        # OPTIMIZATION: Cache flow hash calculations to avoid redundant computation
        # Cache key: (client_ip, server_ip, client_port, server_port)
        flow_hash_cache: dict[tuple[str, str, int, int], tuple[int, Any]] = {}

        # Build output text via helper to keep this module lean and tests stable
        from capmaster.plugins.compare.output_formatter import build_report_text
        output_text = build_report_text(
            results=results,
            baseline_file=baseline_file,
            compare_file=compare_file,
            matched_only=matched_only,
            show_flow_hash=show_flow_hash,
            flow_hash_cache=flow_hash_cache,
        )


        if output_file:
            # Ensure parent directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(output_text)
            logger.info(f"Results written to: {output_file}")

            # Write meta.json file
            from capmaster.utils.meta_writer import write_meta_json
            write_meta_json(
                output_file=output_file,
                command_id="packet_differences",
                source="basic",
            )
        elif not quiet:
            # Only print to stdout if not in quiet mode and no output file specified
            print(output_text)

        # Write to database if connection parameters provided
        if db_connection and kase_id is not None:
            self._write_to_database(
                db_connection,
                kase_id,
                results,
                baseline_file,
                compare_file,
                pcap_id_mapping,
                flow_hash_cache,
            )


    def _write_to_database(
        self,
        db_connection: str,
        kase_id: int,
        results: list,
        baseline_file: Path,
        compare_file: Path,
        pcap_id_mapping: dict[str, int] | None = None,
        flow_hash_cache: dict[tuple[str, str, int, int], tuple[int, Any]] | None = None,
    ) -> None:
        """
        Write comparison results to database.

        Args:
            db_connection: Database connection string
            kase_id: Case ID for table name
            results: List of (match, baseline_packets, compare_packets, comparison_result) tuples
            baseline_file: Baseline PCAP file (file1)
            compare_file: Compare PCAP file (file2)
            pcap_id_mapping: Mapping from file path to pcap_id (optional)
            flow_hash_cache: Cache of flow hash calculations (optional, for optimization)
        """
        from capmaster.plugins.compare.flow_hash import calculate_connection_flow_hash
        from capmaster.plugins.compare.packet_comparator import DiffType
        from capmaster.plugins.compare.db_writer import DatabaseWriter

        logger.info(f"Writing results to database (kase_id={kase_id})...")

        # Initialize flow_hash_cache if not provided
        if flow_hash_cache is None:
            flow_hash_cache = {}

        try:
            with DatabaseWriter(db_connection, kase_id) as db:
                # Ensure table exists
                db.ensure_table_exists()

                # Determine pcap_id to use (from file1/baseline)
                # Determine pcap_id to use (from file1/baseline)
                if pcap_id_mapping:
                    # Use the pcap_id from file1 (baseline_file)
                    pcap_id = pcap_id_mapping[str(baseline_file)]
                    logger.info(f"Using pcap_id={pcap_id} from file1 ({baseline_file.name})")
                else:
                    # Should not happen with current InputManager logic
                    pcap_id = 0
                    logger.warning(f"No pcap_id_mapping provided, defaulting to pcap_id=0")

                # Group results by baseline stream_id to merge multiple matches
                # Key: (baseline_stream_id, flow_hash)
                # Value: {first_time, last_time, all_tcp_flags_diffs, all_seq_num_diffs, conn}
                baseline_stream_groups = {}

                for match, packets_a, packets_b, result in results:
                    conn = match.conn1  # Use baseline connection

                    # Get flow hash from cache (OPTIMIZATION: avoid redundant calculation)
                    cache_key = (conn.client_ip, conn.server_ip, conn.client_port, conn.server_port)
                    if cache_key not in flow_hash_cache:
                        flow_hash_cache[cache_key] = calculate_connection_flow_hash(
                            conn.client_ip,
                            conn.server_ip,
                            conn.client_port,
                            conn.server_port,
                        )
                    flow_hash, _ = flow_hash_cache[cache_key]

                    # Create group key
                    group_key = (conn.stream_id, flow_hash)

                    # Initialize group if not exists
                    if group_key not in baseline_stream_groups:
                        baseline_stream_groups[group_key] = {
                            'conn': conn,
                            'flow_hash': flow_hash,
                            'first_time': None,
                            'last_time': None,
                            'tcp_flags_diffs': [],
                            'seq_num_diffs': [],
                        }

                    group = baseline_stream_groups[group_key]

                    # Extract first_time and last_time from baseline packets (file1)
                    if packets_a:
                        first_timestamp = packets_a[0].timestamp
                        last_timestamp = packets_a[-1].timestamp

                        first_time_ns = to_nanoseconds(first_timestamp)
                        last_time_ns = to_nanoseconds(last_timestamp)

                        # Update group's time range
                        if group['first_time'] is None or first_time_ns < group['first_time']:
                            group['first_time'] = first_time_ns
                        if group['last_time'] is None or last_time_ns > group['last_time']:
                            group['last_time'] = last_time_ns

                    # Collect TCP flags differences
                    tcp_flags_diffs = [
                        d for d in result.differences
                        if d.diff_type == DiffType.TCP_FLAGS
                    ]
                    group['tcp_flags_diffs'].extend(tcp_flags_diffs)

                    # Collect sequence number differences
                    seq_num_diffs = [
                        d for d in result.differences
                        if d.diff_type == DiffType.SEQ_NUM
                    ]
                    group['seq_num_diffs'].extend(seq_num_diffs)

                # OPTIMIZATION: Prepare all records for batch insert
                # This reduces database round-trips from N to 1
                batch_records = []

                for group_key, group in baseline_stream_groups.items():
                    tcp_flags_diffs = group['tcp_flags_diffs']
                    tcp_flags_cnt = len(tcp_flags_diffs)

                    # Build TCP flags difference type and text as string
                    tcp_flags_type = None
                    tcp_flags_text_list = []
                    if tcp_flags_diffs:
                        # Group by flags pair
                        flags_pairs = {}
                        for diff in tcp_flags_diffs:
                            pair = f"{diff.value_a}→{diff.value_b}"
                            if pair not in flags_pairs:
                                flags_pairs[pair] = []
                            flags_pairs[pair].append((diff.frame_a, diff.frame_b))

                        # Get the most common flags change type and format it
                        if flags_pairs:
                            sorted_pairs = sorted(flags_pairs.items(), key=lambda x: len(x[1]), reverse=True)
                            most_common_pair = sorted_pairs[0][0]
                            # Parse the pair to get baseline and compare flags
                            flags_baseline, flags_compare = most_common_pair.split('→')
                            tcp_flags_type = format_tcp_flags_change(flags_baseline, flags_compare)

                        # Format as frame mapping list: Frame 100→101; Frame 101→102; ...
                        # Limit to first 10 pairs, show "... and X more" if there are more
                        max_examples = 10
                        for i, diff in enumerate(tcp_flags_diffs[:max_examples]):
                            tcp_flags_text_list.append(f"Frame {diff.frame_a}→{diff.frame_b}")
                        if len(tcp_flags_diffs) > max_examples:
                            tcp_flags_text_list.append(f"... and {len(tcp_flags_diffs) - max_examples} more")

                    tcp_flags_text_string = "; ".join(tcp_flags_text_list) if tcp_flags_text_list else ""

                    # Build sequence number difference text
                    seq_num_diffs = group['seq_num_diffs']
                    seq_num_cnt = len(seq_num_diffs)

                    seq_num_text_list = []
                    if seq_num_diffs:
                        max_examples = 10
                        for i, diff in enumerate(seq_num_diffs[:max_examples]):
                            seq_num_text_list.append(
                                f"Frame {diff.frame_a}→{diff.frame_b}: {diff.value_a}→{diff.value_b}"
                            )
                        if len(seq_num_diffs) > max_examples:
                            seq_num_text_list.append(f"... and {len(seq_num_diffs) - max_examples} more")

                    seq_num_text_string = "; ".join(seq_num_text_list) if seq_num_text_list else ""

                    # Add record to batch
                    batch_records.append({
                        'pcap_id': pcap_id,
                        'flow_hash': group['flow_hash'],
                        'first_time': group['first_time'],
                        'last_time': group['last_time'],
                        'tcp_flags_different_cnt': tcp_flags_cnt,
                        'tcp_flags_different_type': tcp_flags_type,
                        'tcp_flags_different_text': tcp_flags_text_string,
                        'seq_num_different_cnt': seq_num_cnt,
                        'seq_num_different_text': seq_num_text_string,
                    })

                # Batch insert all records
                db.insert_flow_hash_batch(batch_records)

                # Commit all inserts
                db.commit()

                logger.info(f"Successfully wrote {len(baseline_stream_groups)} records to database (from {len(results)} matches)")

        except ImportError as e:
            logger.error(f"Database functionality not available: {e}")
            logger.error("Install psycopg2-binary to enable database output: pip install psycopg2-binary")
        except Exception as e:
            logger.error(f"Failed to write to database: {e}")
            raise

