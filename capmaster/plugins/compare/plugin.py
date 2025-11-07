"""Compare plugin for packet-level TCP connection comparison."""

import logging
from pathlib import Path

import click
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from capmaster.core.file_scanner import PcapScanner
from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.compare.packet_comparator import PacketComparator
from capmaster.plugins.compare.packet_extractor import PacketExtractor
from capmaster.plugins.match.connection import ConnectionBuilder
from capmaster.plugins.match.extractor import TcpFieldExtractor
from capmaster.plugins.match.matcher import BucketStrategy, ConnectionMatcher
from capmaster.utils.errors import (
    InsufficientFilesError,
    handle_error,
)

logger = logging.getLogger(__name__)


def round_to_microseconds(timestamp_seconds: float) -> int:
    """
    Convert timestamp from seconds to nanoseconds and round to microsecond precision.

    Args:
        timestamp_seconds: Unix timestamp in seconds (float)

    Returns:
        Timestamp in nanoseconds (int), rounded to microsecond precision

    Example:
        Input:  1.757441703689601024 seconds
        Output: 1757441703689601000 nanoseconds (rounded to nearest microsecond)
    """
    # Convert to microseconds first, round, then convert to nanoseconds
    timestamp_microseconds = round(timestamp_seconds * 1_000_000)
    timestamp_nanoseconds = timestamp_microseconds * 1_000
    return timestamp_nanoseconds


def parse_tcp_flags(flags_hex: str) -> str:
    """
    Parse TCP flags from hex string to human-readable format.

    Args:
        flags_hex: Hex string like "0x0002" or "0x0010"

    Returns:
        Human-readable flags like "[SYN]" or "[ACK]"
    """
    try:
        flags_int = int(flags_hex, 16)
    except (ValueError, TypeError):
        return flags_hex

    flag_names = []
    if flags_int & 0x01:  # FIN
        flag_names.append("FIN")
    if flags_int & 0x02:  # SYN
        flag_names.append("SYN")
    if flags_int & 0x04:  # RST
        flag_names.append("RST")
    if flags_int & 0x08:  # PSH
        flag_names.append("PSH")
    if flags_int & 0x10:  # ACK
        flag_names.append("ACK")
    if flags_int & 0x20:  # URG
        flag_names.append("URG")
    if flags_int & 0x40:  # ECE
        flag_names.append("ECE")
    if flags_int & 0x80:  # CWR
        flag_names.append("CWR")

    if not flag_names:
        return f"{flags_hex} [NONE]"

    return f"{flags_hex} [{', '.join(flag_names)}]"


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

        @cli_group.command(name=self.name)
        @click.option(
            "-i",
            "--input",
            "input_path",
            type=str,
            help="Input directory or comma-separated list of exactly 2 PCAP files",
        )
        @click.option(
            "--file1",
            type=click.Path(exists=True, path_type=Path),
            help="First PCAP file (baseline file)",
        )
        @click.option(
            "--file1-pcapid",
            type=int,
            help="PCAP ID for file1 (0 or 1)",
        )
        @click.option(
            "--file2",
            type=click.Path(exists=True, path_type=Path),
            help="Second PCAP file (compare file)",
        )
        @click.option(
            "--file2-pcapid",
            type=int,
            help="PCAP ID for file2 (0 or 1)",
        )
        @click.option(
            "-o",
            "--output",
            "output_file",
            type=click.Path(path_type=Path),
            help="Output file for comparison results (default: stdout)",
        )
        @click.option(
            "--threshold",
            type=float,
            default=0.60,
            help="Minimum normalized score threshold for matches (0.0-1.0, default: 0.60)",
        )
        @click.option(
            "--bucket",
            type=click.Choice(["auto", "server", "port", "none"], case_sensitive=False),
            default="auto",
            help="Bucketing strategy for matching",
        )
        @click.option(
            "--show-flow-hash",
            is_flag=True,
            default=False,
            help="Calculate and display flow hash for each TCP connection",
        )
        @click.option(
            "--matched-only",
            is_flag=True,
            default=False,
            help="Only compare packets that exist in both A and B with matching IPID (ignore packets only in A or only in B)",
        )
        @click.option(
            "--db-connection",
            type=str,
            help='Database connection string (e.g., "postgresql://user:pass@host:port/db"). When provided, results will be written to database.',
        )
        @click.option(
            "--kase-id",
            type=int,
            help="Case ID for database table name (e.g., 133 -> kase_133_tcp_stream_extra). Required when --db-connection is used.",
        )
        @click.option(
            "--silent",
            is_flag=True,
            default=False,
            help="Silent mode: suppress progress bars and screen output (logs and file output still work)",
        )
        @click.pass_context
        def compare_command(
            ctx: click.Context,
            input_path: str | None,
            file1: Path | None,
            file1_pcapid: int | None,
            file2: Path | None,
            file2_pcapid: int | None,
            output_file: Path | None,
            threshold: float,
            bucket: str,
            show_flow_hash: bool,
            matched_only: bool,
            db_connection: str | None,
            kase_id: int | None,
            silent: bool,
        ) -> None:
            """
            Compare TCP connections at packet level between PCAP files.

            This command first matches TCP connections between two PCAP files,
            then performs detailed packet-level comparison for each matched pair.

            \b
            Baseline File Selection:
              - For comma-separated files: The first file is used as baseline
              - For directory input: Files are sorted alphabetically, first is baseline
              - Comparison results show differences of the second file relative to baseline

            \b
            Comparison fields:
              - IP ID (ipid)
              - TCP flags
              - Sequence number
              - Acknowledgment number

            \b
            Examples:
              # Compare two PCAP files in a directory (alphabetically first is baseline)
              capmaster compare -i /path/to/pcaps/

              # Compare comma-separated file list (file1.pcap is baseline)
              capmaster compare -i "file1.pcap,file2.pcap"

              # Compare with custom threshold
              capmaster compare -i /path/to/pcaps/ --threshold 0.70

              # Save results to file
              capmaster compare -i /path/to/pcaps/ -o comparison.txt

              # Show flow hash for each connection
              capmaster compare -i /path/to/pcaps/ --show-flow-hash

              # Only compare matched packets (ignore packets only in baseline or compare file)
              capmaster compare -i /path/to/pcaps/ --matched-only

              # Write results to database
              capmaster compare -i /path/to/pcaps/ --show-flow-hash \\
                --db-connection "postgresql://postgres:password@172.16.200.156:5433/r2" \\
                --kase-id 133

              # Use file1/file2 with pcap_id mapping
              capmaster compare --file1 a.pcap --file1-pcapid 0 --file2 b.pcap --file2-pcapid 1 \\
                --show-flow-hash --db-connection "postgresql://..." --kase-id 133

            \b
            Input:
              The input can be a directory containing exactly 2 PCAP files,
              or a comma-separated list of exactly 2 PCAP files,
              or specified using --file1 and --file2 with their corresponding pcap IDs.

            \b
            Output:
              Comparison results are printed to stdout by default, or saved to a file
              if -o is specified. Results show differences of the compare file relative
              to the baseline file, including detailed packet-level differences.

              When --db-connection and --kase-id are provided, flow hash results will
              also be written to the database table public.kase_{kase_id}_tcp_stream_extra.
            """
            # Validate input parameters - must use either -i or (--file1 and --file2)
            if input_path and (file1 or file2):
                ctx.fail("Cannot use both -i/--input and --file1/--file2 at the same time")

            if not input_path and not (file1 and file2):
                ctx.fail("Must provide either -i/--input or both --file1 and --file2")

            # Validate file1/file2 parameters
            if file1 or file2 or file1_pcapid is not None or file2_pcapid is not None:
                if not (file1 and file2):
                    ctx.fail("Both --file1 and --file2 must be provided together")
                if file1_pcapid is None or file2_pcapid is None:
                    ctx.fail("Both --file1-pcapid and --file2-pcapid must be provided when using --file1/--file2")
                if file1_pcapid not in (0, 1):
                    ctx.fail("--file1-pcapid must be 0 or 1")
                if file2_pcapid not in (0, 1):
                    ctx.fail("--file2-pcapid must be 0 or 1")

            # Validate database parameters
            if db_connection and not kase_id:
                ctx.fail("--kase-id is required when --db-connection is provided")
            if kase_id and not db_connection:
                ctx.fail("--db-connection is required when --kase-id is provided")
            if db_connection and not show_flow_hash:
                ctx.fail("--show-flow-hash is required when using database output")

            exit_code = self.execute(
                input_path=input_path,
                file1=file1,
                file1_pcapid=file1_pcapid,
                file2=file2,
                file2_pcapid=file2_pcapid,
                output_file=output_file,
                score_threshold=threshold,
                bucket_strategy=bucket,
                show_flow_hash=show_flow_hash,
                matched_only=matched_only,
                db_connection=db_connection,
                kase_id=kase_id,
                silent=silent,
            )
            ctx.exit(exit_code)

    def execute(  # type: ignore[override]
        self,
        input_path: str | Path | None = None,
        file1: Path | None = None,
        file1_pcapid: int | None = None,
        file2: Path | None = None,
        file2_pcapid: int | None = None,
        output_file: Path | None = None,
        score_threshold: float = 0.60,
        bucket_strategy: str = "auto",
        show_flow_hash: bool = False,
        matched_only: bool = False,
        db_connection: str | None = None,
        kase_id: int | None = None,
        silent: bool = False,
    ) -> int:
        """
        Execute the compare plugin.

        The first file (in input order or alphabetically) is used as the baseline,
        and comparison results show differences of the second file relative to the baseline.

        Args:
            input_path: Directory or comma-separated list of exactly 2 PCAP files (optional)
            file1: First PCAP file (baseline) (optional)
            file1_pcapid: PCAP ID for file1 (0 or 1) (optional)
            file2: Second PCAP file (compare) (optional)
            file2_pcapid: PCAP ID for file2 (0 or 1) (optional)
            output_file: Output file for results (None for stdout)
            score_threshold: Minimum score threshold for matching
            bucket_strategy: Bucketing strategy for matching
            show_flow_hash: Whether to calculate and display flow hash
            matched_only: Only compare packets that exist in both files with matching IPID
            db_connection: Database connection string (optional)
            kase_id: Case ID for database table name (optional)
            silent: Silent mode - suppress progress bars and screen output

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Determine which input method is being used
            if file1 and file2:
                # Using --file1 and --file2
                baseline_file = file1
                compare_file = file2
                # Create pcap_id mapping: file path -> pcap_id
                pcap_id_mapping = {
                    str(file1): file1_pcapid,
                    str(file2): file2_pcapid,
                }
            else:
                # Using -i/--input (legacy method)
                # Parse input path (supports comma-separated file list)
                if isinstance(input_path, str):
                    input_paths = PcapScanner.parse_input(input_path)
                    # Preserve order only for comma-separated file lists
                    preserve_order = "," in input_path
                else:
                    input_paths = [str(input_path)]
                    preserve_order = False

                # Scan for PCAP files
                pcap_files = PcapScanner.scan(input_paths, recursive=False, preserve_order=preserve_order)

                if len(pcap_files) != 2:
                    raise InsufficientFilesError(required=2, found=len(pcap_files))

                # Determine baseline file (first file in input order)
                # - For comma-separated files: first file in the list (order preserved)
                # - For directory: first file in alphabetical order (sorted by PcapScanner)
                baseline_file = pcap_files[0]
                compare_file = pcap_files[1]
                # No pcap_id mapping for legacy method
                pcap_id_mapping = None

            logger.info(f"Baseline file: {baseline_file.name}")
            logger.info(f"Compare file: {compare_file.name}")
            logger.info(f"Comparison direction: {compare_file.name} relative to {baseline_file.name}")
            if pcap_id_mapping:
                logger.info(f"PCAP ID mapping: {baseline_file.name} -> {pcap_id_mapping[str(baseline_file)]}, {compare_file.name} -> {pcap_id_mapping[str(compare_file)]}")

            # Use progress bar only if not in silent mode
            from contextlib import nullcontext
            progress_context = nullcontext() if silent else Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
            )

            with progress_context as progress:
                # Step 1: Extract connections from both files
                extract_task = progress.add_task("[cyan]Extracting connections...", total=2) if not silent else None

                baseline_connections = self._extract_connections(baseline_file)
                logger.info(f"Found {len(baseline_connections)} connections in {baseline_file.name}")
                if not silent:
                    progress.update(extract_task, advance=1)

                compare_connections = self._extract_connections(compare_file)
                logger.info(f"Found {len(compare_connections)} connections in {compare_file.name}")
                if not silent:
                    progress.update(extract_task, advance=1)

                # Step 2: Match connections
                match_task = progress.add_task("[yellow]Matching connections...", total=1) if not silent else None

                bucket_enum = BucketStrategy(bucket_strategy)
                matcher = ConnectionMatcher(
                    bucket_strategy=bucket_enum,
                    score_threshold=score_threshold,
                )

                matches = matcher.match(baseline_connections, compare_connections)
                logger.info(f"Found {len(matches)} matched connection pairs")
                if not silent:
                    progress.update(match_task, advance=1)

                if not matches:
                    logger.warning("No matching connections found")
                    return 0

                # Step 3: Compare packets for each matched connection
                compare_task = progress.add_task(
                    "[green]Comparing packets...",
                    total=len(matches),
                ) if not silent else None

                extractor = PacketExtractor()
                comparator = PacketComparator()
                results = []

                for match in matches:
                    # Extract packets for this connection from both files using TCP 5-tuple
                    # Do NOT use stream_id as it may differ between files
                    baseline_packets = extractor.extract_packets(
                        baseline_file,
                        match.conn1.client_ip,
                        match.conn1.client_port,
                        match.conn1.server_ip,
                        match.conn1.server_port,
                    )
                    compare_packets = extractor.extract_packets(
                        compare_file,
                        match.conn2.client_ip,
                        match.conn2.client_port,
                        match.conn2.server_ip,
                        match.conn2.server_port,
                    )

                    # Create connection identifier
                    conn_id = (
                        f"{match.conn1.client_ip}:{match.conn1.client_port} <-> "
                        f"{match.conn1.server_ip}:{match.conn1.server_port}"
                    )

                    # Compare packets (baseline vs compare)
                    result = comparator.compare(baseline_packets, compare_packets, conn_id, matched_only)
                    results.append((match, baseline_packets, compare_packets, result))

                    if not silent:
                        progress.update(compare_task, advance=1)

                # Step 4: Output results
                output_task = progress.add_task("[blue]Writing results...", total=1) if not silent else None
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
                    silent,
                )
                if not silent:
                    progress.update(output_task, advance=1)

            logger.info("Comparison complete")
            return 0

        except Exception as e:
            return handle_error(e, verbose=logger.level <= logging.DEBUG)

    def _extract_connections(self, pcap_file: Path):
        """Extract TCP connections from a PCAP file."""
        extractor = TcpFieldExtractor()
        builder = ConnectionBuilder()

        # Extract packets and build connections
        for packet in extractor.extract(pcap_file):
            builder.add_packet(packet)

        # Build connections
        connections = list(builder.build_connections())

        return connections

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
        silent: bool = False,
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
            silent: Silent mode - suppress screen output (default: False)
        """
        from collections import Counter
        from capmaster.plugins.compare.packet_comparator import DiffType
        from capmaster.plugins.compare.flow_hash import calculate_connection_flow_hash, format_flow_hash
        from capmaster.plugins.compare.db_writer import DatabaseWriter

        lines = []
        lines.append("=" * 100)
        lines.append("TCP Connection Packet-Level Comparison Report")
        lines.append("=" * 100)
        lines.append(f"Baseline File: {baseline_file.name}")
        lines.append(f"Compare File:  {compare_file.name}")
        lines.append(f"Comparison Direction: {compare_file.name} relative to {baseline_file.name}")
        lines.append(f"Matched Connections: {len(results)}")
        if matched_only:
            lines.append("Mode: Matched-only (only comparing packets with matching IPID in both files)")
        lines.append("=" * 100)

        # Section 1: Matched TCP Connections from Baseline File
        lines.append(f"\n{'='*140}")
        lines.append(f"Matched TCP Connections in Baseline File ({baseline_file.name})")
        lines.append("=" * 140)

        if show_flow_hash:
            lines.append(f"{'No.':<6} {'Stream ID':<12} {'Client IP:Port':<25} {'Server IP:Port':<25} {'Packets':<10} {'First Time':<22} {'Last Time':<22} {'Flow Hash':<30}")
        else:
            lines.append(f"{'No.':<6} {'Stream ID':<12} {'Client IP:Port':<25} {'Server IP:Port':<25} {'Packets':<10} {'First Time':<22} {'Last Time':<22}")
        lines.append("-" * 140)

        for idx, (match, packets_a, packets_b, result) in enumerate(results, 1):
            conn = match.conn1  # Baseline connection
            client_addr = f"{conn.client_ip}:{conn.client_port}"
            server_addr = f"{conn.server_ip}:{conn.server_port}"

            # Extract timestamps from baseline packets
            first_time_str = "N/A"
            last_time_str = "N/A"
            if packets_a:
                first_time_ns = round_to_microseconds(packets_a[0].timestamp)
                last_time_ns = round_to_microseconds(packets_a[-1].timestamp)
                first_time_str = str(first_time_ns)
                last_time_str = str(last_time_ns)

            if show_flow_hash:
                # Calculate flow hash for baseline connection
                hash_hex, flow_side = calculate_connection_flow_hash(
                    conn.client_ip,
                    conn.server_ip,
                    conn.client_port,
                    conn.server_port,
                )
                flow_hash_str = format_flow_hash(hash_hex, flow_side)
                lines.append(
                    f"{idx:<6} {conn.stream_id:<12} {client_addr:<25} {server_addr:<25} {len(packets_a):<10} {first_time_str:<22} {last_time_str:<22} {flow_hash_str:<30}"
                )
            else:
                lines.append(
                    f"{idx:<6} {conn.stream_id:<12} {client_addr:<25} {server_addr:<25} {len(packets_a):<10} {first_time_str:<22} {last_time_str:<22}"
                )

        lines.append("-" * 140)
        lines.append(f"Total: {len(results)} connections")

        # Section 2: Matched TCP Connections from Compare File
        lines.append(f"\n{'='*140}")
        lines.append(f"Matched TCP Connections in Compare File ({compare_file.name})")
        lines.append("=" * 140)

        if show_flow_hash:
            lines.append(f"{'No.':<6} {'Stream ID':<12} {'Client IP:Port':<25} {'Server IP:Port':<25} {'Packets':<10} {'First Time':<22} {'Last Time':<22} {'Flow Hash':<30}")
        else:
            lines.append(f"{'No.':<6} {'Stream ID':<12} {'Client IP:Port':<25} {'Server IP:Port':<25} {'Packets':<10} {'First Time':<22} {'Last Time':<22}")
        lines.append("-" * 140)

        for idx, (match, packets_a, packets_b, result) in enumerate(results, 1):
            conn = match.conn2  # Compare connection
            client_addr = f"{conn.client_ip}:{conn.client_port}"
            server_addr = f"{conn.server_ip}:{conn.server_port}"

            # Extract timestamps from compare packets
            first_time_str = "N/A"
            last_time_str = "N/A"
            if packets_b:
                first_time_ns = round_to_microseconds(packets_b[0].timestamp)
                last_time_ns = round_to_microseconds(packets_b[-1].timestamp)
                first_time_str = str(first_time_ns)
                last_time_str = str(last_time_ns)

            if show_flow_hash:
                # Calculate flow hash for compare connection
                hash_hex, flow_side = calculate_connection_flow_hash(
                    conn.client_ip,
                    conn.server_ip,
                    conn.client_port,
                    conn.server_port,
                )
                flow_hash_str = format_flow_hash(hash_hex, flow_side)
                lines.append(
                    f"{idx:<6} {conn.stream_id:<12} {client_addr:<25} {server_addr:<25} {len(packets_b):<10} {first_time_str:<22} {last_time_str:<22} {flow_hash_str:<30}"
                )
            else:
                lines.append(
                    f"{idx:<6} {conn.stream_id:<12} {client_addr:<25} {server_addr:<25} {len(packets_b):<10} {first_time_str:<22} {last_time_str:<22}"
                )

        lines.append("-" * 140)
        lines.append(f"Total: {len(results)} connections")

        # Overall summary statistics
        identical_count = sum(1 for _, _, _, r in results if r.is_identical)
        diff_count = len(results) - identical_count

        lines.append(f"\n{'='*100}")
        lines.append("Overall Summary")
        lines.append("=" * 100)
        lines.append(f"Total matched connections: {len(results)}")
        lines.append(f"Identical connections: {identical_count}")
        lines.append(f"Connections with differences: {diff_count}")

        # Collect all differences by type across all connections
        diff_type_counter = Counter()
        connections_with_diff_type = {}  # Track which connections have each diff type
        tcp_flags_details = Counter()  # Track specific TCP FLAGS differences
        tcp_flags_frame_pairs = {}  # Track frame id pairs for each TCP FLAGS difference

        for match, packets_a, packets_b, result in results:
            if not result.is_identical:
                # Count differences by type
                for diff in result.differences:
                    diff_type_counter[diff.diff_type] += 1

                    # Track connections with this diff type
                    if diff.diff_type not in connections_with_diff_type:
                        connections_with_diff_type[diff.diff_type] = set()
                    connections_with_diff_type[diff.diff_type].add(result.connection_id)

                    # Collect TCP FLAGS details
                    if diff.diff_type == DiffType.TCP_FLAGS:
                        flags_pair = f"{diff.value_a} → {diff.value_b}"
                        tcp_flags_details[flags_pair] += 1

                        # Track frame id pairs for this flags difference
                        if flags_pair not in tcp_flags_frame_pairs:
                            tcp_flags_frame_pairs[flags_pair] = []
                        tcp_flags_frame_pairs[flags_pair].append((diff.frame_a, diff.frame_b))

        # Output categorized statistics
        if diff_type_counter:
            lines.append(f"\n{'='*100}")
            lines.append("Difference Type Statistics")
            lines.append("=" * 100)
            lines.append(f"{'Difference Type':<20} {'Total Count':<15} {'Affected Connections':<25}")
            lines.append("-" * 100)

            # Sort by count (descending)
            for diff_type, count in diff_type_counter.most_common():
                affected_conns = len(connections_with_diff_type.get(diff_type, set()))
                # Use the enum value directly with _DIFF suffix
                diff_type_name = diff_type.value.upper() + '_DIFF'
                lines.append(f"{diff_type_name:<20} {count:<15} {affected_conns:<25}")

            lines.append("-" * 100)

        # TCP FLAGS detailed breakdown
        if tcp_flags_details:
            lines.append(f"\n{'='*100}")
            lines.append("TCP FLAGS Detailed Breakdown")
            lines.append("=" * 100)
            lines.append(f"{'Baseline FLAGS':<35} {'Compare FLAGS':<35} {'Count':<15}")
            lines.append("-" * 100)

            # Sort by count (descending)
            for flags_pair, count in tcp_flags_details.most_common():
                flags_baseline, flags_compare = flags_pair.split(" → ")
                # Parse flags to human-readable format
                flags_baseline_readable = parse_tcp_flags(flags_baseline)
                flags_compare_readable = parse_tcp_flags(flags_compare)
                lines.append(f"{flags_baseline_readable:<35} {flags_compare_readable:<35} {count:<15}")

                # Show frame id pairs for this flags difference
                frame_pairs = tcp_flags_frame_pairs.get(flags_pair, [])
                if frame_pairs:
                    # Show first few pairs as examples
                    max_examples = 10
                    lines.append(f"  Example Frame ID pairs (Baseline → Compare):")

                    # Format pairs in a compact way, multiple per line
                    pairs_per_line = 5
                    for i in range(0, min(max_examples, len(frame_pairs)), pairs_per_line):
                        batch = frame_pairs[i:i+pairs_per_line]
                        pair_strs = [f"({frame_baseline}→{frame_compare})" for frame_baseline, frame_compare in batch]
                        lines.append(f"    {', '.join(pair_strs)}")

                    # If there are more pairs, show summary
                    if len(frame_pairs) > max_examples:
                        lines.append(f"    ... and {len(frame_pairs) - max_examples} more pairs")

            lines.append("-" * 100)
            lines.append(f"{'TOTAL':<71} {sum(tcp_flags_details.values()):<15}")

        # Remove "Connection Details" section as requested

        # Write output
        output_text = "\n".join(lines)

        if output_file:
            output_file.write_text(output_text)
            logger.info(f"Results written to: {output_file}")
        elif not silent:
            # Only print to stdout if not in silent mode and no output file specified
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
            )


    def _write_to_database(
        self,
        db_connection: str,
        kase_id: int,
        results: list,
        baseline_file: Path,
        compare_file: Path,
        pcap_id_mapping: dict[str, int] | None = None,
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
        """
        from capmaster.plugins.compare.flow_hash import calculate_connection_flow_hash
        from capmaster.plugins.compare.packet_comparator import DiffType
        from capmaster.plugins.compare.db_writer import DatabaseWriter

        logger.info(f"Writing results to database (kase_id={kase_id})...")

        try:
            with DatabaseWriter(db_connection, kase_id) as db:
                # Ensure table exists
                db.ensure_table_exists()

                # Determine pcap_id to use (from file1/baseline)
                if pcap_id_mapping:
                    # Use the pcap_id from file1 (baseline_file)
                    pcap_id = pcap_id_mapping[str(baseline_file)]
                    logger.info(f"Using pcap_id={pcap_id} from file1 ({baseline_file.name})")
                else:
                    # Legacy mode: default to 0
                    pcap_id = 0
                    logger.info(f"Using default pcap_id=0 (legacy mode)")

                # Process each matched connection
                for match, packets_a, packets_b, result in results:
                    conn = match.conn1  # Use baseline connection

                    # Calculate flow hash
                    flow_hash, _ = calculate_connection_flow_hash(
                        conn.client_ip,
                        conn.server_ip,
                        conn.client_port,
                        conn.server_port,
                    )

                    # Extract first_time and last_time from baseline packets (file1)
                    # Convert from Unix timestamp (seconds) to nanoseconds, rounded to microsecond precision
                    first_time = None
                    last_time = None
                    if packets_a:
                        # packets_a are already sorted chronologically
                        first_timestamp = packets_a[0].timestamp  # float, in seconds
                        last_timestamp = packets_a[-1].timestamp  # float, in seconds

                        # Convert to nanoseconds, rounded to microsecond precision
                        first_time = round_to_microseconds(first_timestamp)
                        last_time = round_to_microseconds(last_timestamp)

                    # Count TCP flags differences
                    tcp_flags_diffs = [
                        d for d in result.differences
                        if d.diff_type == DiffType.TCP_FLAGS
                    ]
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

                        # Get the most common flags change type (use -> instead of →)
                        if flags_pairs:
                            # Sort by occurrence count and get the most common one
                            sorted_pairs = sorted(flags_pairs.items(), key=lambda x: len(x[1]), reverse=True)
                            most_common_pair = sorted_pairs[0][0]
                            # Convert → to -> for database storage
                            tcp_flags_type = most_common_pair.replace('→', '->')

                        # Format as list of strings, then join with semicolon
                        for pair, frames in flags_pairs.items():
                            tcp_flags_text_list.append(f"{pair} ({len(frames)} occurrences)")

                    # Convert list to semicolon-separated string
                    tcp_flags_text_string = "; ".join(tcp_flags_text_list) if tcp_flags_text_list else ""

                    # Count sequence number differences
                    seq_num_diffs = [
                        d for d in result.differences
                        if d.diff_type == DiffType.SEQ_NUM
                    ]
                    seq_num_cnt = len(seq_num_diffs)

                    # Build sequence number difference text as string
                    seq_num_text_list = []
                    if seq_num_diffs:
                        # Show first few examples
                        max_examples = 10
                        for i, diff in enumerate(seq_num_diffs[:max_examples]):
                            seq_num_text_list.append(
                                f"Frame {diff.frame_a}→{diff.frame_b}: {diff.value_a}→{diff.value_b}"
                            )
                        if len(seq_num_diffs) > max_examples:
                            seq_num_text_list.append(f"... and {len(seq_num_diffs) - max_examples} more")

                    # Convert list to semicolon-separated string
                    seq_num_text_string = "; ".join(seq_num_text_list) if seq_num_text_list else ""

                    # Insert record
                    # Use pcap_id from file1 (baseline_file)
                    # first_time and last_time are extracted from baseline packets (file1)
                    db.insert_flow_hash(
                        pcap_id=pcap_id,
                        flow_hash=flow_hash,
                        first_time=first_time,
                        last_time=last_time,
                        tcp_flags_different_cnt=tcp_flags_cnt,
                        tcp_flags_different_type=tcp_flags_type,
                        tcp_flags_different_text=tcp_flags_text_string,
                        seq_num_different_cnt=seq_num_cnt,
                        seq_num_different_text=seq_num_text_string,
                    )

                # Commit all inserts
                db.commit()

                logger.info(f"Successfully wrote {len(results)} records to database")

        except ImportError as e:
            logger.error(f"Database functionality not available: {e}")
            logger.error("Install psycopg2-binary to enable database output: pip install psycopg2-binary")
        except Exception as e:
            logger.error(f"Failed to write to database: {e}")
            raise

