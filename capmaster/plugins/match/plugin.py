"""Match plugin for TCP connection matching."""

from __future__ import annotations
import logging
from pathlib import Path

import click
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.core.connection.matcher import BucketStrategy, ConnectionMatcher, MatchMode
from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.match.endpoint_stats import (
    EndpointStatsCollector,
    format_endpoint_stats,
    format_endpoint_stats_table,
)
from capmaster.plugins.match.sampler import ConnectionSampler
from capmaster.plugins.match.server_detector import ServerDetector
from capmaster.utils.cli_options import (
    dual_file_input_options,
    validate_database_params,
    validate_dual_file_input,
)
from capmaster.utils.errors import (
    InsufficientFilesError,
    handle_error,
)
from capmaster.utils.input_parser import DualFileInputParser

logger = logging.getLogger(__name__)


@register_plugin
class MatchPlugin(PluginBase):
    """
    Match TCP connections between PCAP files.

    This plugin identifies matching TCP connections across different
    PCAP files based on connection features like SYN options, ISN,
    payload hash, and packet length signatures.
    """

    @property
    def name(self) -> str:
        """Plugin name (CLI subcommand)."""
        return "match"

    def setup_cli(self, cli_group: click.Group) -> None:
        """
        Register CLI subcommand.

        Args:
            cli_group: Click group to add command to
        """

        @cli_group.command(name=self.name)
        @dual_file_input_options
        @click.option(
            "-o",
            "--output",
            "output_file",
            type=click.Path(path_type=Path),
            help="Output file for match results (default: stdout)",
        )
        @click.option(
            "--mode",
            type=click.Choice(["auto", "header"], case_sensitive=False),
            default="auto",
            help="Matching mode (auto: automatic, header: header-only)",
        )
        @click.option(
            "--bucket",
            type=click.Choice(["auto", "server", "port", "none"], case_sensitive=False),
            default="auto",
            help="Bucketing strategy for matching",
        )
        @click.option(
            "--threshold",
            type=float,
            default=0.60,
            help="Minimum normalized score threshold for matches (0.0-1.0, default: 0.60)",
        )
        @click.option(
            "--match-mode",
            type=click.Choice(["one-to-one", "one-to-many"], case_sensitive=False),
            default="one-to-one",
            help="Matching mode (one-to-one: each connection matches at most once, "
            "one-to-many: allow one connection to match multiple connections based on time overlap)",
        )
        @click.option(
            "--endpoint-stats",
            is_flag=True,
            default=False,
            help="Generate endpoint statistics (client IP, server IP, server port) for matched connections",
        )
        @click.option(
            "--endpoint-stats-output",
            type=click.Path(path_type=Path),
            help="Output file for endpoint statistics (default: stdout)",
        )
        @click.option(
            "--no-sampling",
            is_flag=True,
            default=False,
            help="Disable connection sampling (process all connections regardless of dataset size)",
        )
        @click.option(
            "--sampling-threshold",
            type=int,
            default=1000,
            help="Number of connections above which sampling is triggered (default: 1000)",
        )
        @click.option(
            "--sampling-rate",
            type=float,
            default=0.5,
            help="Fraction of connections to keep when sampling (0.0-1.0, default: 0.5)",
        )
        @click.option(
            "--db-connection",
            type=str,
            help='Database connection string (e.g., "postgresql://user:pass@host:port/db"). When provided, endpoint statistics will be written to database.',
        )
        @click.option(
            "--kase-id",
            type=int,
            help="Case ID for database table name (e.g., 137 -> kase_137_topological_graph). Required when --db-connection is used.",
        )
        @click.option(
            "--endpoint-stats-json",
            type=click.Path(path_type=Path),
            help="Output JSON file for endpoint statistics in database format (one JSON object per line)",
        )
        @click.option(
            "--merge-by-5tuple",
            is_flag=True,
            default=False,
            help="Merge TCP connections by direction-independent 5-tuple within each PCAP file. "
            "This allows port reuse detection and can determine server from later SYN packets "
            "when the first connection lacks handshake packets.",
        )
        @click.option(
            "--disable-very-low-dual-output",
            is_flag=True,
            default=False,
            help="Disable dual output for VERY_LOW confidence endpoint pairs. "
            "By default, VERY_LOW confidence pairs output both original and reversed interpretations.",
        )
        @click.option(
            "--endpoint-pair-mode",
            is_flag=True,
            default=False,
            help="Use endpoint pair mode instead of service aggregation. "
            "By default, endpoint pairs are aggregated by service (server port + protocol). "
            "Use this flag to output individual endpoint pairs with separate group_ids.",
        )
        @click.option(
            "--service-group-mapping",
            type=click.Path(exists=True, path_type=Path),
            help="JSON file mapping service ports to group IDs for custom grouping. "
            "Format: {\"8000\": 1, \"8080\": 1, \"443\": 2}. "
            "Only used when service aggregation is enabled (default behavior).",
        )
        @click.pass_context
        def match_command(
            ctx: click.Context,
            input_path: str | None,
            file1: Path | None,
            file1_pcapid: int | None,
            file2: Path | None,
            file2_pcapid: int | None,
            output_file: Path | None,
            mode: str,
            bucket: str,
            threshold: float,
            match_mode: str,
            endpoint_stats: bool,
            endpoint_stats_output: Path | None,
            no_sampling: bool,
            sampling_threshold: int,
            sampling_rate: float,
            db_connection: str | None,
            kase_id: int | None,
            endpoint_stats_json: Path | None,
            merge_by_5tuple: bool,
            disable_very_low_dual_output: bool,
            endpoint_pair_mode: bool,
            service_group_mapping: Path | None,
        ) -> None:
            """
            Match TCP connections between PCAP files.

            This command identifies matching TCP connections across different PCAP files
            based on connection features including:
            - SYN options and TCP timestamps
            - Initial sequence numbers (ISN)
            - Payload hash (MD5)
            - Packet length signatures
            - IP identification (IPID)

            \b
            Examples:
              # Match connections in a directory (auto mode)
              capmaster match -i captures/

              # Match comma-separated file list
              capmaster match -i "file1.pcap,file2.pcap"

              # Match using explicit file specification with pcap IDs
              capmaster match --file1 a.pcap --file1-pcapid 0 --file2 b.pcap --file2-pcapid 1

              # Match with custom threshold
              capmaster match -i captures/ --threshold 0.70

              # Match header-only connections
              capmaster match -i captures/ --mode header

              # Match with specific bucketing strategy
              capmaster match -i captures/ --bucket server

              # Save results to file
              capmaster match -i captures/ -o matches.txt

              # Disable sampling (process all connections)
              capmaster match -i captures/ --no-sampling

              # Custom sampling parameters
              capmaster match -i captures/ --sampling-threshold 5000 --sampling-rate 0.3

            \b
            Bucketing Strategies:
              auto    - Automatically choose best strategy
              server  - Group by server IP
              port    - Group by server port
              none    - No bucketing (compare all pairs)

            \b
            Sampling:
              By default, sampling is applied when connection count exceeds 1000.
              Use --no-sampling to disable, or customize with --sampling-threshold
              and --sampling-rate. Sampling uses time-based stratified sampling
              and always preserves header-only connections and special ports.

            \b
            Input:
              The input can be a directory containing exactly 2 PCAP files,
              or a comma-separated list of exactly 2 PCAP files,
              or specified using --file1 and --file2 with their corresponding pcap IDs.

            \b
            Output:
              Match results are printed to stdout by default, or saved to a file
              if -o is specified. Results include match statistics and details.

              When --db-connection and --kase-id are provided, endpoint statistics
              will also be written to the database table public.kase_{kase_id}_topological_graph.
              Note: Existing data in the table will be cleared before writing new data.
              If the table doesn't exist, it will be created automatically.

            \b
            Database Output:
              # Write endpoint statistics to database
              capmaster match --file1 a.pcap --file1-pcapid 0 --file2 b.pcap --file2-pcapid 1 \\
                --endpoint-stats \\
                --db-connection "postgresql://postgres:password@host:port/db" \\
                --kase-id 137

            \b
            JSON Output:
              # Write endpoint statistics to JSON file (one JSON object per line)
              capmaster match --file1 a.pcap --file1-pcapid 0 --file2 b.pcap --file2-pcapid 1 \\
                --endpoint-stats \\
                --endpoint-stats-json endpoint_stats.json
            """
            # Validate input parameters
            validate_dual_file_input(ctx, input_path, file1, file2, file1_pcapid, file2_pcapid)

            # Validate database parameters
            validate_database_params(
                ctx, db_connection, kase_id, "endpoint-stats", endpoint_stats
            )

            exit_code = self.execute(
                input_path=input_path,
                file1=file1,
                file1_pcapid=file1_pcapid,
                file2=file2,
                file2_pcapid=file2_pcapid,
                output_file=output_file,
                mode=mode,
                bucket_strategy=bucket,
                score_threshold=threshold,
                match_mode=match_mode,
                endpoint_stats=endpoint_stats,
                endpoint_stats_output=endpoint_stats_output,
                no_sampling=no_sampling,
                sampling_threshold=sampling_threshold,
                sampling_rate=sampling_rate,
                db_connection=db_connection,
                kase_id=kase_id,
                endpoint_stats_json=endpoint_stats_json,
                merge_by_5tuple=merge_by_5tuple,
                disable_very_low_dual_output=disable_very_low_dual_output,
                endpoint_pair_mode=endpoint_pair_mode,
                service_group_mapping=service_group_mapping,
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
        mode: str = "auto",
        bucket_strategy: str = "auto",
        score_threshold: float = 0.60,
        match_mode: str = "one-to-one",
        endpoint_stats: bool = False,
        endpoint_stats_output: Path | None = None,
        no_sampling: bool = False,
        sampling_threshold: int = 1000,
        sampling_rate: float = 0.5,
        db_connection: str | None = None,
        kase_id: int | None = None,
        endpoint_stats_json: Path | None = None,
        merge_by_5tuple: bool = False,
        disable_very_low_dual_output: bool = False,
        endpoint_pair_mode: bool = False,
        service_group_mapping: Path | None = None,
    ) -> int:
        """
        Execute the match plugin.

        Args:
            input_path: Directory, file list, or comma-separated PCAP files (legacy method)
            file1: First PCAP file (explicit method)
            file1_pcapid: PCAP ID for file1 (0 or 1)
            file2: Second PCAP file (explicit method)
            file2_pcapid: PCAP ID for file2 (0 or 1)
            output_file: Output file for results (None for stdout)
            mode: Matching mode (auto or header)
            bucket_strategy: Bucketing strategy
            score_threshold: Minimum score threshold
            match_mode: Matching mode (one-to-one or one-to-many)
            endpoint_stats: Generate endpoint statistics
            endpoint_stats_output: Output file for endpoint statistics
            no_sampling: Disable sampling
            sampling_threshold: Connection count threshold for sampling
            sampling_rate: Fraction of connections to keep when sampling
            db_connection: Database connection string
            kase_id: Case ID for database table name
            endpoint_stats_json: Output JSON file for endpoint statistics
            merge_by_5tuple: Merge connections by direction-independent 5-tuple
            disable_very_low_dual_output: Disable dual output for VERY_LOW confidence pairs
            endpoint_pair_mode: Use endpoint pair mode instead of service aggregation (default: False)
            service_group_mapping: JSON file mapping service ports to group IDs

        Returns:
            Exit code (0 for success, non-zero for failure)

        Raises:
            ValueError: If parameters are invalid
        """
        # Validate parameters
        if not 0.0 <= score_threshold <= 1.0:
            logger.error(f"Invalid score threshold: {score_threshold}. Must be between 0.0 and 1.0")
            return 1

        if not 0.0 < sampling_rate <= 1.0:
            logger.error(f"Invalid sampling rate: {sampling_rate}. Must be between 0.0 and 1.0")
            return 1

        if sampling_threshold <= 0:
            logger.error(f"Invalid sampling threshold: {sampling_threshold}. Must be positive")
            return 1

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
            ) as progress:
                # Parse dual file input
                scan_task = progress.add_task("[cyan]Scanning for PCAP files...", total=1)

                dual_input = DualFileInputParser.parse(
                    input_path, file1, file2, file1_pcapid, file2_pcapid
                )
                progress.update(scan_task, advance=1)

                # Extract file paths
                match_file1 = dual_input.file1
                match_file2 = dual_input.file2
                pcap_id_mapping = dual_input.pcap_id_mapping

                logger.info(f"File 1: {match_file1.name}")
                logger.info(f"File 2: {match_file2.name}")
                if pcap_id_mapping:
                    logger.info(
                        f"PCAP ID mapping: {match_file1.name} -> {pcap_id_mapping[str(match_file1)]}, "
                        f"{match_file2.name} -> {pcap_id_mapping[str(match_file2)]}"
                    )
                logger.info(f"Matching: {match_file1.name} <-> {match_file2.name}")

                # Extract connections from both files
                extract_task = progress.add_task("[cyan]Extracting connections...", total=2)

                progress.update(extract_task, description=f"[cyan]Extracting from {match_file1.name}...")
                connections1 = self._extract_connections(match_file1, merge_by_5tuple=merge_by_5tuple)
                logger.info(f"Found {len(connections1)} connections in {match_file1.name}")
                if merge_by_5tuple:
                    logger.info("  (merged by direction-independent 5-tuple)")
                progress.update(extract_task, advance=1)

                progress.update(extract_task, description=f"[cyan]Extracting from {match_file2.name}...")
                connections2 = self._extract_connections(match_file2, merge_by_5tuple=merge_by_5tuple)
                logger.info(f"Found {len(connections2)} connections in {match_file2.name}")
                if merge_by_5tuple:
                    logger.info("  (merged by direction-independent 5-tuple)")
                progress.update(extract_task, advance=1)

                # Apply sampling if needed (unless disabled)
                if no_sampling:
                    logger.info("Sampling disabled by --no-sampling flag")
                else:
                    # Validate sampling parameters
                    if sampling_rate <= 0.0 or sampling_rate > 1.0:
                        logger.warning(f"Invalid sampling rate {sampling_rate}, using default 0.5")
                        sampling_rate = 0.5

                    if sampling_threshold < 1:
                        logger.warning(f"Invalid sampling threshold {sampling_threshold}, using default 1000")
                        sampling_threshold = 1000

                    sampler = ConnectionSampler(
                        threshold=sampling_threshold,
                        sample_rate=sampling_rate,
                    )

                    if sampler.should_sample(connections1):
                        sample_task = progress.add_task("[yellow]Sampling connections...", total=1)
                        logger.info(
                            f"Applying sampling to first file (threshold={sampling_threshold}, rate={sampling_rate})..."
                        )
                        original_count1 = len(connections1)
                        connections1 = sampler.sample(connections1)
                        logger.info(
                            f"Sampled from {original_count1} to {len(connections1)} connections "
                            f"({len(connections1)/original_count1:.1%} retained)"
                        )
                        progress.update(sample_task, advance=1)

                    if sampler.should_sample(connections2):
                        sample_task = progress.add_task("[yellow]Sampling connections...", total=1)
                        logger.info(
                            f"Applying sampling to second file (threshold={sampling_threshold}, rate={sampling_rate})..."
                        )
                        original_count2 = len(connections2)
                        connections2 = sampler.sample(connections2)
                        logger.info(
                            f"Sampled from {original_count2} to {len(connections2)} connections "
                            f"({len(connections2)/original_count2:.1%} retained)"
                        )
                        progress.update(sample_task, advance=1)

                # Improve server detection using cardinality analysis
                detector_task = progress.add_task("[yellow]Analyzing server/client roles...", total=1)
                logger.info("Performing cardinality analysis for server detection...")
                detector = ServerDetector()

                # Collect all connections for cardinality analysis
                for conn in connections1:
                    detector.collect_connection(conn)
                for conn in connections2:
                    detector.collect_connection(conn)

                # Finalize cardinality analysis
                detector.finalize_cardinality()

                # Re-detect server/client roles with improved detection
                connections1 = self._improve_server_detection(connections1, detector)
                connections2 = self._improve_server_detection(connections2, detector)
                logger.info("Server detection improved using cardinality analysis")
                progress.update(detector_task, advance=1)

                # Match connections
                match_task = progress.add_task("[green]Matching connections...", total=1)
                logger.info("Matching connections...")
                bucket_enum = BucketStrategy(bucket_strategy)
                match_mode_enum = MatchMode(match_mode)
                matcher = ConnectionMatcher(
                    bucket_strategy=bucket_enum,
                    score_threshold=score_threshold,
                    match_mode=match_mode_enum,
                )

                matches = matcher.match(connections1, connections2)
                logger.info(f"Found {len(matches)} matches")
                progress.update(match_task, advance=1)

                # Get statistics
                stats = matcher.get_match_stats(connections1, connections2, matches)

                # Output results
                output_task = progress.add_task("[green]Writing results...", total=1)
                self._output_results(matches, stats, output_file)
                progress.update(output_task, advance=1)

                # Generate endpoint statistics if requested
                if endpoint_stats:
                    endpoint_task = progress.add_task("[green]Generating endpoint statistics...", total=1)
                    endpoint_stats_list = self._output_endpoint_stats(
                        matches,
                        match_file1,
                        match_file2,
                        endpoint_stats_output,
                        disable_very_low_dual_output=disable_very_low_dual_output,
                    )
                    progress.update(endpoint_task, advance=1)

                    # Aggregate by service by default (unless endpoint_pair_mode is enabled)
                    service_stats_list = None
                    if not endpoint_pair_mode:
                        service_task = progress.add_task("[green]Aggregating by service...", total=1)
                        service_stats_list = self._aggregate_and_output_service_stats(
                            endpoint_stats_list,
                            match_file1,
                            match_file2,
                            endpoint_stats_output,
                        )
                        progress.update(service_task, advance=1)

                    # Write to database if connection parameters provided
                    if db_connection and kase_id is not None:
                        db_task = progress.add_task("[green]Writing to database...", total=1)
                        self._write_to_database(
                            db_connection,
                            kase_id,
                            endpoint_stats_list,
                            match_file1,
                            match_file2,
                            pcap_id_mapping,
                            service_stats_list=service_stats_list,
                            service_group_mapping_file=service_group_mapping,
                        )
                        progress.update(db_task, advance=1)

                    # Write to JSON file if requested
                    if endpoint_stats_json:
                        json_task = progress.add_task("[green]Writing to JSON file...", total=1)
                        self._write_to_json(
                            endpoint_stats_json,
                            endpoint_stats_list,
                            match_file1,
                            match_file2,
                            pcap_id_mapping,
                            service_stats_list=service_stats_list,
                            service_group_mapping_file=service_group_mapping,
                        )
                        progress.update(json_task, advance=1)

            logger.info("Matching complete")
            return 0

        except InsufficientFilesError as e:
            # Expected business error - handle gracefully
            return handle_error(e, show_traceback=False)
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

    def _extract_connections(self, pcap_file: Path, merge_by_5tuple: bool = False) -> list:
        """
        Extract TCP connections from a PCAP file.

        Args:
            pcap_file: Path to PCAP file
            merge_by_5tuple: If True, merge connections by direction-independent 5-tuple

        Returns:
            List of TcpConnection objects
        """
        return extract_connections_from_pcap(pcap_file, merge_by_5tuple=merge_by_5tuple)

    def _output_results(
        self, matches: list, stats: dict, output_file: Path | None
    ) -> None:
        """
        Output match results.

        Args:
            matches: List of ConnectionMatch objects
            stats: Statistics dictionary
            output_file: Output file path (None for stdout)
        """
        lines = []

        # Header
        lines.append("=" * 80)
        lines.append("TCP Connection Matching Results")
        lines.append("=" * 80)
        lines.append("")

        # Statistics
        lines.append("Statistics:")
        lines.append(f"  Total connections (file 1): {stats['total_connections_1']}")
        lines.append(f"  Total connections (file 2): {stats['total_connections_2']}")
        lines.append(f"  Matched pairs: {stats['matched_pairs']}")
        lines.append(f"  Unmatched (file 1): {stats['unmatched_1']}")
        lines.append(f"  Unmatched (file 2): {stats['unmatched_2']}")
        lines.append(f"  Match rate (file 1): {stats['match_rate_1']:.1%}")
        lines.append(f"  Match rate (file 2): {stats['match_rate_2']:.1%}")
        lines.append(f"  Average score: {stats['average_score']:.2f}")
        lines.append("")

        # Matches
        lines.append("Matched Connections:")
        lines.append("-" * 80)

        for i, match in enumerate(matches, 1):
            lines.append(
                f"\n[{i}] A: {match.conn1.client_ip}:{match.conn1.client_port} <-> {match.conn1.server_ip}:{match.conn1.server_port}"
            )
            lines.append(
                f"    B: {match.conn2.client_ip}:{match.conn2.client_port} <-> {match.conn2.server_ip}:{match.conn2.server_port}"
            )
            lines.append(
                f"    置信度: {match.score.normalized_score:.2f} | 证据: {match.score.evidence}"
            )

        lines.append("")
        lines.append("=" * 80)

        # Write output
        output_text = "\n".join(lines)

        if output_file:
            output_file.write_text(output_text)
            logger.info(f"Results written to: {output_file}")
        else:
            print(output_text)


    def _output_endpoint_stats(
        self,
        matches: list,
        file1: Path,
        file2: Path,
        output_file: Path | None,
        disable_very_low_dual_output: bool = False,
    ) -> list:
        """
        Output endpoint statistics for matched connections.

        Args:
            matches: List of ConnectionMatch objects
            file1: Path to first PCAP file
            file2: Path to second PCAP file
            output_file: Output file for statistics (None for stdout)
            disable_very_low_dual_output: Disable dual output for VERY_LOW confidence pairs

        Returns:
            List of EndpointPairStats objects
        """
        # Create detector and collector
        detector = ServerDetector()
        collector = EndpointStatsCollector(
            detector, disable_very_low_dual_output=disable_very_low_dual_output
        )

        # Collect statistics from matches
        for match in matches:
            collector.add_match(match)

        # Finalize collection (performs cardinality analysis)
        collector.finalize()

        # Get aggregated statistics
        stats = collector.get_stats()

        # Format output (use detailed format)
        output_text = format_endpoint_stats(
            stats,
            file1_name=file1.name,
            file2_name=file2.name,
        )

        # Write output
        if output_file:
            output_file.write_text(output_text)
            logger.info(f"Endpoint statistics written to: {output_file}")
        else:
            print(output_text)

        # Return stats for database writing
        return stats

    def _aggregate_and_output_service_stats(
        self,
        endpoint_stats_list: list,
        file1: Path,
        file2: Path,
        output_file: Path | None,
    ) -> list:
        """
        Aggregate endpoint statistics by service and output.

        Args:
            endpoint_stats_list: List of EndpointPairStats objects
            file1: Path to first PCAP file
            file2: Path to second PCAP file
            output_file: Output file for statistics (None for stdout)

        Returns:
            List of ServiceStats objects
        """
        from capmaster.plugins.match.endpoint_stats import aggregate_by_service, format_service_stats

        # Aggregate by service
        service_stats = aggregate_by_service(endpoint_stats_list)

        # Format output
        output_text = format_service_stats(
            service_stats,
            file1_name=file1.name,
            file2_name=file2.name,
        )

        # Write output
        if output_file:
            # Append to existing file or create new one
            with output_file.open("a") as f:
                f.write("\n\n")
                f.write(output_text)
            logger.info(f"Service statistics appended to: {output_file}")
        else:
            print("\n")
            print(output_text)

        return service_stats

    def _load_service_group_mapping(self, mapping_file: Path) -> dict:
        """
        Load service to group ID mapping from JSON file.

        Args:
            mapping_file: Path to JSON file with mapping

        Returns:
            Dictionary mapping ServiceKey to group_id

        Raises:
            ValueError: If JSON file is invalid
        """
        import json
        from capmaster.plugins.match.endpoint_stats import ServiceKey

        try:
            with mapping_file.open("r") as f:
                port_to_group = json.load(f)

            # Convert port strings to ServiceKey objects
            # Assume TCP (protocol 6) by default
            service_to_group = {}
            for port_str, group_id in port_to_group.items():
                port = int(port_str)
                service_key = ServiceKey(server_port=port, protocol=6)
                service_to_group[service_key] = int(group_id)

            logger.info(f"Loaded service group mapping from {mapping_file}")
            logger.info(f"  Mappings: {len(service_to_group)} services")

            return service_to_group

        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"Invalid service group mapping file: {e}")

    def _improve_server_detection(
        self,
        connections: list[TcpConnection],
        detector: ServerDetector,
    ) -> list[TcpConnection]:
        """
        Improve server/client detection using ServerDetector.

        This method re-detects server/client roles for connections where
        the original detection may be unreliable (e.g., missing SYN packets).
        It then rebuilds the IPID sets based on the corrected roles.

        Args:
            connections: List of connections to improve
            detector: ServerDetector with finalized cardinality analysis

        Returns:
            List of connections with improved server/client detection
        """
        from capmaster.core.connection.models import TcpConnection

        improved_connections = []

        for conn in connections:
            # Detect server using multi-layer approach
            server_info = detector.detect(conn)

            # Check if server/client roles need to be swapped
            needs_swap = (
                server_info.server_ip != conn.server_ip
                or server_info.server_port != conn.server_port
            )

            if needs_swap:
                # Swap server/client roles and rebuild IPID sets
                improved_conn = TcpConnection(
                    stream_id=conn.stream_id,
                    protocol=conn.protocol,
                    client_ip=server_info.client_ip,
                    client_port=server_info.client_port,
                    server_ip=server_info.server_ip,
                    server_port=server_info.server_port,
                    syn_timestamp=conn.syn_timestamp,
                    syn_options=conn.syn_options,
                    client_isn=conn.server_isn,  # Swap ISNs
                    server_isn=conn.client_isn,
                    tcp_timestamp_tsval=conn.tcp_timestamp_tsval,
                    tcp_timestamp_tsecr=conn.tcp_timestamp_tsecr,
                    client_payload_md5=conn.server_payload_md5,  # Swap payloads
                    server_payload_md5=conn.client_payload_md5,
                    length_signature=conn.length_signature,
                    is_header_only=conn.is_header_only,
                    ipid_set=conn.ipid_set,
                    ipid_first=conn.ipid_first,
                    client_ipid_set=conn.server_ipid_set,  # Swap IPID sets
                    server_ipid_set=conn.client_ipid_set,
                    first_packet_time=conn.first_packet_time,
                    last_packet_time=conn.last_packet_time,
                    packet_count=conn.packet_count,
                    client_ttl=conn.server_ttl,  # Swap TTLs
                    server_ttl=conn.client_ttl,
                )
                improved_connections.append(improved_conn)
                logger.debug(
                    f"Swapped server/client for stream {conn.stream_id}: "
                    f"{conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port} "
                    f"-> {improved_conn.client_ip}:{improved_conn.client_port} <-> "
                    f"{improved_conn.server_ip}:{improved_conn.server_port} "
                    f"(method: {server_info.method}, confidence: {server_info.confidence})"
                )
            else:
                # No swap needed, keep original connection
                improved_connections.append(conn)

        return improved_connections

    def _write_to_database(
        self,
        db_connection: str,
        kase_id: int,
        endpoint_stats: list,
        file1: Path,
        file2: Path,
        pcap_id_mapping: dict[str, int] | None = None,
        service_stats_list: list | None = None,
        service_group_mapping_file: Path | None = None,
    ) -> None:
        """
        Write endpoint statistics to database.

        Args:
            db_connection: Database connection string
            kase_id: Case ID for table name
            endpoint_stats: List of EndpointPairStats objects
            file1: Path to first PCAP file
            file2: Path to second PCAP file
            pcap_id_mapping: Mapping from file path to pcap_id (optional)
            service_stats_list: List of ServiceStats objects (optional, for service aggregation)
            service_group_mapping_file: JSON file with service to group mapping (optional)
        """
        from capmaster.plugins.match.db_writer import MatchDatabaseWriter

        # Skip database operations if no endpoint pairs or service stats were matched
        if not endpoint_stats and not service_stats_list:
            logger.warning(
                "No endpoint pairs found in match results. "
                "Skipping database write operation to preserve existing data."
            )
            return

        logger.info(f"Writing statistics to database (kase_id={kase_id})...")

        try:
            with MatchDatabaseWriter(db_connection, kase_id) as db:
                # Ensure table exists (create if not exists)
                db.ensure_table_exists()

                # Clear existing data from table before writing new data
                db.clear_table_data()

                # Write service statistics if available
                if service_stats_list:
                    # Load service group mapping if provided
                    service_to_group_mapping = None
                    if service_group_mapping_file:
                        service_to_group_mapping = self._load_service_group_mapping(
                            service_group_mapping_file
                        )

                    records_inserted = db.write_service_stats(
                        service_stats=service_stats_list,
                        pcap_id_mapping=pcap_id_mapping or {},
                        file1_path=str(file1),
                        file2_path=str(file2),
                        service_to_group_mapping=service_to_group_mapping,
                    )
                else:
                    # Write endpoint statistics (original behavior)
                    records_inserted = db.write_endpoint_stats(
                        endpoint_stats=endpoint_stats,
                        pcap_id_mapping=pcap_id_mapping or {},
                        file1_path=str(file1),
                        file2_path=str(file2),
                    )

                # Commit all inserts
                db.commit()

                logger.info(f"Successfully wrote {records_inserted} records to database")

        except ImportError as e:
            logger.error(f"Database functionality not available: {e}")
            logger.error("Install psycopg2-binary to enable database output: pip install psycopg2-binary")
        except Exception as e:
            logger.error(f"Failed to write to database: {e}")
            raise

    def _write_to_json(
        self,
        output_file: Path,
        endpoint_stats: list,
        file1: Path,
        file2: Path,
        pcap_id_mapping: dict[str, int] | None = None,
        service_stats_list: list | None = None,
        service_group_mapping_file: Path | None = None,
    ) -> None:
        """
        Write endpoint statistics to JSON file.

        Args:
            output_file: Path to output JSON file
            endpoint_stats: List of EndpointPairStats objects
            file1: Path to first PCAP file
            file2: Path to second PCAP file
            pcap_id_mapping: Mapping from file path to pcap_id (optional)
            service_stats_list: List of ServiceStats objects (optional, for service aggregation)
            service_group_mapping_file: JSON file with service to group mapping (optional)
        """
        from capmaster.plugins.match.db_writer import MatchDatabaseWriter

        # Skip JSON write if no endpoint pairs or service stats were matched
        if not endpoint_stats and not service_stats_list:
            logger.warning(
                "No endpoint pairs found in match results. "
                "Skipping JSON file write operation."
            )
            return

        logger.info(f"Writing statistics to JSON file: {output_file}")

        try:
            # Write service statistics if available
            if service_stats_list:
                # Load service group mapping if provided
                service_to_group_mapping = None
                if service_group_mapping_file:
                    service_to_group_mapping = self._load_service_group_mapping(
                        service_group_mapping_file
                    )

                records_written = MatchDatabaseWriter.write_service_stats_to_json(
                    service_stats=service_stats_list,
                    pcap_id_mapping=pcap_id_mapping or {},
                    file1_path=str(file1),
                    file2_path=str(file2),
                    output_file=output_file,
                    service_to_group_mapping=service_to_group_mapping,
                )
            else:
                # Write endpoint statistics (original behavior)
                records_written = MatchDatabaseWriter.write_endpoint_stats_to_json(
                    endpoint_stats=endpoint_stats,
                    pcap_id_mapping=pcap_id_mapping or {},
                    file1_path=str(file1),
                    file2_path=str(file2),
                    output_file=output_file,
                )

            logger.info(f"Successfully wrote {records_written} records to {output_file}")

        except Exception as e:
            logger.error(f"Failed to write to JSON file: {e}")
            raise
