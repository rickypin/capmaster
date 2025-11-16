"""Match plugin for TCP connection matching."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import click
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)

from capmaster.core.connection.behavioral_matcher import BehavioralMatcher
from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.core.connection.f5_matcher import F5Matcher
from capmaster.core.connection.matcher import BucketStrategy, ConnectionMatcher, MatchMode
from capmaster.core.connection.models import TcpConnection
from capmaster.core.connection.tls_matcher import TlsMatcher
from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.match.cli_commands import register_comparative_analysis_command
from capmaster.plugins.match.runner import (
    match_connections_in_memory as run_match_in_memory,
    run_match_pipeline,
)
from capmaster.plugins.match.endpoint_stats import (
    EndpointStatsCollector,
    ServiceKey,
    aggregate_by_service,
    format_endpoint_stats,
    format_service_stats,
)
from capmaster.plugins.match.output_formatter import (
    output_match_results,
    save_matches_json,
)
from capmaster.plugins.match.sampler import ConnectionSampler
from capmaster.plugins.match.server_detector import ServerDetector
from capmaster.plugins.match.strategies import (
    convert_f5_matches_to_connection_matches,
    convert_tls_matches_to_connection_matches,
)
from capmaster.utils.cli_options import (
    dual_file_input_options,
    validate_database_params,
)
from capmaster.utils.errors import (
    InsufficientFilesError,
    handle_error,
)
from capmaster.utils.input_parser import DualFileInputParser
from capmaster.utils.meta_writer import write_meta_json

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
            type=click.Choice(["auto", "header", "behavioral"], case_sensitive=False),
            default="auto",
            help="Matching mode (auto: automatic, header: header-only, behavioral: behavior-only)",
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
            "--behavioral-weight-overlap",
            type=float,
            default=0.35,
            help="Weight for time overlap feature in behavioral matching (default: 0.35)",
        )
        @click.option(
            "--behavioral-weight-duration",
            type=float,
            default=0.25,
            help="Weight for duration similarity feature in behavioral matching (default: 0.25)",
        )
        @click.option(
            "--behavioral-weight-iat",
            type=float,
            default=0.20,
            help="Weight for inter-arrival time similarity feature in behavioral matching (default: 0.20)",
        )
        @click.option(
            "--behavioral-weight-bytes",
            type=float,
            default=0.20,
            help="Weight for total bytes similarity feature in behavioral matching (default: 0.20)",
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
            "--enable-sampling",
            is_flag=True,
            default=False,
            help="Enable connection sampling for large datasets. When enabled, sampling is triggered "
            "when connection count exceeds --sample-threshold (default: 1000 connections).",
        )
        @click.option(
            "--sample-threshold",
            type=int,
            default=1000,
            help="Number of connections above which sampling is triggered when --enable-sampling is used (default: 1000)",
        )
        @click.option(
            "--sample-rate",
            type=float,
            default=0.5,
            help="Fraction of connections to keep when sampling is enabled (0.0-1.0, default: 0.5)",
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
            'Format: {"8000": 1, "8080": 1, "443": 2}. '
            "Only used when service aggregation is enabled (default behavior).",
        )
        @click.option(
            "--match-json",
            type=click.Path(path_type=Path),
            help="Output JSON file for match results. This file can be used as input to the compare command "
            "to ensure consistent matching between match and compare operations.",
        )
        @click.option(
            "--topology",
            is_flag=True,
            default=False,
            help="Output network topology analysis based on matched connections. "
            "Shows the relative positions of capture points and network devices.",
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
            behavioral_weight_overlap: float,
            behavioral_weight_duration: float,
            behavioral_weight_iat: float,
            behavioral_weight_bytes: float,
            endpoint_stats: bool,
            endpoint_stats_output: Path | None,
            enable_sampling: bool,
            sample_threshold: int,
            sample_rate: float,
            db_connection: str | None,
            kase_id: int | None,
            endpoint_stats_json: Path | None,
            merge_by_5tuple: bool,
            endpoint_pair_mode: bool,
            service_group_mapping: Path | None,
            match_json: Path | None,
            topology: bool,
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

              # Enable sampling for large datasets (default: disabled)
              capmaster match -i captures/ --enable-sampling

              # Custom sampling parameters
              capmaster match -i captures/ --enable-sampling --sample-threshold 5000 --sample-rate 0.3

            \b
            Bucketing Strategies:
              auto    - Automatically choose best strategy
              server  - Group by server IP
              port    - Group by server port
              none    - No bucketing (compare all pairs)

            \b
            Sampling:
              By default, sampling is DISABLED and all connections are processed.
              Use --enable-sampling to enable sampling for large datasets.
              When enabled, sampling is triggered when connection count exceeds
              --sample-threshold (default: 1000). Sampling uses time-based stratified
              sampling and always preserves header-only connections and special ports.

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
            # Dual-file input validation is handled by @dual_file_input_options callback.

            # Validate database parameters
            validate_database_params(ctx, db_connection, kase_id, "endpoint-stats", endpoint_stats)

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
                behavioral_weight_overlap=behavioral_weight_overlap,
                behavioral_weight_duration=behavioral_weight_duration,
                behavioral_weight_iat=behavioral_weight_iat,
                behavioral_weight_bytes=behavioral_weight_bytes,
                endpoint_stats=endpoint_stats,
                endpoint_stats_output=endpoint_stats_output,
                enable_sampling=enable_sampling,
                sample_threshold=sample_threshold,
                sample_rate=sample_rate,
                db_connection=db_connection,
                kase_id=kase_id,
                endpoint_stats_json=endpoint_stats_json,
                merge_by_5tuple=merge_by_5tuple,
                endpoint_pair_mode=endpoint_pair_mode,
                service_group_mapping=service_group_mapping,
                match_json=match_json,
                topology=topology,
            )
            ctx.exit(exit_code)

        # Register extracted comparative-analysis subcommand
        register_comparative_analysis_command(self, cli_group)

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
        behavioral_weight_overlap: float = 0.35,
        behavioral_weight_duration: float = 0.25,
        behavioral_weight_iat: float = 0.20,
        behavioral_weight_bytes: float = 0.20,
        endpoint_stats: bool = False,
        endpoint_stats_output: Path | None = None,
        enable_sampling: bool = False,
        sample_threshold: int = 1000,
        sample_rate: float = 0.5,
        db_connection: str | None = None,
        kase_id: int | None = None,
        endpoint_stats_json: Path | None = None,
        merge_by_5tuple: bool = False,
        endpoint_pair_mode: bool = False,
        service_group_mapping: Path | None = None,
        match_json: Path | None = None,
        topology: bool = False,
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
            behavioral_weight_overlap: Weight for time overlap in behavioral matching
            behavioral_weight_duration: Weight for duration similarity in behavioral matching
            behavioral_weight_iat: Weight for inter-arrival-time similarity in behavioral matching
            behavioral_weight_bytes: Weight for total-bytes similarity in behavioral matching
            endpoint_stats: Generate endpoint statistics
            endpoint_stats_output: Output file for endpoint statistics
            enable_sampling: Enable sampling for large datasets (default: False)
            sample_threshold: Connection count threshold for sampling
            sample_rate: Fraction of connections to keep when sampling
            db_connection: Database connection string
            kase_id: Case ID for database table name
            endpoint_stats_json: Output JSON file for endpoint statistics
            merge_by_5tuple: Merge connections by direction-independent 5-tuple
            endpoint_pair_mode: Use endpoint pair mode instead of service aggregation (default: False)
            service_group_mapping: JSON file mapping service ports to group IDs
            match_json: Output JSON file for match results (can be used as input to compare command)
            topology: Output network topology analysis

        Returns:
            Exit code (0 for success, non-zero for failure)


        # Delegate to runner.run_match_pipeline for the actual implementation.
        # The runner function preserves the original behaviour (parameter
        # validation, progress reporting, matching logic, and error handling).
        return run_match_pipeline(
            input_path=input_path,
            file1=file1,
            file1_pcapid=file1_pcapid,
            file2=file2,
            file2_pcapid=file2_pcapid,
            output_file=output_file,
            mode=mode,
            bucket_strategy=bucket_strategy,
            score_threshold=score_threshold,
            match_mode=match_mode,
            behavioral_weight_overlap=behavioral_weight_overlap,
            behavioral_weight_duration=behavioral_weight_duration,
            behavioral_weight_iat=behavioral_weight_iat,
            behavioral_weight_bytes=behavioral_weight_bytes,
            endpoint_stats=endpoint_stats,
            endpoint_stats_output=endpoint_stats_output,
            enable_sampling=enable_sampling,
            sample_threshold=sample_threshold,
            sample_rate=sample_rate,
            db_connection=db_connection,
            kase_id=kase_id,
            endpoint_stats_json=endpoint_stats_json,
            merge_by_5tuple=merge_by_5tuple,
            endpoint_pair_mode=endpoint_pair_mode,
            service_group_mapping=service_group_mapping,
            match_json=match_json,
            topology=topology,
        )

        Raises:
            ValueError: If parameters are invalid
        """
        # Validate parameters
        if not 0.0 <= score_threshold <= 1.0:
            logger.error(f"Invalid score threshold: {score_threshold}. Must be between 0.0 and 1.0")
            return 1

        if not 0.0 < sample_rate <= 1.0:
            logger.error(f"Invalid sample rate: {sample_rate}. Must be between 0.0 and 1.0")
            return 1

        if sample_threshold <= 0:
            logger.error(f"Invalid sample threshold: {sample_threshold}. Must be positive")
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

                # Determine matching strategy: F5 > TLS > Feature-based, or explicit behavioral
                use_f5_matching = False
                use_tls_matching = False
                use_behavioral = mode.lower() == "behavioral"

                if use_behavioral:
                    logger.info("Behavioral-only mode selected - skipping F5/TLS detection")
                else:
                    # Check for F5 Ethernet Trailer first (highest priority)
                    detect_task = progress.add_task(
                        "[cyan]Detecting F5 Ethernet Trailer...", total=2
                    )
                    f5_matcher = F5Matcher()

                    has_f5_file1 = f5_matcher.detect_f5_trailer(match_file1)
                    progress.update(detect_task, advance=1)

                    has_f5_file2 = f5_matcher.detect_f5_trailer(match_file2)
                    progress.update(detect_task, advance=1)

                    use_f5_matching = has_f5_file1 and has_f5_file2

                    if use_f5_matching:
                        logger.info(
                            "F5 Ethernet Trailer detected in both files - using F5 matching mode"
                        )
                    else:
                        if has_f5_file1 or has_f5_file2:
                            logger.warning(
                                f"F5 trailer found in {'file1' if has_f5_file1 else 'file2'} only - "
                                "will check for TLS Client Hello"
                            )

                        # Check for TLS Client Hello if F5 is not available (medium priority)
                        detect_task = progress.add_task(
                            "[cyan]Detecting TLS Client Hello...", total=2
                        )
                        tls_matcher = TlsMatcher()

                        has_tls_file1 = tls_matcher.detect_tls_client_hello(match_file1)
                        progress.update(detect_task, advance=1)

                        has_tls_file2 = tls_matcher.detect_tls_client_hello(match_file2)
                        progress.update(detect_task, advance=1)

                        use_tls_matching = has_tls_file1 and has_tls_file2

                        if use_tls_matching:
                            logger.info(
                                "TLS Client Hello detected in both files - using TLS matching mode"
                            )
                        else:
                            if has_tls_file1 or has_tls_file2:
                                logger.warning(
                                    f"TLS Client Hello found in {'file1' if has_tls_file1 else 'file2'} only - "
                                    "falling back to feature-based matching"
                                )
                            logger.info("Using feature-based matching mode")

                # Log final matching strategy
                if use_f5_matching:
                    logger.info("Final matching strategy: F5 Ethernet Trailer")
                elif use_tls_matching:
                    logger.info("Final matching strategy: TLS Client Hello")
                elif use_behavioral:
                    logger.info("Final matching strategy: Behavioral (behavior-only)")
                else:
                    logger.info("Final matching strategy: Feature-based")

                # Extract connections from both files
                extract_task = progress.add_task("[cyan]Extracting connections...", total=2)

                progress.update(
                    extract_task, description=f"[cyan]Extracting from {match_file1.name}..."
                )
                connections1 = self._extract_connections(
                    match_file1, merge_by_5tuple=merge_by_5tuple
                )
                logger.info(f"Found {len(connections1)} connections in {match_file1.name}")
                if merge_by_5tuple:
                    logger.info("  (merged by direction-independent 5-tuple)")
                progress.update(extract_task, advance=1)

                progress.update(
                    extract_task, description=f"[cyan]Extracting from {match_file2.name}..."
                )
                connections2 = self._extract_connections(
                    match_file2, merge_by_5tuple=merge_by_5tuple
                )
                logger.info(f"Found {len(connections2)} connections in {match_file2.name}")
                if merge_by_5tuple:
                    logger.info("  (merged by direction-independent 5-tuple)")
                progress.update(extract_task, advance=1)

                # Apply sampling if enabled
                if enable_sampling:
                    # Validate sampling parameters
                    if sample_rate <= 0.0 or sample_rate > 1.0:
                        logger.warning(f"Invalid sample rate {sample_rate}, using default 0.5")
                        sample_rate = 0.5

                    if sample_threshold < 1:
                        logger.warning(
                            f"Invalid sample threshold {sample_threshold}, using default 1000"
                        )
                        sample_threshold = 1000

                    sampler = ConnectionSampler(
                        threshold=sample_threshold,
                        sample_rate=sample_rate,
                    )

                    if sampler.should_sample(connections1):
                        sample_task = progress.add_task("[yellow]Sampling connections...", total=1)
                        logger.info(
                            f"Applying sampling to first file (threshold={sample_threshold}, rate={sample_rate})..."
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
                            f"Applying sampling to second file (threshold={sample_threshold}, rate={sample_rate})..."
                        )
                        original_count2 = len(connections2)
                        connections2 = sampler.sample(connections2)
                        logger.info(
                            f"Sampled from {original_count2} to {len(connections2)} connections "
                            f"({len(connections2)/original_count2:.1%} retained)"
                        )
                        progress.update(sample_task, advance=1)
                else:
                    logger.info(
                        "Sampling disabled (default behavior). Use --enable-sampling to enable."
                    )

                # Branch based on matching mode
                matcher: ConnectionMatcher | BehavioralMatcher
                if use_f5_matching:
                    # F5-based matching
                    match_task = progress.add_task(
                        "[green]Matching connections using F5 trailers...", total=1
                    )
                    logger.info("Matching connections using F5 Ethernet Trailer...")

                    f5_matcher = F5Matcher()
                    f5_matches = f5_matcher.match(match_file1, match_file2)
                    logger.info(f"Found {len(f5_matches)} F5-based matches")

                    # Convert F5 matches to standard ConnectionMatch format
                    matches = convert_f5_matches_to_connection_matches(
                        f5_matches, connections1, connections2
                    )
                    progress.update(match_task, advance=1)

                    # Create a matcher instance for statistics calculation
                    matcher = ConnectionMatcher(
                        bucket_strategy=BucketStrategy("auto"),
                        score_threshold=score_threshold,
                        match_mode=MatchMode(match_mode),
                    )
                elif use_tls_matching:
                    # TLS-based matching
                    match_task = progress.add_task(
                        "[green]Matching connections using TLS Client Hello...", total=1
                    )
                    logger.info("Matching connections using TLS Client Hello...")

                    tls_matcher = TlsMatcher()
                    tls_matches = tls_matcher.match(match_file1, match_file2)
                    logger.info(f"Found {len(tls_matches)} TLS-based matches")

                    # Convert TLS matches to standard ConnectionMatch format
                    matches = convert_tls_matches_to_connection_matches(
                        tls_matches, connections1, connections2
                    )
                    progress.update(match_task, advance=1)

                    # Create a matcher instance for statistics calculation
                    matcher = ConnectionMatcher(
                        bucket_strategy=BucketStrategy("auto"),
                        score_threshold=score_threshold,
                        match_mode=MatchMode(match_mode),
                    )
                elif use_behavioral:
                    # Behavioral-only matching
                    detector_task = progress.add_task(
                        "[yellow]Analyzing server/client roles...", total=1
                    )
                    logger.info(
                        "Performing cardinality analysis for server detection (behavioral mode)..."
                    )
                    detector = self._create_and_populate_detector(connections1, connections2)
                    connections1 = self._improve_server_detection(connections1, detector)
                    connections2 = self._improve_server_detection(connections2, detector)
                    progress.update(detector_task, advance=1)

                    match_task = progress.add_task(
                        "[green]Matching connections (behavioral)...", total=1
                    )
                    logger.info("Matching connections using behavioral features only...")
                    bucket_enum = BucketStrategy(bucket_strategy)
                    match_mode_enum = MatchMode(match_mode)
                    matcher = BehavioralMatcher(
                        bucket_strategy=bucket_enum,
                        score_threshold=score_threshold,
                        match_mode=match_mode_enum,
                        weight_overlap=behavioral_weight_overlap,
                        weight_duration=behavioral_weight_duration,
                        weight_iat=behavioral_weight_iat,
                        weight_bytes=behavioral_weight_bytes,
                    )
                    matches = matcher.match(connections1, connections2)
                    logger.info(f"Found {len(matches)} matches (behavioral)")
                    progress.update(match_task, advance=1)
                else:
                    # Feature-based matching (original logic)
                    # Improve server detection using cardinality analysis
                    detector_task = progress.add_task(
                        "[yellow]Analyzing server/client roles...", total=1
                    )
                    logger.info("Performing cardinality analysis for server detection...")

                    # Create and populate detector using helper method
                    detector = self._create_and_populate_detector(connections1, connections2)

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

                # Output topology if requested (takes precedence over regular results)
                if topology:
                    topology_task = progress.add_task("[green]Analyzing topology...", total=1)
                    self._output_topology(matches, match_file1, match_file2, output_file)
                    progress.update(topology_task, advance=1)
                else:
                    # Output regular match results
                    output_task = progress.add_task("[green]Writing results...", total=1)
                    output_match_results(matches, stats, output_file)
                    progress.update(output_task, advance=1)

                # Save matches to JSON if requested
                if match_json:
                    json_task = progress.add_task("[green]Saving matches to JSON...", total=1)
                    save_matches_json(
                        matches,
                        match_json,
                        match_file1,
                        match_file2,
                        stats,
                    )
                    progress.update(json_task, advance=1)

                # Generate endpoint statistics if requested
                if endpoint_stats:
                    endpoint_task = progress.add_task(
                        "[green]Generating endpoint statistics...", total=1
                    )
                    endpoint_stats_list = self._output_endpoint_stats(
                        matches,
                        match_file1,
                        match_file2,
                        endpoint_stats_output,
                    )
                    progress.update(endpoint_task, advance=1)

                    # Aggregate by service by default (unless endpoint_pair_mode is enabled)
                    service_stats_list = None
                    if not endpoint_pair_mode:
                        service_task = progress.add_task(
                            "[green]Aggregating by service...", total=1
                        )
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
                f"File system error: {e}", "Check file permissions and ensure files are accessible"
            )
            return handle_error(error, show_traceback=logger.level <= logging.DEBUG)
        except RuntimeError as e:
            # Tshark or processing errors
            from capmaster.utils.errors import CapMasterError

            error = CapMasterError(
                f"Processing error: {e}", "Check that PCAP files are valid and tshark is working"
            )
            return handle_error(error, show_traceback=logger.level <= logging.DEBUG)
        except Exception as e:
            # Unexpected errors - show traceback in debug mode
            return handle_error(e, show_traceback=logger.level <= logging.DEBUG)

    def match_connections_in_memory(
        self,
        connections1: list,
        connections2: list,
        bucket_strategy: str = "auto",
        score_threshold: float = 0.60,
        match_mode: str = "one-to-one",
    ) -> list:
        """Match connections in memory with full ServerDetector processing.

        This method provides the same matching logic as the execute() method,
        but operates on pre-extracted connections in memory without file I/O.
        It includes the complete ServerDetector cardinality analysis pipeline.

        This is designed to be called by other plugins (e.g., compare plugin)
        to ensure consistent matching results.
        """

        logger.info("Delegating in-memory matching to runner.match_connections_in_memory")
        return run_match_in_memory(
            connections1,
            connections2,
            bucket_strategy=bucket_strategy,
            score_threshold=score_threshold,
            match_mode=match_mode,
        )

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


    def _output_results(self, matches: list, stats: dict, output_file: Path | None) -> None:
        """Delegated to capmaster.plugins.match.output_formatter.output_match_results."""
        from capmaster.plugins.match.output_formatter import output_match_results

        output_match_results(matches, stats, output_file)

    def _save_matches_json(
        self,
        matches: list,
        output_file: Path,
        file1: Path,
        file2: Path,
        stats: dict,
    ) -> None:
        """Delegated to capmaster.plugins.match.output_formatter.save_matches_json."""
        from capmaster.plugins.match.output_formatter import save_matches_json

        save_matches_json(matches, output_file, file1, file2, stats)

    def _output_endpoint_stats(
        self,
        matches: list,
        file1: Path,
        file2: Path,
        output_file: Path | None,
    ) -> list:
        """
        Output endpoint statistics for matched connections.

        Args:
            matches: List of ConnectionMatch objects
            file1: Path to first PCAP file
            file2: Path to second PCAP file
            output_file: Output file for statistics (None for stdout)

        Returns:
            List of EndpointPairStats objects
        """
        # Create detector and collector
        detector = ServerDetector()
        collector = EndpointStatsCollector(detector)

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
            # Ensure parent directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(output_text)
            logger.info(f"Endpoint statistics written to: {output_file}")
        else:
            print(output_text)

        # Return stats for database writing
        return stats

    def _output_topology(
        self,
        matches: list,
        file1: Path,
        file2: Path,
        output_file: Path | None = None,
    ) -> None:
        """
        Output network topology analysis for matched connections.

        Args:
            matches: List of ConnectionMatch objects
            file1: Path to first PCAP file
            file2: Path to second PCAP file
            output_file: Optional output file path (None for stdout)
        """
        from capmaster.plugins.match.topology import TopologyAnalyzer, format_topology

        # Analyze topology
        analyzer = TopologyAnalyzer(matches, file1, file2)
        topology_info = analyzer.analyze()

        # Format and output
        output_text = format_topology(topology_info)

        if output_file:
            # Ensure parent directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(output_text)
            logger.info(f"Topology analysis written to: {output_file}")

            # Write meta.json file
            write_meta_json(
                output_file=output_file,
                command_id="topology",
                source="basic",
            )
        else:
            print(output_text)

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
            raise ValueError(f"Invalid service group mapping file: {e}") from e

    def _create_and_populate_detector(
        self,
        connections1: list[TcpConnection],
        connections2: list[TcpConnection],
    ) -> ServerDetector:
        """
        Create a ServerDetector and populate it with connections from both files.

        This helper method eliminates code duplication by centralizing the common
        pattern of creating a detector, collecting connections, and finalizing.

        Args:
            connections1: Connections from first file
            connections2: Connections from second file

        Returns:
            ServerDetector with finalized cardinality analysis
        """
        detector = ServerDetector()

        # Collect all connections for cardinality analysis
        for conn in connections1:
            detector.collect_connection(conn)
        for conn in connections2:
            detector.collect_connection(conn)

        # Finalize cardinality analysis
        detector.finalize_cardinality()

        return detector

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
            logger.error(
                "Install psycopg2-binary to enable database output: pip install psycopg2-binary"
            )
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
                "No endpoint pairs found in match results. " "Skipping JSON file write operation."
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

    def execute_comparative_analysis(
        self,
        input_path: str | Path | None = None,
        file1: Path | None = None,
        file2: Path | None = None,
        analysis_type: str = "service",
        topology_file: Path | None = None,
        matched_connections_file: Path | None = None,
        top_n: int | None = None,
        output_file: Path | None = None,
    ) -> int:
        """
        Execute comparative analysis between two PCAP files.

        Args:
            input_path: Directory or comma-separated list of PCAP files
            file1: Path to first PCAP file (alternative to input_path)
            file2: Path to second PCAP file (alternative to input_path)
            analysis_type: Type of analysis to perform ("service", "connections", or "both")
            topology_file: Path to topology file (for service analysis)
            matched_connections_file: Path to matched connections file (for connection pair analysis)
            top_n: Show top N worst performing connection pairs (only for connection analysis)
            output_file: Optional output file path (None for stdout)

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            from capmaster.plugins.match.quality_analyzer import (
                QualityAnalyzer,
                format_connection_pair_report,
                format_quality_report,
                parse_matched_connections,
                parse_topology_services,
            )

            logger.info(f"Starting comparative analysis (type: {analysis_type})...")

            # Parse input to get file1 and file2
            if input_path:
                try:
                    dual_input = DualFileInputParser.parse(
                        input_path=input_path,
                        file1=file1,
                        file2=file2,
                        file1_pcapid=None,
                        file2_pcapid=None,
                    )
                    file1 = dual_input.file1
                    file2 = dual_input.file2
                    logger.info("Using files from input path:")
                    logger.info(f"  File 1: {file1}")
                    logger.info(f"  File 2: {file2}")
                except InsufficientFilesError as e:
                    logger.error(str(e))
                    return 1

            # Validate that we have both files
            if not file1 or not file2:
                logger.error("Both file1 and file2 must be specified")
                return 1

            analyzer = QualityAnalyzer()
            reports = []

            # Service-level analysis
            if analysis_type in ("service", "both"):
                if not topology_file:
                    logger.error("Topology file must be specified for service analysis")
                    return 1

                # Parse topology file to extract services
                logger.info(f"Parsing topology file: {topology_file}")
                services = parse_topology_services(topology_file)

                if not services:
                    logger.error("No services found in topology file")
                    return 1

                logger.info(f"Found {len(services)} services to analyze")
                for ip, port in services:
                    logger.info(f"  - {ip}:{port}")

                # Analyze quality metrics
                logger.info("Analyzing service-level quality metrics...")
                service_results = analyzer.analyze_service_quality(file1, file2, services)

                # Format report
                service_report = format_quality_report(service_results, file1.name, file2.name)
                reports.append(service_report)

            # Connection-pair analysis
            if analysis_type in ("connections", "both"):
                if not matched_connections_file:
                    logger.error(
                        "Matched connections file must be specified for connection pair analysis"
                    )
                    return 1

                # Parse matched connections file
                logger.info(f"Parsing matched connections file: {matched_connections_file}")
                connection_pairs = parse_matched_connections(matched_connections_file)

                if not connection_pairs:
                    logger.error("No connection pairs found in matched connections file")
                    return 1

                logger.info(f"Found {len(connection_pairs)} connection pairs to analyze")

                # Analyze quality metrics for each connection pair
                logger.info("Analyzing connection-pair quality metrics...")
                pair_results = analyzer.analyze_connection_pairs(file1, file2, connection_pairs)

                # Format report
                pair_report = format_connection_pair_report(
                    pair_results, file1.name, file2.name, top_n=top_n
                )
                reports.append(pair_report)

            # Combine reports
            if analysis_type == "both":
                report = "\n\n".join(reports)
            else:
                report = reports[0] if reports else ""

            # Output results
            if output_file:
                logger.info(f"Writing comparative analysis report to: {output_file}")
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(report)
                logger.info(f"Comparative analysis report written to: {output_file}")

                # Write meta.json file
                # Determine command_id based on analysis_type
                if analysis_type == "service":
                    command_id = "comparative-analysis-service"
                elif analysis_type == "connections":
                    command_id = "poor-quality-connections"
                else:  # both
                    command_id = "comparative-analysis-both"

                write_meta_json(
                    output_file=output_file,
                    command_id=command_id,
                    source="basic",
                )
            else:
                print(report)

            logger.info("Comparative analysis completed successfully")
            return 0

        except Exception as e:
            return handle_error(e, show_traceback=True)
