"""CLI registration helpers for the match plugin.

Only contains the comparative-analysis subcommand to keep MatchPlugin lean.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from capmaster.utils.cli_options import unified_input_options, validate_database_params




def register_match_command(plugin: Any, cli_group: click.Group) -> None:
    """Register the main 'match' subcommand on the given click group.

    This function mirrors the inlined definition previously inside
    MatchPlugin.setup_cli, but keeps the implementation out of plugin.py
    to reduce file size and improve readability.
    """

    @cli_group.command(name=plugin.name, context_settings=dict(help_option_names=["-h", "--help"]))
    @unified_input_options
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
        "--service-list",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Path to a text file containing known server IPs and ports (e.g., 10.10.10.10:80 or 10.10.10.11:*)",
    )
    @click.pass_context
    def match_command(
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
        service_list: Path | None,
    ) -> None:
        """Match TCP connections between PCAP files.

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
          capmaster match --file1 a.pcap --file1-pcapid 0 --file2 b.pcap --file2-pcapid 1 \
            --endpoint-stats \
            --db-connection "postgresql://postgres:password@host:port/db" \
            --kase-id 137

        \b
        JSON Output:
          # Write endpoint statistics to JSON file (one JSON object per line)
          capmaster match --file1 a.pcap --file1-pcapid 0 --file2 b.pcap --file2-pcapid 1 \
            --endpoint-stats \
            --endpoint-stats-json endpoint_stats.json
        """
        # Dual-file input validation is handled by @dual_file_input_options callback.

        # Validate database parameters
        validate_database_params(ctx, db_connection, kase_id, "endpoint-stats", endpoint_stats)

        exit_code = plugin.execute(
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
            service_list=service_list,
        )
        ctx.exit(exit_code)



def register_comparative_analysis_command(plugin: Any, cli_group: click.Group) -> None:
    """Register the comparative-analysis subcommand on the given click group.

    This function mirrors the inlined definition previously inside
    MatchPlugin.setup_cli, but keeps the implementation out of plugin.py
    to reduce file size and improve readability.
    """

    @cli_group.command(name="comparative-analysis", context_settings=dict(help_option_names=["-h", "--help"]))
    @unified_input_options
    @click.option(
        "--service",
        is_flag=True,
        default=False,
        help="Perform comparative analysis on services (network quality metrics)",
    )
    @click.option(
        "--matched-connections",
        type=click.Path(exists=True, path_type=Path),
        help="Matched connections file for per-connection-pair analysis",
    )
    @click.option(
        "--top-n",
        type=int,
        default=None,
        help="Show top N worst performing connection pairs (only with --matched-connections)",
    )
    @click.option(
        "--topology",
        type=click.Path(exists=True, path_type=Path),
        help="Topology file (topology.txt) containing service information (required for --service)",
    )
    @click.option(
        "-o",
        "--output",
        "output_file",
        type=click.Path(path_type=Path),
        help="Output file for comparative analysis report (default: stdout)",
    )
    @click.pass_context
    def comparative_analysis_command(
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
        service: bool,
        matched_connections: Path | None,
        top_n: int | None,
        topology: Path | None,
        output_file: Path | None,
    ) -> None:
        """
        Perform comparative analysis between two PCAP files.

        This command performs comparative analysis to identify differences
        and quality metrics between two capture points.

        \b
        Examples:
          # Comparative analysis on services using directory
          capmaster comparative-analysis -i /path/to/pcaps/ --service --topology topology.txt

          # Comparative analysis on connection pairs
          capmaster comparative-analysis -i /path/to/pcaps/ --matched-connections matched.txt

          # Combine both analyses
          capmaster comparative-analysis -i /path/to/pcaps/ --service --topology topology.txt --matched-connections matched.txt

        \b
        Input:
          The input can be a directory containing exactly 2 PCAP files,
          or a comma-separated list of exactly 2 PCAP files,
          or specified using --file1 and --file2.

        \b
        Analysis Types:
          --service: Analyze network quality metrics aggregated by services
            Requires: --topology file

          --matched-connections: Analyze network quality metrics for each matched connection pair
            Requires: matched connections file from 'capmaster match' command

        \b
        Output:
          Comparative analysis report showing differences and metrics
          between the two PCAP files.
        """
        # Dual-file input validation is handled by @dual_file_input_options callback.

        # Validate analysis type parameters
        if not service and not matched_connections:
            ctx.fail(
                "Please specify an analysis type: --service (requires --topology) or --matched-connections"
            )

        if service and not topology:
            ctx.fail("--service analysis requires --topology file")

        if top_n is not None and not matched_connections:
            ctx.fail("--top-n can only be used with --matched-connections")

        # Determine analysis type
        analysis_type = None
        if service and matched_connections:
            analysis_type = "both"
        elif service:
            analysis_type = "service"
        elif matched_connections:
            analysis_type = "connections"

        exit_code = plugin.execute_comparative_analysis(
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
            analysis_type=analysis_type,
            topology_file=topology,
            matched_connections_file=matched_connections,
            top_n=top_n,
            output_file=output_file,
        )
        ctx.exit(exit_code)
