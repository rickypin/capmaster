"""CLI command registration for the compare plugin.

This module defines a thin wrapper that registers the compare subcommand to the
provided Click group, delegating execution back to the provided plugin instance.
"""

from __future__ import annotations

from pathlib import Path
import click

from capmaster.utils.cli_options import validate_database_params, validate_dual_file_input


def register_compare_command(plugin: "ComparePlugin", cli_group: click.Group) -> None:
    """Register the compare CLI command on the given Click group.

    The CLI options and help text remain unchanged. The handler delegates to
    the provided plugin instance to execute the logic.
    """

    @cli_group.command(name=plugin.name)
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
        help=(
            "Only compare packets that exist in both A and B with matching IPID "
            "(ignore packets only in A or only in B)"
        ),
    )
    @click.option(
        "--db-connection",
        type=str,
        help=(
            'Database connection string (e.g., "postgresql://user:pass@host:port/db"). '
            "When provided, results will be written to database."
        ),
    )
    @click.option(
        "--kase-id",
        type=int,
        help=(
            "Case ID for database table name (e.g., 133 -> kase_133_tcp_stream_extra). "
            "Required when --db-connection is used."
        ),
    )
    @click.option(
        "--silent",
        is_flag=True,
        default=False,
        help=(
            "Silent mode: suppress progress bars and screen output "
            "(logs and file output still work)"
        ),
    )
    @click.option(
        "--match-mode",
        type=click.Choice(["one-to-one", "one-to-many"], case_sensitive=False),
        default="one-to-one",
        help=(
            "Matching mode (one-to-one: each connection matches at most once, "
            "one-to-many: allow one connection to match multiple connections based "
            "on time overlap)"
        ),
    )
    @click.option(
        "--match-file",
        type=click.Path(exists=True, path_type=Path),
        help=(
            "JSON file containing match results from the match command. "
            "When provided, compare will use these matches instead of performing its "
            "own matching. This ensures consistency between match and compare results."
        ),
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
        match_mode: str,
        match_file: Path | None,
    ) -> None:
        """Compare TCP connections at packet level between PCAP files.

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
          capmaster compare -i /path/to/pcaps/ --show-flow-hash \
            --db-connection "postgresql://postgres:password@172.16.200.156:5433/r2" \
            --kase-id 133

          # Use file1/file2 with pcap_id mapping
          capmaster compare --file1 a.pcap --file1-pcapid 0 --file2 b.pcap --file2-pcapid 1 \
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
        # Validate input parameters
        validate_dual_file_input(ctx, input_path, file1, file2, file1_pcapid, file2_pcapid)

        # Validate database parameters
        validate_database_params(
            ctx, db_connection, kase_id, "show-flow-hash", show_flow_hash
        )

        exit_code = plugin.execute(
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
            match_mode=match_mode,
            match_file=match_file,
        )
        ctx.exit(exit_code)

