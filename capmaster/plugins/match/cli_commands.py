"""CLI registration helpers for the match plugin.

Only contains the comparative-analysis subcommand to keep MatchPlugin lean.
"""
from __future__ import annotations

from pathlib import Path
import click

from capmaster.utils.cli_options import (
    dual_file_input_options,
    validate_dual_file_input,
)


def register_comparative_analysis_command(plugin, cli_group: click.Group) -> None:
    """Register the comparative-analysis subcommand on the given click group.

    This function mirrors the inlined definition previously inside
    MatchPlugin.setup_cli, but keeps the implementation out of plugin.py
    to reduce file size and improve readability.
    """

    @cli_group.command(name="comparative-analysis")
    @dual_file_input_options
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
        file1_pcapid: int | None,
        file2: Path | None,
        file2_pcapid: int | None,
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
        # Validate input parameters
        validate_dual_file_input(ctx, input_path, file1, file2, file1_pcapid, file2_pcapid)

        # Validate analysis type parameters
        if not service and not matched_connections:
            ctx.fail("Please specify an analysis type: --service (requires --topology) or --matched-connections")

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
            analysis_type=analysis_type,
            topology_file=topology,
            matched_connections_file=matched_connections,
            top_n=top_n,
            output_file=output_file,
        )
        ctx.exit(exit_code)

