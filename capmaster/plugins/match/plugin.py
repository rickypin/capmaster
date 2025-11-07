"""Match plugin for TCP connection matching."""

import logging
from pathlib import Path

import click
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from capmaster.core.file_scanner import PcapScanner
from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.match.connection import ConnectionBuilder
from capmaster.plugins.match.extractor import TcpFieldExtractor
from capmaster.plugins.match.matcher import BucketStrategy, ConnectionMatcher, MatchMode
from capmaster.plugins.match.sampler import ConnectionSampler
from capmaster.utils.errors import (
    InsufficientFilesError,
    handle_error,
)

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
        @click.option(
            "-i",
            "--input",
            "input_path",
            type=str,
            required=True,
            help="Input directory, file list, or comma-separated PCAP files",
        )
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
        @click.pass_context
        def match_command(
            ctx: click.Context,
            input_path: str,
            output_file: Path | None,
            mode: str,
            bucket: str,
            threshold: float,
            match_mode: str,
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

              # Match with custom threshold
              capmaster match -i captures/ --threshold 0.70

              # Match header-only connections
              capmaster match -i captures/ --mode header

              # Match with specific bucketing strategy
              capmaster match -i captures/ --bucket server

              # Save results to file
              capmaster match -i captures/ -o matches.txt

            \b
            Bucketing Strategies:
              auto    - Automatically choose best strategy
              server  - Group by server IP
              port    - Group by server port
              none    - No bucketing (compare all pairs)

            \b
            Output:
              Match results are printed to stdout by default, or saved to a file
              if -o is specified. Results include match statistics and details.
            """
            exit_code = self.execute(
                input_path=input_path,
                output_file=output_file,
                mode=mode,
                bucket_strategy=bucket,
                score_threshold=threshold,
            )
            ctx.exit(exit_code)

    def execute(  # type: ignore[override]
        self,
        input_path: str | Path,
        output_file: Path | None = None,
        mode: str = "auto",
        bucket_strategy: str = "auto",
        score_threshold: float = 0.60,
    ) -> int:
        """
        Execute the match plugin.

        Args:
            input_path: Directory, file list, or comma-separated PCAP files
            output_file: Output file for results (None for stdout)
            mode: Matching mode (auto or header)
            bucket_strategy: Bucketing strategy
            score_threshold: Minimum score threshold

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
            ) as progress:
                # Scan for PCAP files
                scan_task = progress.add_task("[cyan]Scanning for PCAP files...", total=1)

                # Parse input path (supports comma-separated file list)
                if isinstance(input_path, str):
                    input_paths = PcapScanner.parse_input(input_path)
                else:
                    input_paths = [str(input_path)]

                logger.info(f"Scanning: {input_path}")
                pcap_files = PcapScanner.scan(input_paths, recursive=False)
                progress.update(scan_task, advance=1)

                if len(pcap_files) < 2:
                    raise InsufficientFilesError(required=2, found=len(pcap_files))

                logger.info(f"Found {len(pcap_files)} PCAP files")

                # For now, match first two files
                # TODO: Support matching multiple files
                file1, file2 = pcap_files[0], pcap_files[1]
                logger.info(f"Matching: {file1.name} <-> {file2.name}")

                # Extract connections from both files
                extract_task = progress.add_task("[cyan]Extracting connections...", total=2)

                progress.update(extract_task, description=f"[cyan]Extracting from {file1.name}...")
                connections1 = self._extract_connections(file1)
                logger.info(f"Found {len(connections1)} connections in {file1.name}")
                progress.update(extract_task, advance=1)

                progress.update(extract_task, description=f"[cyan]Extracting from {file2.name}...")
                connections2 = self._extract_connections(file2)
                logger.info(f"Found {len(connections2)} connections in {file2.name}")
                progress.update(extract_task, advance=1)

                # Apply sampling if needed
                sampler = ConnectionSampler()

                if sampler.should_sample(connections1):
                    sample_task = progress.add_task("[yellow]Sampling connections...", total=1)
                    logger.info("Applying sampling to first file...")
                    connections1 = sampler.sample(connections1)
                    logger.info(f"Sampled to {len(connections1)} connections")
                    progress.update(sample_task, advance=1)

                if sampler.should_sample(connections2):
                    sample_task = progress.add_task("[yellow]Sampling connections...", total=1)
                    logger.info("Applying sampling to second file...")
                    connections2 = sampler.sample(connections2)
                    logger.info(f"Sampled to {len(connections2)} connections")
                    progress.update(sample_task, advance=1)

                # Match connections
                match_task = progress.add_task("[green]Matching connections...", total=1)
                logger.info("Matching connections...")
                bucket_enum = BucketStrategy(bucket_strategy)
                match_mode_enum = MatchMode(match_mode.replace("-", "_").upper())
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

            logger.info("Matching complete")
            return 0

        except Exception as e:
            return handle_error(e, verbose=logger.level <= logging.DEBUG)

    def _extract_connections(self, pcap_file: Path) -> list:
        """
        Extract TCP connections from a PCAP file.

        Args:
            pcap_file: Path to PCAP file

        Returns:
            List of TcpConnection objects
        """
        extractor = TcpFieldExtractor()
        builder = ConnectionBuilder()

        # Extract packets and build connections
        for packet in extractor.extract(pcap_file):
            builder.add_packet(packet)

        # Build connections
        connections = list(builder.build_connections())

        return connections

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
