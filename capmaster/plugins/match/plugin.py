"""Match plugin for TCP connection matching."""

from __future__ import annotations

import logging
from pathlib import Path

import click

from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.match.cli_commands import (
    register_comparative_analysis_command,
    register_match_command,
)
from capmaster.plugins.match.comparative_runner import run_comparative_analysis
from capmaster.plugins.match.runner import (
    match_connections_in_memory as run_match_in_memory,
    run_match_pipeline,
    _improve_server_detection as runner_improve_server_detection,
)
from capmaster.plugins.match.stats_pipeline import (
    write_to_database as stats_write_to_database,
    write_to_json as stats_write_to_json,
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
        """Register CLI subcommands for the match plugin.

        This delegates the actual click command definitions to helper
        functions in capmaster.plugins.match.cli_commands to keep this
        file small and focused on orchestration logic.
        """

        register_match_command(self, cli_group)
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
        """Match TCP connections between PCAP files.

        This is a thin wrapper around capmaster.plugins.match.runner.run_match_pipeline.
        See run_match_pipeline for full parameter semantics and behaviour.
        """
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
        # Legacy implementation of execute() moved to runner.run_match_pipeline.

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





    def _improve_server_detection(
        self,
        connections: list,
        detector,
    ) -> list:
        """Improve server/client detection using ServerDetector.

        This thin wrapper delegates to runner_improve_server_detection in
        capmaster.plugins.match.runner to keep the core logic in a dedicated
        module while preserving the legacy private API used by scripts.
        """
        return runner_improve_server_detection(connections, detector)

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
        """Thin wrapper for writing statistics to the database.

        The real implementation lives in capmaster.plugins.match.stats_pipeline.
        This method is kept only to preserve the historical private API used
        by tests and external scripts.
        """
        stats_write_to_database(
            db_connection=db_connection,
            kase_id=kase_id,
            endpoint_stats=endpoint_stats,
            file1=file1,
            file2=file2,
            pcap_id_mapping=pcap_id_mapping,
            service_stats_list=service_stats_list,
            service_group_mapping_file=service_group_mapping_file,
        )

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
        """Thin wrapper for writing statistics to a JSON file.

        The real implementation lives in capmaster.plugins.match.stats_pipeline.
        This method is kept only to preserve the historical private API used
        by tests and external scripts.
        """
        stats_write_to_json(
            output_file=output_file,
            endpoint_stats=endpoint_stats,
            file1=file1,
            file2=file2,
            pcap_id_mapping=pcap_id_mapping,
            service_stats_list=service_stats_list,
            service_group_mapping_file=service_group_mapping_file,
        )

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
        return run_comparative_analysis(
            input_path=input_path,
            file1=file1,
            file2=file2,
            analysis_type=analysis_type,
            topology_file=topology_file,
            matched_connections_file=matched_connections_file,
            top_n=top_n,
            output_file=output_file,
        )
