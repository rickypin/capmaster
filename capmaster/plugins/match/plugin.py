"""Match plugin for TCP connection matching."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import click

from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.core.input_manager import InputManager
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
        input_path: str | None = None,
        file1: Path | None = None,
        file2: Path | None = None,
        file3: Path | None = None,
        file4: Path | None = None,
        file5: Path | None = None,
        file6: Path | None = None,

        allow_no_input: bool = False,
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
        service_list: Path | None = None,

        silent: bool = False,
        strict: bool = False,
        quiet: bool = False,
    ) -> int:
        """Match TCP connections between PCAP files.

        This is a thin wrapper around capmaster.plugins.match.runner.run_match_pipeline.
        See run_match_pipeline for full parameter semantics and behaviour.
        """
        # Resolve inputs
        file_args = {
            1: file1, 2: file2, 3: file3, 4: file4, 5: file5, 6: file6
        }
        input_files = InputManager.resolve_inputs(input_path, file_args)
        
        # Validate for MatchPlugin (needs exactly 2 files)
        InputManager.validate_file_count(input_files, min_files=2, max_files=2, allow_no_input=allow_no_input)
        
        # Extract files
        f1 = input_files[0]
        f2 = input_files[1]

        return run_match_pipeline(
            input_path=None,
            file1=f1.path,
            file1_pcapid=f1.pcapid,
            file2=f2.path,
            file2_pcapid=f2.pcapid,
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
            service_list=service_list,
            silent=silent,
            strict=strict,
            allow_no_input=allow_no_input,
            quiet=quiet,
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



    def execute_comparative_analysis(
        self,
        input_path: str | None = None,
        file1: Path | None = None,
        file2: Path | None = None,
        file3: Path | None = None,
        file4: Path | None = None,
        file5: Path | None = None,
        file6: Path | None = None,
        silent_exit: bool = False,
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
            file3-file6: Additional files (ignored for this command)
            silent_exit: Exit silently if file count mismatch
            analysis_type: Type of analysis ("service", "connections", or "both")
            topology_file: Path to topology file (required for service analysis)
            matched_connections_file: Path to matched connections file
            top_n: Number of top worst connections to show
            output_file: Path to output file

        Returns:
            Exit code (0 for success)
        """
        # Resolve inputs
        file_args = {
            1: file1, 2: file2, 3: file3, 4: file4, 5: file5, 6: file6
        }
        input_files = InputManager.resolve_inputs(input_path, file_args)
        
        # Validate for Comparative Analysis (needs exactly 2 files)
        InputManager.validate_file_count(input_files, min_files=2, max_files=2, silent_exit=silent_exit)
        
        # Extract files
        f1 = input_files[0]
        f2 = input_files[1]

        return run_comparative_analysis(
            input_path=None,
            file1=f1.path,
            file2=f2.path,
            analysis_type=analysis_type,
            topology_file=topology_file,
            matched_connections_file=matched_connections_file,
            top_n=top_n,
            output_file=output_file,
        )

    def get_command_map(self) -> dict[str, str]:
        """Return mapping for match and comparative-analysis commands."""
        return {
            "match": "execute",
            "comparative-analysis": "execute_comparative_analysis",
        }

    def resolve_args(self, command: str, kwargs: dict[str, Any]) -> dict[str, Any]:
        """Resolve arguments for match plugin commands."""
        # 1. Default resolution (kebab-case -> snake_case)
        args = super().resolve_args(command, kwargs)

        # Map threshold -> score_threshold
        if "threshold" in args and "score_threshold" not in args:
            args["score_threshold"] = args.pop("threshold")

        if command == "comparative-analysis":
            # 2. Handle special logic for analysis_type
            service = args.pop("service", False)
            matched = args.get("matched_connections_file") or args.get(
                "matched_connections"
            )

            # Ensure matched_connections_file is set if matched_connections was used
            if "matched_connections" in args:
                args["matched_connections_file"] = args.pop("matched_connections")

            if service and matched:
                args["analysis_type"] = "both"
            elif service:
                args["analysis_type"] = "service"
            elif matched:
                args["analysis_type"] = "connections"

            # Map topology -> topology_file
            if "topology" in args and "topology_file" not in args:
                args["topology_file"] = args.pop("topology")

        return args

