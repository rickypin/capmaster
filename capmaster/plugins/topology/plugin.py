"""Topology plugin for single-point and dual-point analysis."""

from __future__ import annotations

import logging
from pathlib import Path

import click

from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.topology.runner import run_topology_analysis
from capmaster.core.input_manager import InputManager
from capmaster.utils.cli_options import unified_input_options

logger = logging.getLogger(__name__)


@register_plugin
class TopologyPlugin(PluginBase):
    """Expose topology analysis as a standalone CLI command."""

    @property
    def name(self) -> str:
        """CLI subcommand name."""
        return "topology"

    def setup_cli(self, cli_group: click.Group) -> None:
        """Register the topology CLI."""

        @cli_group.command(name=self.name)
        @unified_input_options
        @click.option(
            "--matched-connections",
            type=click.Path(exists=True, dir_okay=False, path_type=Path),
            help="Matched connections text file produced by 'capmaster match -o ...'. "
            "Required for dual-point analysis.",
        )
        @click.option(
            "--empty-match-behavior",
            type=click.Choice(["error", "fallback-single"], case_sensitive=False),
            default="error",
            show_default=True,
            help=(
                "Behavior when no valid matched connections are found in dual-capture "
                "analysis: 'error' to fail (default), 'fallback-single' to run per-"
                "capture single-point topology analysis instead."
            ),
        )
        @click.option(
            "-o",
            "--output",
            "output_file",
            type=click.Path(path_type=Path),
            help="Output file for the topology report (default: stdout).",
        )
        @click.option(
            "--service-list",
            type=click.Path(exists=True, dir_okay=False, path_type=Path),
            help="Optional service list file (ip:port or ip:*) to aid server detection.",
        )
        @click.option(
            "--silent",
            is_flag=True,
            help="Suppress progress bars and non-error logs.",
        )
        @click.pass_context
        def topology_command(
            ctx: click.Context,
            input_path: str | None,
            file1: Path | None,
            file1_pcapid: int | None,
            file2: Path | None,
            file2_pcapid: int | None,
            file3: Path | None,
            file3_pcapid: int | None,
            file4: Path | None,
            file4_pcapid: int | None,
            file5: Path | None,
            file5_pcapid: int | None,
            file6: Path | None,
            file6_pcapid: int | None,
            silent_exit: bool,
            matched_connections: Path | None,
            empty_match_behavior: str,
            output_file: Path | None,
            service_list: Path | None,
            silent: bool,
        ) -> None:
            """Render network topology for one or two capture points.

            Examples:
              # Single capture
              capmaster topology --single-file cases/sample.pcap

              # Directory containing exactly two captures + matched connections
              capmaster topology -i /path/to/2hops/ --matched-connections tmp/matched_connections.txt

              # Explicit files
              capmaster topology --file1 a.pcap --file2 b.pcap --matched-connections tmp/matched.txt
            """

            exit_code = self.execute(
                input_path=input_path,
                file1=file1,
                file2=file2,
                file3=file3,
                file4=file4,
                file5=file5,
                file6=file6,
                silent_exit=silent_exit,
                matched_connections=matched_connections,
                empty_match_behavior=empty_match_behavior,
                output_file=output_file,
                service_list=service_list,
                silent=silent,
            )
            ctx.exit(exit_code)

    def execute(  # type: ignore[override]
        self,
        input_path: str | None = None,
        file1: Path | None = None,
        file2: Path | None = None,
        file3: Path | None = None,
        file4: Path | None = None,
        file5: Path | None = None,
        file6: Path | None = None,
        silent_exit: bool = False,
        matched_connections: Path | None = None,
        empty_match_behavior: str = "error",
        output_file: Path | None = None,
        service_list: Path | None = None,
        silent: bool = False,
        # Legacy
        single_file: Path | None = None,
    ) -> int:
        """Delegate to the topology runner."""
        # Resolve inputs
        file_args = {
            1: file1, 2: file2, 3: file3, 4: file4, 5: file5, 6: file6
        }
        input_files = InputManager.resolve_inputs(input_path, file_args)
        
        # Validate for TopologyPlugin (needs 1 or 2 files)
        InputManager.validate_file_count(input_files, min_files=1, max_files=2, silent_exit=silent_exit)
        
        # Map to legacy args
        single_file_path = None
        file1_path = None
        file2_path = None
        
        if len(input_files) == 1:
            single_file_path = input_files[0].path
        elif len(input_files) == 2:
            file1_path = input_files[0].path
            file2_path = input_files[1].path

        return run_topology_analysis(
            input_path=None,
            single_file=single_file_path,
            file1=file1_path,
            file2=file2_path,
            matched_connections_file=matched_connections,
            empty_match_behavior=empty_match_behavior,
            output_file=output_file,
            service_list=service_list,
            silent=silent,
        )

    def get_command_map(self) -> dict[str, str]:
        """Return mapping for topology command."""
        return {self.name: "execute"}

