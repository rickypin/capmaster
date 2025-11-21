"""Topology plugin for single-point and dual-point analysis."""

from __future__ import annotations

import logging
from pathlib import Path

import click

from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.topology.runner import run_topology_analysis

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
        @click.option(
            "-i",
            "--input",
            "input_path",
            type=str,
            help="Directory or comma-separated list containing 1 or 2 PCAP files.",
        )
        @click.option(
            "--single-file",
            type=click.Path(exists=True, dir_okay=False, path_type=Path),
            help="Single PCAP file for single-point topology analysis.",
        )
        @click.option(
            "--file1",
            type=click.Path(exists=True, dir_okay=False, path_type=Path),
            help="First PCAP file (Capture Point A) for dual-point analysis.",
        )
        @click.option(
            "--file2",
            type=click.Path(exists=True, dir_okay=False, path_type=Path),
            help="Second PCAP file (Capture Point B) for dual-point analysis.",
        )
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
        @click.pass_context
        def topology_command(
            ctx: click.Context,
            input_path: str | None,
            single_file: Path | None,
            file1: Path | None,
            file2: Path | None,
            matched_connections: Path | None,
            empty_match_behavior: str,
            output_file: Path | None,
            service_list: Path | None,
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
                single_file=single_file,
                file1=file1,
                file2=file2,
                matched_connections=matched_connections,
                empty_match_behavior=empty_match_behavior,
                output_file=output_file,
                service_list=service_list,
            )
            ctx.exit(exit_code)

    def execute(  # type: ignore[override]
        self,
        input_path: str | Path | None = None,
        single_file: Path | None = None,
        file1: Path | None = None,
        file2: Path | None = None,
        matched_connections: Path | None = None,
        empty_match_behavior: str = "error",
        output_file: Path | None = None,
        service_list: Path | None = None,
    ) -> int:
        """Delegate to the topology runner."""
        return run_topology_analysis(
            input_path=input_path,
            single_file=single_file,
            file1=file1,
            file2=file2,
            matched_connections_file=matched_connections,
            empty_match_behavior=empty_match_behavior,
            output_file=output_file,
            service_list=service_list,
        )

