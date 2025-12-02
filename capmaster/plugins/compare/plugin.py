"""Compare plugin for packet-level TCP connection comparison."""

from __future__ import annotations

from pathlib import Path

import click

from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.compare.cli_commands import register_compare_command
from capmaster.plugins.match.comparative_runner import execute_packet_diff


@register_plugin
class ComparePlugin(PluginBase):
    """
    Compare TCP connections at packet level between PCAP files.

    This plugin first matches TCP connections between two PCAP files and then
    performs detailed packet-level comparison for each matched connection pair.
    The first file (in input order or alphabetically) is treated as baseline
    and differences are reported relative to it.
    """

    @property
    def name(self) -> str:
        """Plugin name (CLI subcommand)."""
        return "compare"

    def setup_cli(self, cli_group: click.Group) -> None:
        """Register CLI subcommand."""
        register_compare_command(self, cli_group)

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
        strict: bool = False,
        quiet: bool = False,
        output_file: Path | None = None,
        score_threshold: float = 0.60,
        bucket_strategy: str = "auto",
        show_flow_hash: bool = False,
        matched_only: bool = False,
        db_connection: str | None = None,
        kase_id: int | None = None,
        match_mode: str = "one-to-one",
        match_file: Path | None = None,
    ) -> int:
        """Execute the packet diff comparison shared with comparative-analysis."""
        return execute_packet_diff(
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
            score_threshold=score_threshold,
            bucket_strategy=bucket_strategy,
            show_flow_hash=show_flow_hash,
            matched_only=matched_only,
            db_connection=db_connection,
            kase_id=kase_id,
            match_mode=match_mode,
            match_file=match_file,
        )
