"""Pipeline plugin implementation."""

from pathlib import Path

import click

from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.pipeline.runner import PipelineRunner


@register_plugin
class PipelinePlugin(PluginBase):
    """Plugin for running analysis pipelines defined in YAML."""

    @property
    def name(self) -> str:
        """CLI subcommand name."""
        return "run-pipeline"

    def setup_cli(self, cli_group: click.Group) -> None:
        """Register the run-pipeline command."""

        @cli_group.command(name=self.name)
        @click.option(
            "-c",
            "--config",
            "config_path",
            required=True,
            type=click.Path(exists=True, path_type=Path),
            help="Path to the pipeline configuration YAML file.",
        )
        @click.option(
            "-i",
            "--input",
            "input_path",
            required=True,
            help="Input PCAP file or directory.",
        )
        @click.option(
            "-o",
            "--output",
            "output_dir",
            required=True,
            type=click.Path(path_type=Path),
            help="Output directory for pipeline results.",
        )
        @click.option(
            "--dry-run",
            is_flag=True,
            default=False,
            help="Simulate pipeline execution without running commands.",
        )
        @click.option(
            "--silent",
            is_flag=True,
            default=False,
            help="Run in silent mode (suppress output).",
        )
        @click.pass_context
        def command(
            ctx: click.Context,
            config_path: Path,
            input_path: str,
            output_dir: Path,
            dry_run: bool,
            silent: bool,
        ) -> None:
            """Run a multi-step analysis pipeline."""
            exit_code = self.execute(
                config_path=config_path,
                input_path=input_path,
                output_dir=output_dir,
                dry_run=dry_run,
                silent=silent,
            )
            ctx.exit(exit_code)

    def execute(
        self,
        config_path: Path,
        input_path: str,
        output_dir: Path,
        dry_run: bool = False,
        silent: bool = False,
        **kwargs,
    ) -> int:
        """Execute the pipeline."""
        # Note: We do not modify global logger level here to avoid side effects.
        # The silent flag is passed to the runner and individual plugins.

        runner = PipelineRunner(
            config_path=config_path,
            input_path=input_path,
            output_dir=output_dir,
            dry_run=dry_run,
            silent=silent,
        )
        return runner.run()
