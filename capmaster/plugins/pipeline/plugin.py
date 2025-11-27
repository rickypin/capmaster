"""Pipeline plugin implementation."""

from pathlib import Path

import click

from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.pipeline.runner import PipelineRunner
from capmaster.core.input_manager import InputManager
from capmaster.utils.cli_options import unified_input_options


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
        @unified_input_options
        @click.option(
            "-c",
            "--config",
            "config_path",
            required=True,
            type=click.Path(exists=True, path_type=Path),
            help="Path to the pipeline configuration YAML file.",
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
            input_path: str | None,
            file1: Path | None,
            file2: Path | None,
            file3: Path | None,
            file4: Path | None,
            file5: Path | None,
            file6: Path | None,
            silent_exit: bool,
            output_dir: Path,
            dry_run: bool,
            silent: bool,
        ) -> None:
            """Run a multi-step analysis pipeline."""
            exit_code = self.execute(
                config_path=config_path,
                input_path=input_path,
                file1=file1,
                file2=file2,
                file3=file3,
                file4=file4,
                file5=file5,
                file6=file6,
                silent_exit=silent_exit,
                output_dir=output_dir,
                dry_run=dry_run,
                silent=silent,
            )
            ctx.exit(exit_code)

    def execute(
        self,
        config_path: Path,
        output_dir: Path,
        input_path: str | None = None,
        file1: Path | None = None,
        file2: Path | None = None,
        file3: Path | None = None,
        file4: Path | None = None,
        file5: Path | None = None,
        file6: Path | None = None,
        silent_exit: bool = False,
        dry_run: bool = False,
        silent: bool = False,
        **kwargs,
    ) -> int:
        """Execute the pipeline."""
        # Resolve inputs
        file_args = {
            1: file1, 2: file2, 3: file3, 4: file4, 5: file5, 6: file6
        }
        input_files = InputManager.resolve_inputs(input_path, file_args)
        
        # Validate for PipelinePlugin (needs at least 1 file)
        InputManager.validate_file_count(input_files, min_files=1, silent_exit=silent_exit)

        runner = PipelineRunner(
            config_path=config_path,
            original_input=input_path,
            input_files=input_files,
            output_dir=output_dir,
            dry_run=dry_run,
            silent=silent,
        )
        return runner.run()
