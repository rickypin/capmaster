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

        @cli_group.command(name=self.name, context_settings=dict(help_option_names=["-h", "--help"]))
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
            allow_no_input: bool,
            strict: bool,
            quiet: bool,
            output_dir: Path,
            dry_run: bool,
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
                allow_no_input=allow_no_input,
                strict=strict,
                quiet=quiet,
                output_dir=output_dir,
                dry_run=dry_run,
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
        allow_no_input: bool = False,
        strict: bool = False,
        quiet: bool = False,
        dry_run: bool = False,
        **kwargs,
    ) -> int:
        """Execute the pipeline."""
        # Resolve inputs
        file_args = {
            1: file1, 2: file2, 3: file3, 4: file4, 5: file5, 6: file6
        }
        input_files = InputManager.resolve_inputs(input_path, file_args)
        
        # Validate for PipelinePlugin (needs at least 1 file)
        InputManager.validate_file_count(
            input_files,
            min_files=1,
            allow_no_input=allow_no_input,
        )

        runner = PipelineRunner(
            config_path=config_path,
            original_input=input_path,
            input_files=input_files,
            output_dir=output_dir,
            dry_run=dry_run,
            quiet=quiet,
            allow_no_input=allow_no_input,
            strict=strict,
        )
        return runner.run()
