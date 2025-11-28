"""Base class for all plugins."""

from abc import ABC, abstractmethod
from typing import Any

import click


class PluginBase(ABC):
    """Abstract base class for all plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Plugin name (used as CLI subcommand name).

        Returns:
            Plugin name (e.g., "analyze", "match", "preprocess")
        """
        pass

    @abstractmethod
    def setup_cli(self, cli_group: click.Group) -> None:
        """
        Register CLI subcommand for this plugin.

        Args:
            cli_group: Click group to register the subcommand to
        """
        pass

    @abstractmethod
    def execute(self, **kwargs: Any) -> int:
        """
        Execute plugin logic.

        Args:
            **kwargs: Plugin-specific arguments

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        pass

    def get_command_map(self) -> dict[str, str]:
        """
        Return a mapping of CLI command names to method names.

        Returns:
            Dictionary mapping command name to method name.
            Default is {self.name: "execute"}.
        """
        return {self.name: "execute"}

    def resolve_args(self, command: str, kwargs: dict[str, Any]) -> dict[str, Any]:
        """
        Resolve CLI arguments to Python method arguments.

        Args:
            command: The command name being executed
            kwargs: The arguments from the configuration file (CLI style)

        Returns:
            Dictionary of arguments ready to be passed to the method.
            Default behavior converts kebab-case keys to snake_case,
            and maps common CLI aliases (input->input_path, output->output_file).
        """
        args = {k.replace("-", "_"): v for k, v in kwargs.items()}

        # Common mappings
        if "input" in args and "input_path" not in args:
            args["input_path"] = args.pop("input")
        if "output" in args and "output_file" not in args:
            args["output_file"] = args.pop("output")

        return args
