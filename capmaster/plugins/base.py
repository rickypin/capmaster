"""Base class for all plugins."""

from abc import ABC, abstractmethod

import click


class PluginBase(ABC):
    """Abstract base class for all plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Plugin name (used as CLI subcommand name).

        Returns:
            Plugin name (e.g., "analyze", "match", "filter")
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
    def execute(self, **kwargs: object) -> int:
        """
        Execute plugin logic.

        Args:
            **kwargs: Plugin-specific arguments

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        pass
