"""Main CLI entry point for capmaster."""

import sys

import click

from capmaster.plugins import discover_plugins, get_all_plugins
from capmaster.utils.logger import console, console_err, setup_logger

# Version
__version__ = "1.0.0"


_PLUGINS_REGISTERED = False


class CapMasterGroup(click.Group):
    """Custom Click Group to enforce specific help output order and formatting."""

    def format_help(self, ctx, formatter):
        # 1. Description (Top, Left Aligned)
        if self.help:
            formatter.write(self.help + "\n\n")

        # 2. Usage
        self.format_usage(ctx, formatter)

        # 3. Options and Commands
        self.format_options(ctx, formatter)

        # 4. Epilog (Examples), left-aligned
        if self.epilog:
            formatter.write("\n")
            formatter.write(self.epilog + "\n")


@click.group(
    cls=CapMasterGroup,
    context_settings=dict(help_option_names=["-h", "--help"]),
    epilog="""Examples:

  1. Preprocess PCAP files (time-align, deduplicate)
     capmaster preprocess -i capture.pcap

  2. Analyze PCAP files to get statistics
     capmaster analyze -i capture.pcap

  3. Match TCP connections between two PCAP files
     capmaster match -i captures/

  4. Compare connections at packet level
     capmaster compare -i captures/

  5. Render network topology
     capmaster topology --single-file capture.pcap

  For more information on a specific command:
    capmaster <command> --help
""",
)
@click.version_option(version=__version__, prog_name="capmaster")
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Increase verbosity (-v for INFO, -vv for DEBUG)",
)
@click.pass_context
def cli(ctx: click.Context, verbose: int) -> None:
    """
    CapMaster - Unified PCAP Analysis Tool.

    A Python CLI tool for PCAP analysis, preprocessing, TCP connection matching, and comparison.
    """
    # Ensure context object exists
    ctx.ensure_object(dict)

    # Store verbosity in context
    ctx.obj["verbose"] = verbose

    # Setup logger
    logger = setup_logger("capmaster", verbose)
    ctx.obj["logger"] = logger


def register_cli_plugins() -> None:
    """Discover plugins and register their CLI commands once."""
    global _PLUGINS_REGISTERED
    if _PLUGINS_REGISTERED:
        return

    discover_plugins()
    for plugin_class in get_all_plugins():
        plugin = plugin_class()
        plugin.setup_cli(cli)

    _PLUGINS_REGISTERED = True


# Ensure commands are available upon import for test invocation.
register_cli_plugins()


def main() -> None:
    """Main entry point for the CLI."""
    try:
        register_cli_plugins()

        # Run CLI
        cli(obj={})
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except click.ClickException:
        # Let Click handle its own exceptions (e.g., missing arguments, invalid options)
        raise
    except Exception as e:
        # Unexpected errors during plugin discovery or CLI setup
        console_err.print(f"[red]Fatal error during initialization: {e}[/red]")
        console_err.print("[dim]This is likely a bug. Please report it.[/dim]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
