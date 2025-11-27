"""Main CLI entry point for capmaster."""

import sys

import click

from capmaster.plugins import discover_plugins, get_all_plugins
from capmaster.utils.logger import console, console_err, setup_logger

# Version
__version__ = "1.0.0"


_PLUGINS_REGISTERED = False


@click.group()
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

    \b
    Available Commands:
      analyze               Analyze PCAP files and generate statistics
      match                 Match TCP connections between PCAP files
      compare               Compare TCP connections at packet level between PCAP files
      streamdiff           Compare TCP stream packets and report A-only/B-only packets

      comparative-analysis  Perform comparative analysis between two PCAP files
      preprocess            Preprocess PCAP files before further analysis

    \b
    Examples:
      # Analyze a single PCAP file
      capmaster analyze -i capture.pcap

      # Match connections between two PCAP files
      capmaster match -i captures/

      # Compare connections at packet level
      capmaster compare -i captures/

      # Preprocess PCAP files (time-align, deduplicate, one-way analysis)
      capmaster preprocess -i capture.pcap

      # Run with verbose output
      capmaster -v analyze -i capture.pcap

    \b
    For more information on a specific command:
      capmaster <command> --help
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
