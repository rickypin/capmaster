"""Common CLI options and decorators for plugins."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import click


def validate_database_params(
    ctx: click.Context,
    db_connection: str | None,
    kase_id: int | None,
    required_flag: str | None,
    required_flag_value: bool = False,
) -> None:
    """
    Validate database connection parameters.

    NOTE: This function can still be called manually, but for simpler validation
    (without required_flag), consider using database parameter options with callbacks.

    Validation rules:
    1. If db_connection is provided, kase_id must also be provided
    2. If kase_id is provided, db_connection must also be provided
    3. If required_flag is specified, it must be True when using database output

    Args:
        ctx: Click context
        db_connection: Database connection string
        kase_id: Case ID for table name
        required_flag: Name of required flag (e.g., "endpoint-stats", "show-flow-hash")
        required_flag_value: Value of the required flag

    Raises:
        click.ClickException: If validation fails

    Examples:
        # Match plugin
        validate_database_params(
            ctx, db_connection, kase_id,
            required_flag="endpoint-stats",
            required_flag_value=endpoint_stats
        )

        # Compare plugin
        validate_database_params(
            ctx, db_connection, kase_id,
            required_flag="show-flow-hash",
            required_flag_value=show_flow_hash
        )
    """
    # Check db_connection and kase_id mutual dependency
    if db_connection and not kase_id:
        ctx.fail("--kase-id is required when --db-connection is provided")
    if kase_id and not db_connection:
        ctx.fail("--db-connection is required when --kase-id is provided")

    # Check required flag if specified
    if db_connection and required_flag and not required_flag_value:
        ctx.fail(f"--{required_flag} is required when using database output")


def unified_input_options(func: Callable) -> Callable:
    """
    Add unified input options to a Click command.

    Adds the following parameters:
    - -i/--input: Directory, file, or comma-separated list
    - --file1 through --file6: Individual file inputs
    - --silent-exit: Exit with code 0 if file count requirements are not met

    These options are designed to be processed by InputManager.resolve_inputs().
    """
    # Add --silent-exit
    # Add --allow-no-input (formerly --silent-exit)
    func = click.option(
        "--allow-no-input",
        is_flag=True,
        default=False,
        help="Exit with code 0 if input file count requirements are not met (formerly --silent-exit)",
    )(func)

    # Add --strict
    func = click.option(
        "--strict",
        is_flag=True,
        default=False,
        help="Fail on warnings (e.g., missing config files, malformed data).",
    )(func)

    # Add -q / --quiet
    func = click.option(
        "-q",
        "--quiet",
        is_flag=True,
        default=False,
        help="Suppress output (only show errors).",
    )(func)

    # Add --file6 down to --file1
    for i in range(6, 0, -1):
        func = click.option(
            f"--file{i}",
            type=click.Path(exists=True, path_type=Path),
            help=f"Input PCAP file {i}",
        )(func)

    # Add -i / --input
    func = click.option(
        "-i",
        "--input",
        "input_path",
        type=str,
        help="Input directory, file, or comma-separated list of files",
    )(func)

    return func

