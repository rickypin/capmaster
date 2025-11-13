"""Common CLI options and decorators for plugins."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import click


def _validate_dual_file_input_callback(
    ctx: click.Context,
    param: click.Parameter,
    value: Any,
) -> Any:
    """
    Click callback to validate dual file input parameters.

    This callback is triggered when the last parameter (file2_pcapid) is set,
    ensuring all dual file input parameters are validated together.
    """
    # Only validate when we have the context with all parameters
    if ctx.params is None:
        return value

    # Get all relevant parameters from context
    input_path = ctx.params.get("input_path")
    file1 = ctx.params.get("file1")
    file2 = ctx.params.get("file2")
    file1_pcapid = ctx.params.get("file1_pcapid")
    file2_pcapid = value  # This is the current parameter being set

    # If using -i/--input, skip dual file validation
    if input_path:
        # Check mutual exclusivity
        if file1 or file2:
            raise click.BadParameter(
                "Cannot use both -i/--input and --file1/--file2 at the same time",
                ctx=ctx,
                param=param,
            )
        # Input path is provided, no need to validate dual file parameters
        return value

    # Validate file1/file2 parameters completeness
    if file1 or file2 or file1_pcapid is not None or file2_pcapid is not None:
        if not (file1 and file2):
            raise click.BadParameter(
                "Both --file1 and --file2 must be provided together",
                ctx=ctx,
                param=param,
            )
        if file1_pcapid is None or file2_pcapid is None:
            raise click.BadParameter(
                "Both --file1-pcapid and --file2-pcapid must be provided when using --file1/--file2",
                ctx=ctx,
                param=param,
            )
        if file1_pcapid not in (0, 1):
            raise click.BadParameter(
                "--file1-pcapid must be 0 or 1",
                ctx=ctx,
                param=param,
            )
        if file2_pcapid not in (0, 1):
            raise click.BadParameter(
                "--file2-pcapid must be 0 or 1",
                ctx=ctx,
                param=param,
            )
    else:
        # Neither input_path nor dual file parameters provided
        raise click.BadParameter(
            "Must provide either -i/--input or both --file1 and --file2",
            ctx=ctx,
            param=param,
        )

    return value


def dual_file_input_options(func: Callable) -> Callable:
    """
    Add dual file input options to a Click command with automatic validation.

    Supports two input methods:
    1. -i/--input: Traditional method (directory or comma-separated file list)
    2. --file1/--file2 with --file1-pcapid/--file2-pcapid: Explicit file specification

    Automatically adds the following parameters to the command:
    - input_path: str | None
    - file1: Path | None
    - file1_pcapid: int | None
    - file2: Path | None
    - file2_pcapid: int | None

    The validation is performed automatically via Click callbacks, so you no longer
    need to call validate_dual_file_input() manually in your command.

    Usage:
        @cli_group.command()
        @dual_file_input_options
        @click.option(...)  # other options
        @click.pass_context
        def my_command(ctx, input_path, file1, file1_pcapid, file2, file2_pcapid, ...):
            # Validation is automatic - no need to call validate_dual_file_input()
            # ... rest of command logic
    """
    # Add options in reverse order (decorators are applied bottom-up)
    # Add callback to the last parameter to trigger validation when all params are set
    func = click.option(
        "--file2-pcapid",
        type=int,
        help="PCAP ID for file2 (0 or 1)",
        callback=_validate_dual_file_input_callback,
    )(func)

    func = click.option(
        "--file2",
        type=click.Path(exists=True, path_type=Path),
        help="Second PCAP file",
    )(func)

    func = click.option(
        "--file1-pcapid",
        type=int,
        help="PCAP ID for file1 (0 or 1)",
    )(func)

    func = click.option(
        "--file1",
        type=click.Path(exists=True, path_type=Path),
        help="First PCAP file (baseline file)",
    )(func)

    func = click.option(
        "-i",
        "--input",
        "input_path",
        type=str,
        help="Input directory or comma-separated list of exactly 2 PCAP files",
    )(func)

    return func


def validate_dual_file_input(
    ctx: click.Context,
    input_path: str | None,
    file1: Path | None,
    file2: Path | None,
    file1_pcapid: int | None,
    file2_pcapid: int | None,
) -> None:
    """
    Validate dual file input parameters.

    DEPRECATED: This function is no longer needed when using @dual_file_input_options
    decorator, as validation is now performed automatically via Click callbacks.

    This function is kept for backward compatibility only.

    Validation rules:
    1. Cannot use both -i and --file1/--file2 at the same time
    2. Must provide either -i or both --file1 and --file2
    3. When using --file1/--file2, both must be provided
    4. When using --file1/--file2, both pcapid values must be provided
    5. pcapid values must be 0 or 1

    Args:
        ctx: Click context
        input_path: Input path from -i/--input
        file1: First file from --file1
        file2: Second file from --file2
        file1_pcapid: PCAP ID for file1
        file2_pcapid: PCAP ID for file2

    Raises:
        click.ClickException: If validation fails
    """
    # This function body is now a no-op since validation happens in the callback
    # Kept for backward compatibility
    pass


def validate_database_params(
    ctx: click.Context,
    db_connection: str | None,
    kase_id: int | None,
    required_flag: str | None = None,
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

