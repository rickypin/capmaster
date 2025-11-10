"""Common CLI options and decorators for plugins."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import click


def dual_file_input_options(func: Callable) -> Callable:
    """
    Add dual file input options to a Click command.

    Supports two input methods:
    1. -i/--input: Traditional method (directory or comma-separated file list)
    2. --file1/--file2 with --file1-pcapid/--file2-pcapid: Explicit file specification

    Automatically adds the following parameters to the command:
    - input_path: str | None
    - file1: Path | None
    - file1_pcapid: int | None
    - file2: Path | None
    - file2_pcapid: int | None

    Usage:
        @cli_group.command()
        @dual_file_input_options
        @click.option(...)  # other options
        @click.pass_context
        def my_command(ctx, input_path, file1, file1_pcapid, file2, file2_pcapid, ...):
            validate_dual_file_input(ctx, input_path, file1, file2, file1_pcapid, file2_pcapid)
            # ... rest of command logic
    """
    # Add options in reverse order (decorators are applied bottom-up)
    func = click.option(
        "--file2-pcapid",
        type=int,
        help="PCAP ID for file2 (0 or 1)",
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
    # Check mutual exclusivity
    if input_path and (file1 or file2):
        ctx.fail("Cannot use both -i/--input and --file1/--file2 at the same time")

    # Check that at least one input method is provided
    if not input_path and not (file1 and file2):
        ctx.fail("Must provide either -i/--input or both --file1 and --file2")

    # Validate file1/file2 parameters completeness
    if file1 or file2 or file1_pcapid is not None or file2_pcapid is not None:
        if not (file1 and file2):
            ctx.fail("Both --file1 and --file2 must be provided together")
        if file1_pcapid is None or file2_pcapid is None:
            ctx.fail(
                "Both --file1-pcapid and --file2-pcapid must be provided when using --file1/--file2"
            )
        if file1_pcapid not in (0, 1):
            ctx.fail("--file1-pcapid must be 0 or 1")
        if file2_pcapid not in (0, 1):
            ctx.fail("--file2-pcapid must be 0 or 1")

