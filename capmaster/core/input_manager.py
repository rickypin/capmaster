"""Input file management for capmaster plugins."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import click

from capmaster.core.file_scanner import PcapScanner
from capmaster.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class InputFile:
    """Represents a processed input PCAP file."""
    path: Path
    pcapid: int
    capture_point: str


class InputManager:
    """
    Manages input file resolution, validation, and standardization.
    """
    MAX_FILES = 6

    @classmethod
    def resolve_inputs(
        cls,
        input_path: str | Path | None = None,
        file_args: dict[int, Path | None] | None = None,
    ) -> list[InputFile]:
        """
        Resolve input arguments into a list of InputFile objects.

        Args:
            input_path: Value from -i/--input argument
            file_args: Dictionary mapping file index (1-based) to Path from --fileX arguments

        Returns:
            List of InputFile objects sorted by sequence.
        """
        resolved_paths: list[Path] = []

        # Case 1: -i/--input provided
        if input_path:
            if file_args and any(f is not None for f in file_args.values()):
                raise click.BadParameter("Cannot use both -i/--input and --fileX arguments.")
            
            # Use PcapScanner to parse and scan
            raw_paths = PcapScanner.parse_input(input_path)
            try:
                resolved_paths = PcapScanner.scan(raw_paths, recursive=False, preserve_order=True)
            except FileNotFoundError as e:
                raise click.BadParameter(str(e))

        # Case 2: --fileX arguments provided
        elif file_args:
            # Check for single file constraint: if only 1 file is provided, it must be file1
            active_files = {k: v for k, v in file_args.items() if v is not None}
            if len(active_files) == 1 and 1 not in active_files:
                raise click.BadParameter("When providing only one file via --fileX arguments, you must use --file1.")

            # Extract files in order 1..6
            for i in range(1, cls.MAX_FILES + 1):
                path = file_args.get(i)
                if path:
                    resolved_paths.append(path)
        
        else:
            # No input provided
            return []

        # Validate max files
        if len(resolved_paths) > cls.MAX_FILES:
            raise click.BadParameter(f"Too many input files. Maximum allowed is {cls.MAX_FILES}.")

        # Create InputFile objects
        input_files = []
        for idx, path in enumerate(resolved_paths):
            # Validate extension
            if path.suffix.lower() not in PcapScanner.VALID_EXTENSIONS:
                 raise click.BadParameter(f"Invalid file format: {path.name}. Only .pcap and .pcapng are supported.")
            
            input_files.append(InputFile(
                path=path,
                pcapid=idx,
                capture_point=chr(ord('A') + idx)
            ))

        return input_files

    @classmethod
    def validate_file_count(
        cls, 
        input_files: list[InputFile], 
        min_files: int = 1, 
        max_files: int | None = None,
        silent_exit: bool = False
    ) -> None:
        """
        Validate the number of input files against requirements.

        Args:
            input_files: List of resolved input files
            min_files: Minimum required files
            max_files: Maximum allowed files (None for no limit)
            silent_exit: If True, exit with 0 instead of error on count mismatch
        """
        count = len(input_files)
        error_msg = None

        if count < min_files:
            if count == 0:
                error_msg = "No valid input files found."
            else:
                error_msg = f"Input file count mismatch: Expected at least {min_files}, got {count}."
        elif max_files is not None and count > max_files:
            error_msg = f"Input file count mismatch: Expected at most {max_files}, got {count}."

        if error_msg:
            if silent_exit:
                logger.info(f"{error_msg} Exiting silently as requested.")
                sys.exit(0)
            else:
                raise click.BadParameter(error_msg)

