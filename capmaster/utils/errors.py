"""Error handling utilities for better user experience."""

from __future__ import annotations

from pathlib import Path

from capmaster.utils.logger import console_err


class CapMasterError(Exception):
    """Base exception for CapMaster errors."""

    def __init__(self, message: str, suggestion: str | None = None):
        """
        Initialize error with message and optional suggestion.

        Args:
            message: Error message
            suggestion: Optional suggestion for fixing the error
        """
        self.message = message
        self.suggestion = suggestion
        super().__init__(message)

    def display(self) -> None:
        """Display error message with suggestion."""
        console_err.print(f"[bold red]Error:[/bold red] {self.message}")
        if self.suggestion:
            console_err.print(f"[yellow]Suggestion:[/yellow] {self.suggestion}")


class PcapFileNotFoundError(CapMasterError):
    """Error when a required PCAP file is not found."""

    def __init__(self, file_path: Path):
        """
        Initialize PCAP file not found error.

        Args:
            file_path: Path to the missing file
        """
        message = f"File not found: {file_path}"
        suggestion = "Please check that the file exists and the path is correct."
        super().__init__(message, suggestion)


class InvalidFileError(CapMasterError):
    """Error when a file is invalid or corrupted."""

    def __init__(self, file_path: Path, reason: str):
        """
        Initialize invalid file error.

        Args:
            file_path: Path to the invalid file
            reason: Reason why the file is invalid
        """
        message = f"Invalid file: {file_path} - {reason}"
        suggestion = "Please ensure the file is a valid PCAP/PCAPNG file."
        super().__init__(message, suggestion)


class NoPcapFilesError(CapMasterError):
    """Error when no PCAP files are found."""

    def __init__(self, search_path: Path):
        """
        Initialize no PCAP files error.

        Args:
            search_path: Path where PCAP files were searched
        """
        message = f"No PCAP files found in: {search_path}"
        suggestion = (
            "Please ensure the directory contains .pcap or .pcapng files. "
            "Use -r flag to search recursively."
        )
        super().__init__(message, suggestion)


class InsufficientFilesError(CapMasterError):
    """Error when insufficient files are provided."""

    def __init__(self, required: int, found: int):
        """
        Initialize insufficient files error.

        Args:
            required: Number of files required
            found: Number of files found
        """
        message = f"Need at least {required} PCAP files, found {found}"
        suggestion = "Please provide a directory containing at least 2 PCAP files for matching."
        super().__init__(message, suggestion)


class TsharkNotFoundError(CapMasterError):
    """Error when tshark is not found."""

    def __init__(self) -> None:
        """Initialize tshark not found error."""
        message = "tshark command not found"
        suggestion = (
            "Please install Wireshark/tshark:\n"
            "  macOS:  brew install wireshark\n"
            "  Ubuntu: sudo apt install tshark\n"
            "  Verify: which tshark"
        )
        super().__init__(message, suggestion)


class TsharkExecutionError(CapMasterError):
    """Error when tshark execution fails."""

    def __init__(self, command: str, return_code: int, stderr: str):
        """
        Initialize tshark execution error.

        Args:
            command: The tshark command that failed
            return_code: Exit code from tshark
            stderr: Error output from tshark
        """
        message = f"tshark command failed with exit code {return_code}"
        suggestion = (
            f"Command: {command}\n"
            f"Error output: {stderr[:200]}\n"
            "Please check that the PCAP file is not corrupted and tshark is properly installed."
        )
        super().__init__(message, suggestion)


class OutputDirectoryError(CapMasterError):
    """Error when output directory cannot be created or written to."""

    def __init__(self, directory: Path, reason: str):
        """
        Initialize output directory error.

        Args:
            directory: Path to the output directory
            reason: Reason for the error
        """
        message = f"Cannot use output directory: {directory} - {reason}"
        suggestion = "Please check directory permissions or specify a different output directory."
        super().__init__(message, suggestion)


class NoProtocolsDetectedError(CapMasterError):
    """Error when no protocols are detected in PCAP file."""

    def __init__(self, file_path: Path):
        """
        Initialize no protocols detected error.

        Args:
            file_path: Path to the PCAP file
        """
        message = f"No protocols detected in: {file_path}"
        suggestion = "The PCAP file may be empty or corrupted. Please verify the file contents."
        super().__init__(message, suggestion)


class ConfigurationError(CapMasterError):
    """Error when configuration is invalid."""

    def __init__(self, config_file: Path, reason: str):
        """
        Initialize configuration error.

        Args:
            config_file: Path to the configuration file
            reason: Reason for the error
        """
        message = f"Invalid configuration in {config_file}: {reason}"
        suggestion = "Please check the configuration file format and contents."
        super().__init__(message, suggestion)


def handle_error(error: Exception, *, show_traceback: bool = False) -> int:
    """
    Handle an error and return appropriate exit code.

    Args:
        error: The exception to handle
        show_traceback: Whether to show full traceback (keyword-only)

    Returns:
        Exit code (non-zero)
    """
    if isinstance(error, CapMasterError):
        error.display()
        if show_traceback:
            import traceback

            console_err.print("\n[dim]Traceback:[/dim]")
            traceback.print_exc()
        return 1
    else:
        console_err.print(f"[bold red]Unexpected error:[/bold red] {error}")
        if show_traceback:
            import traceback

            console_err.print("\n[dim]Traceback:[/dim]")
            traceback.print_exc()
        else:
            console_err.print("[dim]Run with -vv for more details[/dim]")
        return 1


class StrictModeError(CapMasterError):
    """Error raised when a warning occurs in strict mode."""

    def __init__(self, message: str):
        """
        Initialize strict mode error.

        Args:
            message: The warning message that triggered the error
        """
        super().__init__(
            message=f"Strict mode violation: {message}",
            suggestion="Fix the warning or run without --strict to ignore."
        )


