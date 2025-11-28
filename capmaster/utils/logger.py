"""Logging utilities using rich for beautiful terminal output."""

import logging

from rich.console import Console
from rich.logging import RichHandler

# Global console instances
console = Console()
console_err = Console(stderr=True, style="red")


def setup_logger(name: str, verbosity: int = 0, log_file: str | None = None) -> logging.Logger:
    """
    Set up a logger with rich formatting and optional file rotation.

    Args:
        name: Logger name
        verbosity: Verbosity level (0=WARNING, 1=INFO, 2=DEBUG)
        log_file: Optional path to log file. If provided, enables file logging with rotation.

    Returns:
        Configured logger instance
    """
    # Map verbosity to log level
    level_map = {
        0: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG,
    }
    level = level_map.get(verbosity, logging.DEBUG)

    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Remove existing handlers
    logger.handlers.clear()

    # Add rich handler
    handler = RichHandler(
        console=console,
        show_time=False,
        show_path=False,
        markup=True,
    )
    handler.setLevel(level)

    # Set format
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    # Add file handler if log_file is provided
    if log_file:
        from logging.handlers import RotatingFileHandler
        from pathlib import Path

        # Ensure directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.

    This function returns a logger without automatically adding handlers.
    Handlers should be configured once at application startup using setup_logger().

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def print_success(message: str) -> None:
    """Print success message in green."""
    console.print(f"[green]✓[/green] {message}")


def print_error(message: str) -> None:
    """Print error message in red."""
    console_err.print(f"[red]✗[/red] {message}")


def print_warning(message: str) -> None:
    """Print warning message in yellow."""
    console.print(f"[yellow]⚠[/yellow] {message}")


def print_info(message: str) -> None:
    """Print info message."""
    console.print(f"[blue]ℹ[/blue] {message}")


def print_header(message: str) -> None:
    """Print header message in bold."""
    console.print(f"\n[bold]{message}[/bold]")
