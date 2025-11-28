"""Execution context for managing global state like strict mode."""

from __future__ import annotations

import logging
from typing import Any

from capmaster.utils.errors import StrictModeError


class ExecutionContext:
    """Singleton-like context for execution state."""

    _strict_mode: bool = False
    _quiet_mode: bool = False

    @classmethod
    def set_strict(cls, strict: bool) -> None:
        """Set strict mode."""
        cls._strict_mode = strict

    @classmethod
    def is_strict(cls) -> bool:
        """Check if strict mode is enabled."""
        return cls._strict_mode

    @classmethod
    def set_quiet(cls, quiet: bool) -> None:
        """Set quiet mode."""
        cls._quiet_mode = quiet

    @classmethod
    def is_quiet(cls) -> bool:
        """Check if quiet mode is enabled."""
        return cls._quiet_mode

    @classmethod
    def warn_or_error(cls, logger: logging.Logger, message: str, *args: Any, **kwargs: Any) -> None:
        """
        Log warning or raise error based on strict mode.
        
        Args:
            logger: The logger instance to use
            message: The warning message
            *args: Positional arguments for logger
            **kwargs: Keyword arguments for logger
        
        Raises:
            StrictModeError: If strict mode is enabled
        """
        if cls._strict_mode:
            # In strict mode, log as error and raise exception
            logger.error(f"[STRICT] {message}", *args, **kwargs)
            raise StrictModeError(message % args if args else message)
        else:
            # In normal mode, just log warning
            logger.warning(message, *args, **kwargs)
