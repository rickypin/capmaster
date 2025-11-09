"""Base class for analysis modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class AnalysisModule(ABC):
    """Abstract base class for all analysis modules."""

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Module name.

        Returns:
            Module name (e.g., "protocol_hierarchy", "tcp_conversations")
        """
        pass

    @property
    @abstractmethod
    def output_suffix(self) -> str:
        """
        Output file suffix.

        Returns:
            Output file suffix (e.g., "protocol-hierarchy.txt")
        """
        pass

    @property
    def required_protocols(self) -> set[str]:
        """
        Required protocols for this module to execute.

        Returns:
            Set of protocol names (lowercase). Empty set means always execute.
        """
        return set()

    @abstractmethod
    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments for this module.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark command arguments
        """
        pass

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process tshark output before writing to file.

        This method can be overridden by subclasses to transform the raw
        tshark output using Python data structures and algorithms.

        Common transformations:
        - Counting and aggregating (Counter, defaultdict)
        - Sorting and ranking (sorted(), custom key functions)
        - Filtering and categorizing (regex, conditionals)
        - Statistical analysis (collections, itertools)
        - Format conversion (txt to markdown)

        Args:
            tshark_output: Raw stdout from tshark command
            output_format: Output format ("txt" or "md", default: "txt")

        Returns:
            Processed output string to write to file
        """
        # Default: no post-processing, just return as-is
        # Subclasses can override to provide format-specific processing
        return tshark_output

    def should_execute(self, detected_protocols: set[str]) -> bool:
        """
        Determine if this module should execute based on detected protocols.

        Args:
            detected_protocols: Set of protocols detected in the PCAP file

        Returns:
            True if module should execute, False otherwise
        """
        if not self.required_protocols:
            # No protocol requirements, always execute
            return True
        # Execute if any required protocol is present
        return bool(self.required_protocols & detected_protocols)
