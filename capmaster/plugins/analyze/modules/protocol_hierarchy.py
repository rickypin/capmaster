"""Protocol hierarchy statistics module."""

from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class ProtocolHierarchyModule(AnalysisModule):
    """Generate protocol hierarchy statistics."""

    @property
    def name(self) -> str:
        """Module name."""
        return "protocol_hierarchy"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "protocol-hierarchy.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols (empty = always execute)."""
        return set()

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for protocol hierarchy statistics
        """
        return ["-q", "-z", "io,phs"]
