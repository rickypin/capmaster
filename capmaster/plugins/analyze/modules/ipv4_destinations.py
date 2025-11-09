"""IPv4 destinations and ports statistics module."""

from __future__ import annotations

from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class Ipv4DestinationsModule(AnalysisModule):
    """Generate IPv4 destinations and ports statistics.
    
    Matches original script:
    tshark -r {INPUT} -q -z dests,tree
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "ipv4_destinations"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "ipv4-destinations-and-ports.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"ip"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for IPv4 destinations and ports
        """
        return ["-q", "-z", "dests,tree"]

