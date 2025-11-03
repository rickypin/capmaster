"""DNS statistics module."""

from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class DnsStatsModule(AnalysisModule):
    """Generate DNS statistics."""

    @property
    def name(self) -> str:
        """Module name."""
        return "dns_stats"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "dns-stats.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"dns"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for DNS statistics
        """
        return ["-q", "-z", "dns,tree"]
