"""IPv4 hosts statistics module."""

from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class Ipv4HostsModule(AnalysisModule):
    """Generate IPv4 hosts statistics."""

    @property
    def name(self) -> str:
        """Module name."""
        return "ipv4_hosts"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "ipv4-hosts.txt"

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
            List of tshark arguments for IPv4 hosts statistics
        """
        return ["-q", "-z", "endpoints,ip"]
