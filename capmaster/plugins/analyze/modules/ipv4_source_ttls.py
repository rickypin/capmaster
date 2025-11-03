"""IPv4 source TTLs statistics module."""

from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class Ipv4SourceTtlsModule(AnalysisModule):
    """Generate IPv4 source TTLs statistics.
    
    Matches original script:
    tshark -r {INPUT} -q -z ip_ttl,tree
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "ipv4_source_ttls"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "ipv4-source-ttls.txt"

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
            List of tshark arguments for IPv4 source TTLs
        """
        return ["-q", "-z", "ip_ttl,tree"]

