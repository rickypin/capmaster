"""DNS query/response statistics module."""

from __future__ import annotations

from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class DnsQrStatsModule(AnalysisModule):
    """Generate DNS query/response statistics.
    
    Matches original script:
    tshark -r {INPUT} -q -z dns_qr,tree
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "dns_qr_stats"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "dns-query-response.txt"

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
            List of tshark arguments for DNS query/response statistics
        """
        return ["-q", "-z", "dns_qr,tree"]

