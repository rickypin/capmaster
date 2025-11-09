"""UDP conversations statistics module."""

from __future__ import annotations

from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class UdpConversationsModule(AnalysisModule):
    """Generate UDP conversations statistics."""

    @property
    def name(self) -> str:
        """Module name."""
        return "udp_conversations"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "udp-conversations.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"udp"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for UDP conversations
        """
        return ["-q", "-z", "conv,udp"]
