"""TCP conversations statistics module."""

from __future__ import annotations

from pathlib import Path

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class TcpConversationsModule(AnalysisModule):
    """Generate TCP conversations statistics."""

    @property
    def name(self) -> str:
        """Module name."""
        return "tcp_conversations"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "tcp-conversations.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"tcp"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for TCP conversations
        """
        return ["-q", "-z", "conv,tcp"]
