"""Protocol detection using tshark."""

from __future__ import annotations
import re
from pathlib import Path

from capmaster.core.tshark_wrapper import TsharkWrapper


class ProtocolDetector:
    """Detect protocols present in a PCAP file."""

    def __init__(self, tshark: TsharkWrapper) -> None:
        """
        Initialize ProtocolDetector.

        Args:
            tshark: TsharkWrapper instance for executing tshark commands
        """
        self.tshark = tshark

    def detect(self, pcap_file: Path) -> set[str]:
        """
        Detect protocols in a PCAP file using tshark -z io,phs.

        Args:
            pcap_file: Path to PCAP file

        Returns:
            Set of protocol names (lowercase) found in the file

        Raises:
            TsharkExecutionError: If tshark command fails
        """
        # Execute tshark with protocol hierarchy statistics
        result = self.tshark.execute(
            args=["-q", "-z", "io,phs"],
            input_file=pcap_file,
            timeout=60,
        )

        # Parse output to extract protocols
        protocols = self._parse_protocol_hierarchy(result.stdout)

        return protocols

    def _parse_protocol_hierarchy(self, output: str) -> set[str]:
        """
        Parse tshark protocol hierarchy output.

        The output format is like:
        ===================================================================
        Protocol Hierarchy Statistics
        Filter:

        eth                                      frames:100 bytes:50000
          ip                                     frames:95 bytes:48000
            tcp                                  frames:80 bytes:40000
              http                               frames:20 bytes:10000
            udp                                  frames:15 bytes:8000
              dns                                frames:10 bytes:5000

        Args:
            output: tshark -z io,phs output

        Returns:
            Set of protocol names (lowercase)
        """
        protocols: set[str] = set()

        # Pattern to match protocol lines (protocol name followed by frames/bytes)
        # Example: "  tcp                                  frames:80 bytes:40000"
        pattern = re.compile(r"^\s*([a-zA-Z0-9_\-\.]+)\s+frames:", re.MULTILINE)

        for match in pattern.finditer(output):
            protocol = match.group(1).lower()
            protocols.add(protocol)

        return protocols
