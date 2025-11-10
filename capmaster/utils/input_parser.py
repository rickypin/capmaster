"""Input parsing utilities for dual file operations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from capmaster.core.file_scanner import PcapScanner
from capmaster.utils.errors import InsufficientFilesError


@dataclass
class DualFileInput:
    """
    Parsed result of dual file input.

    Attributes:
        file1: First PCAP file (baseline file)
        file2: Second PCAP file (compare file)
        pcap_id_mapping: Optional mapping from file path to PCAP ID (0 or 1)
                        Only present when using --file1/--file2 input method
    """

    file1: Path
    file2: Path
    pcap_id_mapping: dict[str, int] | None = None

    @property
    def baseline_file(self) -> Path:
        """Alias for file1 (baseline file)."""
        return self.file1

    @property
    def compare_file(self) -> Path:
        """Alias for file2 (compare file)."""
        return self.file2


class DualFileInputParser:
    """Parser for dual file input parameters."""

    @staticmethod
    def parse(
        input_path: str | None,
        file1: Path | None,
        file2: Path | None,
        file1_pcapid: int | None,
        file2_pcapid: int | None,
    ) -> DualFileInput:
        """
        Parse dual file input parameters into a unified structure.

        Supports two input methods:
        1. Using --file1/--file2 with pcapid mapping
        2. Using -i/--input (directory or comma-separated file list)

        Args:
            input_path: Input path from -i/--input
            file1: First file from --file1
            file2: Second file from --file2
            file1_pcapid: PCAP ID for file1 (0 or 1)
            file2_pcapid: PCAP ID for file2 (0 or 1)

        Returns:
            DualFileInput object containing the two files and optional pcap_id mapping

        Raises:
            InsufficientFilesError: If the number of files found is not exactly 2
        """
        if file1 and file2:
            # Method 1: Using --file1/--file2
            pcap_id_mapping = {
                str(file1): file1_pcapid,
                str(file2): file2_pcapid,
            }
            return DualFileInput(
                file1=file1,
                file2=file2,
                pcap_id_mapping=pcap_id_mapping,
            )
        else:
            # Method 2: Using -i/--input
            input_paths = PcapScanner.parse_input(input_path)
            # Preserve order only for comma-separated file lists
            preserve_order = "," in input_path
            pcap_files = PcapScanner.scan(
                input_paths, recursive=False, preserve_order=preserve_order
            )

            if len(pcap_files) != 2:
                raise InsufficientFilesError(required=2, found=len(pcap_files))

            return DualFileInput(
                file1=pcap_files[0],
                file2=pcap_files[1],
                pcap_id_mapping=None,
            )

