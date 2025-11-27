"""PCAP file scanner for discovering and validating PCAP files."""

from __future__ import annotations

from pathlib import Path


class PcapScanner:
    """Scanner for discovering and validating PCAP files."""

    VALID_EXTENSIONS: set[str] = {".pcap", ".pcapng"}

    @classmethod
    def parse_input(cls, input_str: str | Path) -> list[str]:
        """
        Parse input string or Path to extract file/directory paths.

        Supports:
        - Single file path: "/path/to/file.pcap" or Path("/path/to/file.pcap")
        - Single directory path: "/path/to/dir" or Path("/path/to/dir")
        - Comma-separated file list: "/path/to/file1.pcap,/path/to/file2.pcap"

        Args:
            input_str: Input string or Path object containing path(s)

        Returns:
            List of path strings
        """
        # Convert Path to string if needed
        if isinstance(input_str, Path):
            input_str = str(input_str)

        # Check if input contains comma (file list)
        if "," in input_str:
            # Split by comma and strip whitespace
            paths = [p.strip() for p in input_str.split(",")]
            # Filter out empty strings
            return [p for p in paths if p]
        else:
            # Single path
            return [input_str.strip()]

    @classmethod
    def scan(cls, paths: list[str], recursive: bool = False, preserve_order: bool = False) -> list[Path]:
        """
        Scan and return all valid PCAP files from the given paths.

        Args:
            paths: List of file or directory paths to scan
            recursive: If True, scan directories recursively
            preserve_order: If True, preserve input order instead of sorting alphabetically

        Returns:
            List of valid PCAP file paths, sorted alphabetically (unless preserve_order=True)

        Raises:
            FileNotFoundError: If a path does not exist
        """
        pcap_files: list[Path] = []

        for path_str in paths:
            path = Path(path_str)

            if not path.exists():
                raise FileNotFoundError(f"Path does not exist: {path}")

            if path.is_file():
                if cls.is_valid_pcap(path):
                    pcap_files.append(path)
            elif path.is_dir():
                pcap_files.extend(cls._scan_directory(path, recursive))

        # Remove duplicates
        if preserve_order:
            # Preserve order while removing duplicates
            seen = set()
            result = []
            for p in pcap_files:
                if p not in seen:
                    seen.add(p)
                    result.append(p)
            return result
        else:
            # Remove duplicates and sort alphabetically
            return sorted(set(pcap_files))

    @classmethod
    def _scan_directory(cls, directory: Path, recursive: bool) -> list[Path]:
        """
        Scan a directory for PCAP files.

        Args:
            directory: Directory path to scan
            recursive: If True, scan recursively

        Returns:
            List of valid PCAP file paths
        """
        pcap_files: list[Path] = []

        if recursive:
            # Recursively scan all subdirectories
            # Sort to ensure deterministic order
            for item in sorted(directory.rglob("*")):
                if item.is_file() and cls.is_valid_pcap(item):
                    pcap_files.append(item)
        else:
            # Only scan immediate children
            # Sort to ensure deterministic order
            for item in sorted(directory.iterdir()):
                if item.is_file() and cls.is_valid_pcap(item):
                    pcap_files.append(item)

        return pcap_files

    @staticmethod
    def is_valid_pcap(path: Path) -> bool:
        """
        Validate if a file is a valid PCAP file.

        Checks:
        1. File extension is .pcap or .pcapng
        2. File size is greater than 0

        Args:
            path: File path to validate

        Returns:
            True if the file is a valid PCAP file, False otherwise
        """
        # Check extension
        if path.suffix.lower() not in PcapScanner.VALID_EXTENSIONS:
            return False

        # Check file size
        try:
            if path.stat().st_size == 0:
                return False
        except OSError:
            return False

        return True
