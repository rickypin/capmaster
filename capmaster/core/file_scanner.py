"""PCAP file scanner for discovering and validating PCAP files."""

from pathlib import Path


class PcapScanner:
    """Scanner for discovering and validating PCAP files."""

    VALID_EXTENSIONS: set[str] = {".pcap", ".pcapng"}

    @classmethod
    def scan(cls, paths: list[str], recursive: bool = False) -> list[Path]:
        """
        Scan and return all valid PCAP files from the given paths.

        Args:
            paths: List of file or directory paths to scan
            recursive: If True, scan directories recursively

        Returns:
            List of valid PCAP file paths, sorted alphabetically

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

        # Remove duplicates and sort
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
            for item in directory.rglob("*"):
                if item.is_file() and cls.is_valid_pcap(item):
                    pcap_files.append(item)
        else:
            # Only scan immediate children
            for item in directory.iterdir():
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
