"""Output directory and file management."""

from pathlib import Path


class OutputManager:
    """Manage output directories and file paths."""

    DEFAULT_OUTPUT_DIR_NAME = "statistics"

    @staticmethod
    def create_output_dir(input_file: Path, custom_output: Path | None = None) -> Path:
        """
        Create output directory for analysis results.

        Default behavior: Create 'statistics' directory in the same location as input file.
        Custom behavior: Use the provided custom_output path.

        Args:
            input_file: Input PCAP file path
            custom_output: Optional custom output directory path

        Returns:
            Path to the created output directory

        Raises:
            OSError: If directory creation fails
        """
        if custom_output is not None:
            output_dir = custom_output
        else:
            # Create statistics directory next to input file
            if input_file.is_file():
                output_dir = input_file.parent / OutputManager.DEFAULT_OUTPUT_DIR_NAME
            else:
                # If input is a directory, create statistics inside it
                output_dir = input_file / OutputManager.DEFAULT_OUTPUT_DIR_NAME

        # Create directory if it doesn't exist
        output_dir.mkdir(parents=True, exist_ok=True)

        return output_dir

    @staticmethod
    def get_output_path(
        output_dir: Path,
        base_name: str,
        sequence: int,
        suffix: str,
        output_format: str = "txt"
    ) -> Path:
        """
        Generate output file path with naming convention.

        Format: {base_name}-{sequence}-{suffix}
        The file extension in suffix will be replaced with the specified format.

        Args:
            output_dir: Output directory path
            base_name: Base name from input file (without extension)
            sequence: Sequence number for multiple files
            suffix: Output file suffix (e.g., "tcp-conversations.txt")
            output_format: Output format ("txt" or "md", default: "txt")

        Returns:
            Full path to output file

        Examples:
            >>> get_output_path(Path("/out"), "test", 1, "tcp-stats.txt")
            Path("/out/test-1-tcp-stats.txt")
            >>> get_output_path(Path("/out"), "test", 1, "tcp-stats.txt", "md")
            Path("/out/test-1-tcp-stats.md")
        """
        # Replace the extension in suffix with the specified format
        suffix_parts = suffix.rsplit(".", 1)
        if len(suffix_parts) == 2:
            # Has extension, replace it
            new_suffix = f"{suffix_parts[0]}.{output_format}"
        else:
            # No extension, add it
            new_suffix = f"{suffix}.{output_format}"

        filename = f"{base_name}-{sequence}-{new_suffix}"
        return output_dir / filename

    @staticmethod
    def get_base_name(input_file: Path) -> str:
        """
        Extract base name from input file path.

        Removes extension (.pcap or .pcapng).

        Args:
            input_file: Input file path

        Returns:
            Base name without extension

        Examples:
            >>> get_base_name(Path("test.pcap"))
            "test"
            >>> get_base_name(Path("data.pcapng"))
            "data"
        """
        name = input_file.name
        # Remove .pcap or .pcapng extension
        if name.endswith(".pcapng"):
            return name[:-7]
        elif name.endswith(".pcap"):
            return name[:-5]
        return name
