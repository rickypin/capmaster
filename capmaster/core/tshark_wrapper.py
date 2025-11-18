"""Wrapper for tshark command-line tool."""

from __future__ import annotations
import logging
import shutil
import subprocess
from pathlib import Path

from capmaster.utils.errors import TsharkExecutionError, TsharkNotFoundError

logger = logging.getLogger(__name__)


class TsharkWrapper:
    """Wrapper for executing tshark commands."""

    def __init__(self) -> None:
        """Initialize TsharkWrapper and verify tshark is available."""
        self.tshark_path = self._find_tshark()
        self.version = self._get_version()

    def _find_tshark(self) -> str:
        """
        Find tshark executable in system PATH.

        Returns:
            Path to tshark executable

        Raises:
            TsharkNotFoundError: If tshark is not found
        """
        tshark_path = shutil.which("tshark")
        if tshark_path is None:
            # Raise a domain-specific error so callers can handle this explicitly
            raise TsharkNotFoundError()
        return tshark_path

    def _get_version(self) -> str:
        """
        Get tshark version.

        Returns:
            Version string (e.g., "4.0.6")

        Raises:
            TsharkExecutionError: If the version command fails or output cannot be parsed
        """
        cmd = [self.tshark_path, "--version"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
        except subprocess.CalledProcessError as e:
            raise TsharkExecutionError(
                " ".join(cmd),
                e.returncode,
                e.stderr or str(e),
            ) from e
        except subprocess.TimeoutExpired as e:
            raise TsharkExecutionError(
                " ".join(cmd),
                -1,
                f"tshark --version command timed out after {getattr(e, 'timeout', 'unknown')} seconds",
            ) from e

        # Parse version from first line: "TShark (Wireshark) 4.0.6 ..."
        first_line = result.stdout.split("\n")[0]
        parts = first_line.split()
        for i, part in enumerate(parts):
            if part.lower() == "tshark" and i + 1 < len(parts):
                # Skip "(Wireshark)" if present
                version_idx = i + 2 if parts[i + 1].startswith("(") else i + 1
                if version_idx < len(parts):
                    return parts[version_idx]
        raise TsharkExecutionError(
            " ".join(cmd),
            0,
            f"Could not parse tshark version from: {first_line}",
        )

    def execute(
        self,
        args: list[str],
        input_file: Path | None = None,
        output_file: Path | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """
        Execute tshark command.

        Args:
            args: List of tshark arguments (e.g., ["-q", "-z", "io,phs"])
            input_file: Input PCAP file (will add -r argument)
            output_file: Output file for text output (stdout will be redirected)
                        For PCAP output, use -w in args instead
            timeout: Command timeout in seconds (None for no timeout)

        Returns:
            CompletedProcess with stdout, stderr, and returncode

        Raises:
            TsharkExecutionError: If tshark command fails with exit code not in {0, 2}
            subprocess.TimeoutExpired: If command times out

        Notes:
            Exit code 2 is treated as a warning (e.g., truncated PCAP files) and
            does not raise an exception, as tshark still produces useful output.
        """
        cmd = [self.tshark_path]

        # Add input file
        if input_file is not None:
            cmd.extend(["-r", str(input_file)])

        # Add custom arguments
        cmd.extend(args)

        # Execute command without check=True to handle exit codes manually
        if output_file is not None:
            # Ensure parent directory exists
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            # Redirect stdout to file for text output
            with open(output_file, "w", encoding="utf-8") as f:
                result = subprocess.run(
                    cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,  # Don't raise on non-zero exit
                    timeout=timeout,
                )
        else:
            # Capture output normally
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,  # Don't raise on non-zero exit
                timeout=timeout,
            )

        # Handle exit codes
        # Exit code 0: Success
        # Exit code 2: Warning (e.g., truncated file) - still produces output
        # Other codes: Error
        if result.returncode == 0:
            # Success
            pass
        elif result.returncode == 2:
            # Warning - log but don't fail
            if result.stderr:
                logger.warning(f"tshark warning: {result.stderr.strip()}")
        else:
            # Error - log and then raise a domain-specific exception
            stderr = result.stderr or ""
            if stderr:
                logger.error(
                    "tshark command failed with exit code %s: %s",
                    result.returncode,
                    stderr.strip(),
                )
            raise TsharkExecutionError(
                " ".join(cmd),
                result.returncode,
                stderr,
            )

        return result

    def check_version_requirement(self, min_version: str = "4.0") -> bool:
        """
        Check if tshark version meets minimum requirement.

        Args:
            min_version: Minimum required version (e.g., "4.0")

        Returns:
            True if version meets requirement, False otherwise
        """
        try:
            current_parts = [int(x) for x in self.version.split(".")[:2]]
            required_parts = [int(x) for x in min_version.split(".")[:2]]

            for current, required in zip(current_parts, required_parts, strict=False):
                if current > required:
                    return True
                if current < required:
                    return False
            return True  # Equal versions
        except (ValueError, IndexError):
            # If we can't parse version, assume it's OK
            return True
