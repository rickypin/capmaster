"""Tests for TsharkWrapper."""

from __future__ import annotations
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from capmaster.core.tshark_wrapper import TsharkWrapper


@pytest.mark.integration
class TestTsharkWrapper:
    """Test cases for TsharkWrapper."""

    @patch("shutil.which")
    def test_init_tshark_not_found(self, mock_which: MagicMock) -> None:
        """Test initialization fails when tshark is not found."""
        mock_which.return_value = None

        with pytest.raises(RuntimeError, match="tshark not found"):
            TsharkWrapper()

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_init_success(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        """Test successful initialization."""
        mock_which.return_value = "/usr/bin/tshark"
        mock_run.return_value = MagicMock(
            stdout="TShark (Wireshark) 4.0.6 (Git v4.0.6)\n", returncode=0
        )

        wrapper = TsharkWrapper()

        assert wrapper.tshark_path == "/usr/bin/tshark"
        assert wrapper.version == "4.0.6"

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_version_alternative_format(
        self, mock_run: MagicMock, mock_which: MagicMock
    ) -> None:
        """Test version parsing with alternative format."""
        mock_which.return_value = "/usr/bin/tshark"
        mock_run.return_value = MagicMock(stdout="TShark 4.2.0\n", returncode=0)

        wrapper = TsharkWrapper()

        assert wrapper.version == "4.2.0"

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_version_timeout(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        """Test version check timeout."""
        mock_which.return_value = "/usr/bin/tshark"
        mock_run.side_effect = subprocess.TimeoutExpired("tshark", 5)

        with pytest.raises(RuntimeError, match="timed out"):
            TsharkWrapper()

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_execute_basic(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        """Test basic command execution."""
        mock_which.return_value = "/usr/bin/tshark"
        mock_run.side_effect = [
            MagicMock(stdout="TShark (Wireshark) 4.0.6\n", returncode=0),  # version
            MagicMock(stdout="output", stderr="", returncode=0),  # execute
        ]

        wrapper = TsharkWrapper()
        result = wrapper.execute(["-q", "-z", "io,phs"])

        assert result.stdout == "output"
        assert result.returncode == 0
        mock_run.assert_called_with(
            ["/usr/bin/tshark", "-q", "-z", "io,phs"],
            capture_output=True,
            text=True,
            check=False,  # TsharkWrapper handles exit codes manually
            timeout=None,
        )

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_execute_with_input_file(
        self, mock_run: MagicMock, mock_which: MagicMock, tmp_path: Path
    ) -> None:
        """Test command execution with input file."""
        mock_which.return_value = "/usr/bin/tshark"
        mock_run.side_effect = [
            MagicMock(stdout="TShark (Wireshark) 4.0.6\n", returncode=0),
            MagicMock(stdout="output", stderr="", returncode=0),
        ]

        input_file = tmp_path / "test.pcap"
        input_file.touch()

        wrapper = TsharkWrapper()
        wrapper.execute(["-q"], input_file=input_file)

        # Check that -r was added
        call_args = mock_run.call_args_list[1][0][0]
        assert "-r" in call_args
        assert str(input_file) in call_args

    @patch("shutil.which")
    @patch("subprocess.run")
    @patch("builtins.open", create=True)
    def test_execute_with_output_file(
        self, mock_open: MagicMock, mock_run: MagicMock, mock_which: MagicMock, tmp_path: Path
    ) -> None:
        """Test command execution with output file (text output redirection)."""
        mock_which.return_value = "/usr/bin/tshark"
        mock_run.side_effect = [
            MagicMock(stdout="TShark (Wireshark) 4.0.6\n", returncode=0),
            MagicMock(stdout="", stderr="", returncode=0),
        ]

        output_file = tmp_path / "output.txt"

        wrapper = TsharkWrapper()
        wrapper.execute(["-Y", "tcp"], output_file=output_file)

        # Check that output file was opened for writing
        mock_open.assert_called_once_with(output_file, "w", encoding="utf-8")

        # Check that command was executed
        call_args = mock_run.call_args_list[1][0][0]
        assert "/usr/bin/tshark" in call_args
        assert "-Y" in call_args
        assert "tcp" in call_args

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_execute_with_timeout(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        """Test command execution with timeout."""
        mock_which.return_value = "/usr/bin/tshark"
        mock_run.side_effect = [
            MagicMock(stdout="TShark (Wireshark) 4.0.6\n", returncode=0),
            MagicMock(stdout="output", stderr="", returncode=0),
        ]

        wrapper = TsharkWrapper()
        wrapper.execute(["-q"], timeout=30)

        # Check timeout was passed
        assert mock_run.call_args_list[1][1]["timeout"] == 30

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_execute_command_failure(
        self, mock_run: MagicMock, mock_which: MagicMock
    ) -> None:
        """Test command execution failure."""
        mock_which.return_value = "/usr/bin/tshark"
        mock_run.side_effect = [
            MagicMock(stdout="TShark (Wireshark) 4.0.6\n", returncode=0),
            MagicMock(stdout="", stderr="error", returncode=1),
        ]

        wrapper = TsharkWrapper()

        with pytest.raises(subprocess.CalledProcessError):
            wrapper.execute(["-invalid"])

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_execute_with_exit_code_2_warning(
        self, mock_run: MagicMock, mock_which: MagicMock
    ) -> None:
        """Test command execution with exit code 2 (warning) - should not raise."""
        mock_which.return_value = "/usr/bin/tshark"
        mock_run.side_effect = [
            MagicMock(stdout="TShark (Wireshark) 4.0.6\n", returncode=0),  # version
            MagicMock(
                stdout="packet data",
                stderr='tshark: The file "test.pcap" appears to have been cut short',
                returncode=2,
            ),  # execute with warning
        ]

        wrapper = TsharkWrapper()
        result = wrapper.execute(["-r", "test.pcap"])

        # Should succeed despite exit code 2
        assert result.returncode == 2
        assert result.stdout == "packet data"
        # Warning should be logged but not raise exception

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_check_version_requirement_met(
        self, mock_run: MagicMock, mock_which: MagicMock
    ) -> None:
        """Test version requirement check when met."""
        mock_which.return_value = "/usr/bin/tshark"
        mock_run.return_value = MagicMock(stdout="TShark (Wireshark) 4.2.0\n", returncode=0)

        wrapper = TsharkWrapper()

        assert wrapper.check_version_requirement("4.0") is True
        assert wrapper.check_version_requirement("4.2") is True

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_check_version_requirement_not_met(
        self, mock_run: MagicMock, mock_which: MagicMock
    ) -> None:
        """Test version requirement check when not met."""
        mock_which.return_value = "/usr/bin/tshark"
        mock_run.return_value = MagicMock(stdout="TShark (Wireshark) 3.6.0\n", returncode=0)

        wrapper = TsharkWrapper()

        assert wrapper.check_version_requirement("4.0") is False

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_check_version_requirement_equal(
        self, mock_run: MagicMock, mock_which: MagicMock
    ) -> None:
        """Test version requirement check when equal."""
        mock_which.return_value = "/usr/bin/tshark"
        mock_run.return_value = MagicMock(stdout="TShark (Wireshark) 4.0.0\n", returncode=0)

        wrapper = TsharkWrapper()

        assert wrapper.check_version_requirement("4.0") is True

