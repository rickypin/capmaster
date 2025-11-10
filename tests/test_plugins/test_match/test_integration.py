"""Integration tests for Match plugin."""

import subprocess
from pathlib import Path
from typing import List

import pytest


@pytest.mark.integration
class TestMatchIntegration:
    """Integration tests for the Match plugin using real test cases."""

    @pytest.fixture
    def test_cases_dir(self) -> Path:
        """Return the test cases directory."""
        return Path(__file__).parent.parent.parent.parent / "cases"

    @pytest.fixture
    def tc_001_1(self, test_cases_dir: Path) -> Path:
        """TC-001-1-20160407 test case directory."""
        return test_cases_dir / "TC-001-1-20160407"

    @pytest.fixture
    def tc_001_5(self, test_cases_dir: Path) -> Path:
        """TC-001-5-20190905 test case directory."""
        return test_cases_dir / "TC-001-5-20190905"

    @pytest.fixture
    def tc_002_1(self, test_cases_dir: Path) -> Path:
        """TC-002-1-20211208 test case directory."""
        return test_cases_dir / "TC-002-1-20211208"

    def get_pcap_files(self, directory: Path) -> List[Path]:
        """Get all pcap/pcapng files in a directory (non-recursive)."""
        files = []
        for ext in [".pcap", ".pcapng"]:
            files.extend(directory.glob(f"*{ext}"))
        return sorted(files)

    def test_tc_001_1_has_two_files(self, tc_001_1: Path):
        """Test that TC-001-1 has exactly 2 pcap files."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")
        
        files = self.get_pcap_files(tc_001_1)
        assert len(files) == 2, f"Expected 2 files, found {len(files)}: {files}"

    def test_tc_001_1_match_workflow(self, tc_001_1: Path, tmp_path: Path):
        """Test complete match workflow on TC-001-1."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")
        
        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")
        
        output_file = tmp_path / "matches.txt"
        
        # Run the match command
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
            ],
            capture_output=True,
            text=True,
        )
        
        # Check that the command succeeded
        assert result.returncode == 0, f"Command failed: {result.stderr}"
        
        # Check that output file was created
        assert output_file.exists(), "Output file was not created"
        
        # Check that output file is not empty
        content = output_file.read_text()
        assert len(content) > 0, "Output file is empty"
        
        # Check for expected output format
        lines = content.strip().split("\n")
        assert len(lines) > 0, "No output lines found"

    def test_tc_001_5_single_file_skip(self, tc_001_5: Path, tmp_path: Path):
        """Test that single-file directory is handled correctly."""
        if not tc_001_5.exists():
            pytest.skip(f"Test case directory not found: {tc_001_5}")
        
        files = self.get_pcap_files(tc_001_5)
        if len(files) != 1:
            pytest.skip(f"Expected 1 file, found {len(files)}")
        
        output_file = tmp_path / "matches.txt"
        
        # Run the match command - should fail or skip
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                "-i", str(tc_001_5),
                "-o", str(output_file),
            ],
            capture_output=True,
            text=True,
        )
        
        # Should fail because there's only 1 file
        assert result.returncode != 0, "Command should fail with single file"

    def test_match_with_mode_header(self, tc_001_1: Path, tmp_path: Path):
        """Test match with header-only mode."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")
        
        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")
        
        output_file = tmp_path / "matches_header.txt"
        
        # Run with header mode
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--mode", "header",
            ],
            capture_output=True,
            text=True,
        )
        
        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

    def test_match_with_bucket_server(self, tc_001_1: Path, tmp_path: Path):
        """Test match with server bucket strategy."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")
        
        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")
        
        output_file = tmp_path / "matches_server.txt"
        
        # Run with server bucket
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--bucket", "server",
            ],
            capture_output=True,
            text=True,
        )
        
        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

    def test_match_with_bucket_port(self, tc_001_1: Path, tmp_path: Path):
        """Test match with port bucket strategy."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")
        
        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")
        
        output_file = tmp_path / "matches_port.txt"
        
        # Run with port bucket
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--bucket", "port",
            ],
            capture_output=True,
            text=True,
        )
        
        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

    def test_match_verbose_output(self, tc_001_1: Path, tmp_path: Path):
        """Test match with verbose output."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches_verbose.txt"

        # Run with verbose flag
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "-v",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
            ],
            capture_output=True,
            text=True,
        )

        # Check that the command succeeded
        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Check that output file was created
        assert output_file.exists(), "Output file was not created"

        # Verbose output should be in stdout (INFO level logs)
        assert "INFO" in result.stdout, "No verbose output in stdout"
        assert len(result.stdout) > 0, "No output generated"

    def test_match_with_no_sampling(self, tc_001_1: Path, tmp_path: Path):
        """Test match with sampling disabled."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches_no_sampling.txt"

        # Run with --no-sampling flag
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--no-sampling",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

        # The --no-sampling flag should work without errors
        # (No specific output message is required, just verify it doesn't crash)

    def test_match_with_custom_sampling_threshold(self, tc_001_1: Path, tmp_path: Path):
        """Test match with custom sampling threshold."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches_custom_threshold.txt"

        # Run with custom sampling threshold
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--sampling-threshold", "5000",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

    def test_match_with_custom_sampling_rate(self, tc_001_1: Path, tmp_path: Path):
        """Test match with custom sampling rate."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches_custom_rate.txt"

        # Run with custom sampling rate
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--sampling-rate", "0.3",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

    def test_match_with_combined_sampling_params(self, tc_001_1: Path, tmp_path: Path):
        """Test match with both custom threshold and rate."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches_combined.txt"

        # Run with both custom threshold and rate
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--sampling-threshold", "2000",
                "--sampling-rate", "0.7",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

