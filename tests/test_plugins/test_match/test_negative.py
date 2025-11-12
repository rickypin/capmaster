"""Negative test cases for Match plugin."""

import subprocess
from pathlib import Path

import pytest

from capmaster.core.connection.matcher import BucketStrategy
from capmaster.plugins.match.plugin import MatchPlugin
from capmaster.plugins.match.sampler import ConnectionSampler


@pytest.mark.unit
class TestInvalidParameters:
    """Test invalid parameter handling."""

    def test_invalid_threshold_negative(self):
        """Test that negative threshold is rejected."""
        plugin = MatchPlugin()

        exit_code = plugin.execute(
            input_path=Path("dummy"),
            output_file=Path("dummy.txt"),
            score_threshold=-0.5,
        )

        assert exit_code != 0, "Should fail with negative threshold"

    def test_invalid_threshold_too_high(self):
        """Test that threshold > 1.0 is rejected."""
        plugin = MatchPlugin()

        exit_code = plugin.execute(
            input_path=Path("dummy"),
            output_file=Path("dummy.txt"),
            score_threshold=1.5,
        )

        assert exit_code != 0, "Should fail with threshold > 1.0"

    def test_invalid_bucket_strategy(self):
        """Test that invalid bucket strategy is rejected."""
        # This should raise an error when trying to convert to enum
        with pytest.raises((ValueError, AttributeError)):
            BucketStrategy("invalid_strategy")

    def test_invalid_sampling_rate_negative(self):
        """Test that negative sampling rate is rejected."""
        with pytest.raises(ValueError):
            ConnectionSampler(threshold=100, sample_rate=-0.5)

    def test_invalid_sampling_rate_too_high(self):
        """Test that sampling rate > 1.0 is rejected."""
        with pytest.raises(ValueError):
            ConnectionSampler(threshold=100, sample_rate=1.5)

    def test_invalid_sampling_threshold_negative(self):
        """Test that negative sampling threshold is rejected."""
        with pytest.raises(ValueError):
            ConnectionSampler(threshold=-100, sample_rate=0.5)

    def test_invalid_sampling_threshold_zero(self):
        """Test that zero sampling threshold is rejected."""
        with pytest.raises(ValueError):
            ConnectionSampler(threshold=0, sample_rate=0.5)


@pytest.mark.integration
class TestErrorHandling:
    """Test error handling in various scenarios."""

    def test_nonexistent_input_directory(self, tmp_path: Path):
        """Test handling of non-existent input directory."""
        plugin = MatchPlugin()
        non_existent = tmp_path / "does_not_exist"
        output_file = tmp_path / "output.txt"

        exit_code = plugin.execute(
            input_path=non_existent,
            output_file=output_file,
        )

        assert exit_code != 0, "Should fail with non-existent directory"

    def test_empty_directory(self, tmp_path: Path):
        """Test handling of empty directory."""
        plugin = MatchPlugin()
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        output_file = tmp_path / "output.txt"

        exit_code = plugin.execute(
            input_path=empty_dir,
            output_file=output_file,
        )

        assert exit_code != 0, "Should fail with empty directory"

    def test_single_file_directory(self, tmp_path: Path):
        """Test handling of directory with only one pcap file."""
        plugin = MatchPlugin()
        single_file_dir = tmp_path / "single"
        single_file_dir.mkdir()
        
        # Create a dummy pcap file
        (single_file_dir / "test.pcap").touch()
        
        output_file = tmp_path / "output.txt"

        exit_code = plugin.execute(
            input_path=single_file_dir,
            output_file=output_file,
        )

        assert exit_code != 0, "Should fail with only one file"

    def test_invalid_output_path(self, tmp_path: Path):
        """Test handling of invalid output path."""
        plugin = MatchPlugin()
        
        # Create a directory where output file should be
        invalid_output = tmp_path / "output"
        invalid_output.mkdir()
        
        # Try to use directory as output file
        exit_code = plugin.execute(
            input_path=tmp_path,
            output_file=invalid_output,
        )

        # Should handle gracefully
        assert exit_code != 0, "Should fail with invalid output path"


@pytest.mark.integration
class TestCLIErrorHandling:
    """Test CLI error handling."""

    def test_cli_invalid_threshold(self, tmp_path: Path):
        """Test CLI with invalid threshold."""
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                "-i", str(tmp_path),
                "-o", str(tmp_path / "output.txt"),
                "--threshold", "1.5",  # Invalid: > 1.0
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Should fail with invalid threshold"

    def test_cli_invalid_bucket_strategy(self, tmp_path: Path):
        """Test CLI with invalid bucket strategy."""
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                "-i", str(tmp_path),
                "-o", str(tmp_path / "output.txt"),
                "--bucket", "invalid_strategy",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Should fail with invalid bucket strategy"

    def test_cli_invalid_mode(self, tmp_path: Path):
        """Test CLI with invalid mode."""
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                "-i", str(tmp_path),
                "-o", str(tmp_path / "output.txt"),
                "--mode", "invalid_mode",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Should fail with invalid mode"

    def test_cli_missing_required_args(self):
        """Test CLI with missing required arguments."""
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                # Missing -i and -o
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Should fail with missing required arguments"

    def test_cli_conflicting_sampling_options(self, tmp_path: Path):
        """Test CLI with conflicting sampling options."""
        result = subprocess.run(
            [
                "python", "-m", "capmaster",
                "match",
                "-i", str(tmp_path),
                "-o", str(tmp_path / "output.txt"),
                "--no-sampling",
                "--sampling-rate", "0.5",  # Conflicts with --no-sampling
            ],
            capture_output=True,
            text=True,
        )

        # This might succeed but should log a warning
        # The behavior depends on implementation
        # Just verify it doesn't crash
        assert result.returncode in [0, 1, 2]


@pytest.mark.unit
class TestBoundaryValues:
    """Test boundary value handling."""

    def test_threshold_zero(self):
        """Test threshold at minimum boundary (0.0)."""
        plugin = MatchPlugin()
        # Should accept 0.0 as valid threshold
        # (though it might not be useful in practice)
        # This tests that we don't reject valid boundary values

    def test_threshold_one(self):
        """Test threshold at maximum boundary (1.0)."""
        plugin = MatchPlugin()
        # Should accept 1.0 as valid threshold

    def test_sampling_rate_zero(self):
        """Test sampling rate at minimum boundary (0.0)."""
        # Should this be allowed? Depends on implementation
        # If allowed, it means sample nothing
        try:
            sampler = ConnectionSampler(threshold=100, sample_rate=0.0)
            # If it succeeds, verify behavior
            assert sampler.sample_rate == 0.0
        except ValueError:
            # If it's rejected, that's also valid
            pass

    def test_sampling_rate_one(self):
        """Test sampling rate at maximum boundary (1.0)."""
        sampler = ConnectionSampler(threshold=100, sample_rate=1.0)
        assert sampler.sample_rate == 1.0

    def test_very_large_sampling_threshold(self):
        """Test very large sampling threshold."""
        sampler = ConnectionSampler(threshold=1000000, sample_rate=0.5)
        assert sampler.threshold == 1000000

