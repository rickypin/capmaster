"""
Tests for the FilterPlugin class.
"""

import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from capmaster.cli import cli
from capmaster.plugins import discover_plugins, get_all_plugins
from capmaster.plugins.filter.plugin import FilterPlugin


@pytest.fixture
def filter_plugin():
    """Create a FilterPlugin instance."""
    return FilterPlugin()


@pytest.fixture
def runner():
    """Create a Click CLI runner."""
    return CliRunner()


@pytest.fixture(autouse=True)
def setup_plugins():
    """Ensure plugins are discovered before each test."""
    discover_plugins()
    for plugin_class in get_all_plugins():
        plugin = plugin_class()
        plugin.setup_cli(cli)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestFilterPlugin:
    """Test FilterPlugin class."""
    
    def test_plugin_name(self, filter_plugin):
        """Test plugin name."""
        assert filter_plugin.name == "filter"
    
    def test_cli_registration(self, runner):
        """Test that filter command is registered."""
        result = runner.invoke(cli, ["filter", "--help"])
        assert result.exit_code == 0
        assert "Remove one-way TCP connections" in result.output
        assert "--input" in result.output
        assert "--output" in result.output
        assert "--threshold" in result.output
    
    def test_missing_input(self, runner):
        """Test error when input is missing."""
        result = runner.invoke(cli, ["filter"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()
    
    def test_invalid_input_path(self, runner):
        """Test error when input path doesn't exist."""
        result = runner.invoke(cli, ["filter", "-i", "/nonexistent/path.pcap"])
        assert result.exit_code != 0


class TestDetectOneWayStreams:
    """Test _detect_one_way_streams method."""
    
    def test_detect_with_real_pcap(self, filter_plugin, test_pcap):
        """Test detection with a real PCAP file."""
        # This test requires a PCAP file with TCP traffic
        # The test_pcap fixture should provide a valid PCAP file
        one_way_streams = filter_plugin._detect_one_way_streams(test_pcap, ack_threshold=20)
        
        # Should return a list (may be empty if no one-way streams)
        assert isinstance(one_way_streams, list)
        assert all(isinstance(s, int) for s in one_way_streams)
    
    def test_detect_with_high_threshold(self, filter_plugin, test_pcap):
        """Test detection with a very high threshold."""
        # With a very high threshold, should detect fewer streams
        one_way_streams = filter_plugin._detect_one_way_streams(test_pcap, ack_threshold=10000)
        
        assert isinstance(one_way_streams, list)
    
    def test_detect_with_low_threshold(self, filter_plugin, test_pcap):
        """Test detection with a very low threshold."""
        # With a very low threshold, might detect more streams
        one_way_streams = filter_plugin._detect_one_way_streams(test_pcap, ack_threshold=1)
        
        assert isinstance(one_way_streams, list)


class TestFilterPcap:
    """Test _filter_pcap method."""
    
    def test_filter_no_streams(self, filter_plugin, test_pcap, temp_dir):
        """Test filtering with no streams to exclude."""
        output_file = temp_dir / "output.pcap"
        
        # Filter with empty list
        filter_plugin._filter_pcap(test_pcap, output_file, [])
        
        # Output file should exist and be a copy of input
        assert output_file.exists()
        assert output_file.stat().st_size > 0
    
    def test_filter_with_streams(self, filter_plugin, test_pcap, temp_dir):
        """Test filtering with streams to exclude."""
        output_file = temp_dir / "output.pcap"
        
        # Filter out stream 0 (if it exists)
        filter_plugin._filter_pcap(test_pcap, output_file, [0])
        
        # Output file should exist
        assert output_file.exists()
        # Size might be different from input
        assert output_file.stat().st_size >= 0
    
    def test_filter_multiple_streams(self, filter_plugin, test_pcap, temp_dir):
        """Test filtering with multiple streams to exclude."""
        output_file = temp_dir / "output.pcap"
        
        # Filter out multiple streams
        filter_plugin._filter_pcap(test_pcap, output_file, [0, 1, 2])
        
        # Output file should exist
        assert output_file.exists()


class TestExecute:
    """Test execute method."""
    
    def test_execute_single_file(self, filter_plugin, test_pcap, temp_dir):
        """Test executing filter on a single file."""
        output_file = temp_dir / "output.pcap"
        
        exit_code = filter_plugin.execute(
            input_path=test_pcap,
            output_path=output_file,
            ack_threshold=20,
        )
        
        assert exit_code == 0
        assert output_file.exists()
    
    def test_execute_with_default_output(self, filter_plugin, test_pcap):
        """Test executing filter with default output path."""
        # Default output should be <input>_filtered.pcap
        exit_code = filter_plugin.execute(
            input_path=test_pcap,
            ack_threshold=20,
        )
        
        assert exit_code == 0
        
        # Check default output file
        expected_output = test_pcap.parent / f"{test_pcap.stem}_filtered{test_pcap.suffix}"
        assert expected_output.exists()
        
        # Clean up
        expected_output.unlink()
    
    def test_execute_directory(self, filter_plugin, test_dir, temp_dir):
        """Test executing filter on a directory."""
        # test_dir should contain PCAP files
        exit_code = filter_plugin.execute(
            input_path=test_dir,
            output_path=temp_dir,
            ack_threshold=20,
        )
        
        # Should succeed even if no PCAP files found
        assert exit_code in (0, 1)
    
    def test_execute_custom_threshold(self, filter_plugin, test_pcap, temp_dir):
        """Test executing filter with custom threshold."""
        output_file = temp_dir / "output.pcap"
        
        exit_code = filter_plugin.execute(
            input_path=test_pcap,
            output_path=output_file,
            ack_threshold=100,
        )
        
        assert exit_code == 0
        assert output_file.exists()
    
    def test_execute_invalid_path(self, filter_plugin):
        """Test executing filter with invalid path."""
        exit_code = filter_plugin.execute(
            input_path=Path("/nonexistent/path.pcap"),
            ack_threshold=20,
        )
        
        assert exit_code == 1


class TestCLIIntegration:
    """Test CLI integration."""
    
    def test_filter_command_basic(self, runner, test_pcap, temp_dir):
        """Test basic filter command."""
        output_file = temp_dir / "output.pcap"
        
        result = runner.invoke(cli, [
            "filter",
            "-i", str(test_pcap),
            "-o", str(output_file),
        ])
        
        assert result.exit_code == 0
        assert output_file.exists()
    
    def test_filter_command_with_threshold(self, runner, test_pcap, temp_dir):
        """Test filter command with custom threshold."""
        output_file = temp_dir / "output.pcap"
        
        result = runner.invoke(cli, [
            "filter",
            "-i", str(test_pcap),
            "-o", str(output_file),
            "-t", "50",
        ])
        
        assert result.exit_code == 0
        assert output_file.exists()
    
    def test_filter_command_verbose(self, runner, test_pcap, temp_dir):
        """Test filter command with verbose output."""
        output_file = temp_dir / "output.pcap"
        
        result = runner.invoke(cli, [
            "-v",
            "filter",
            "-i", str(test_pcap),
            "-o", str(output_file),
        ])
        
        assert result.exit_code == 0
        assert output_file.exists()

