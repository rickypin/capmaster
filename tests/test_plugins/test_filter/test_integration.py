"""
Integration tests for the Filter plugin using real PCAP files.
"""

import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from capmaster.cli import cli
from capmaster.plugins import discover_plugins, get_all_plugins
from capmaster.plugins.filter.plugin import FilterPlugin


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


@pytest.fixture
def filter_plugin():
    """Create a FilterPlugin instance."""
    return FilterPlugin()


# Test cases directory
CASES_DIR = Path("cases")


class TestFilterIntegration:
    """Integration tests for filter plugin with real PCAP files."""
    
    @pytest.mark.skipif(not CASES_DIR.exists(), reason="cases directory not found")
    def test_filter_voip_pcap(self, filter_plugin, temp_dir):
        """Test filtering VOIP.pcap file."""
        pcap_file = CASES_DIR / "V-001" / "VOIP.pcap"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        output_file = temp_dir / "voip_filtered.pcap"
        
        exit_code = filter_plugin.execute(
            input_path=pcap_file,
            output_path=output_file,
            ack_threshold=20,
        )
        
        assert exit_code == 0
        assert output_file.exists()
        assert output_file.stat().st_size > 0
    
    @pytest.mark.skipif(not CASES_DIR.exists(), reason="cases directory not found")
    def test_filter_tc001_pcap(self, filter_plugin, temp_dir):
        """Test filtering TC-001 PCAP files."""
        pcap_file = CASES_DIR / "TC-001-1-20160407" / "TC-001-1-20160407-A.pcap"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        output_file = temp_dir / "tc001_filtered.pcap"
        
        exit_code = filter_plugin.execute(
            input_path=pcap_file,
            output_path=output_file,
            ack_threshold=20,
        )
        
        assert exit_code == 0
        assert output_file.exists()
        assert output_file.stat().st_size > 0
    
    @pytest.mark.skipif(not CASES_DIR.exists(), reason="cases directory not found")
    def test_filter_directory(self, filter_plugin, temp_dir):
        """Test filtering a directory of PCAP files."""
        pcap_dir = CASES_DIR / "V-001"
        if not pcap_dir.exists():
            pytest.skip(f"Test directory not found: {pcap_dir}")
        
        exit_code = filter_plugin.execute(
            input_path=pcap_dir,
            output_path=temp_dir,
            ack_threshold=20,
        )
        
        assert exit_code == 0
        # Check that output files were created
        output_files = list(temp_dir.glob("*_filtered.pcap*"))
        assert len(output_files) > 0
    
    @pytest.mark.skipif(not CASES_DIR.exists(), reason="cases directory not found")
    def test_filter_with_different_thresholds(self, filter_plugin, temp_dir):
        """Test filtering with different ACK thresholds."""
        pcap_file = CASES_DIR / "V-001" / "VOIP.pcap"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        # Test with low threshold
        output_low = temp_dir / "output_low.pcap"
        exit_code = filter_plugin.execute(
            input_path=pcap_file,
            output_path=output_low,
            ack_threshold=10,
        )
        assert exit_code == 0
        assert output_low.exists()
        
        # Test with high threshold
        output_high = temp_dir / "output_high.pcap"
        exit_code = filter_plugin.execute(
            input_path=pcap_file,
            output_path=output_high,
            ack_threshold=1000,
        )
        assert exit_code == 0
        assert output_high.exists()
        
        # Both should succeed
        assert output_low.stat().st_size > 0
        assert output_high.stat().st_size > 0


class TestFilterCLIIntegration:
    """Integration tests for filter CLI with real PCAP files."""
    
    @pytest.mark.skipif(not CASES_DIR.exists(), reason="cases directory not found")
    def test_cli_filter_voip(self, runner, temp_dir):
        """Test CLI filter command with VOIP.pcap."""
        pcap_file = CASES_DIR / "V-001" / "VOIP.pcap"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        output_file = temp_dir / "voip_filtered.pcap"
        
        result = runner.invoke(cli, [
            "filter",
            "-i", str(pcap_file),
            "-o", str(output_file),
        ])
        
        assert result.exit_code == 0
        assert output_file.exists()
    
    @pytest.mark.skipif(not CASES_DIR.exists(), reason="cases directory not found")
    def test_cli_filter_with_threshold(self, runner, temp_dir):
        """Test CLI filter command with custom threshold."""
        pcap_file = CASES_DIR / "V-001" / "VOIP.pcap"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        output_file = temp_dir / "voip_filtered.pcap"
        
        result = runner.invoke(cli, [
            "filter",
            "-i", str(pcap_file),
            "-o", str(output_file),
            "-t", "50",
        ])
        
        assert result.exit_code == 0
        assert output_file.exists()
    
    @pytest.mark.skipif(not CASES_DIR.exists(), reason="cases directory not found")
    def test_cli_filter_verbose(self, runner, temp_dir):
        """Test CLI filter command with verbose output."""
        pcap_file = CASES_DIR / "V-001" / "VOIP.pcap"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        output_file = temp_dir / "voip_filtered.pcap"
        
        result = runner.invoke(cli, [
            "-v",
            "filter",
            "-i", str(pcap_file),
            "-o", str(output_file),
        ])
        
        assert result.exit_code == 0
        assert output_file.exists()


class TestFilterOutputValidation:
    """Test that filter output is valid PCAP."""
    
    @pytest.mark.skipif(not CASES_DIR.exists(), reason="cases directory not found")
    def test_output_is_valid_pcap(self, filter_plugin, temp_dir):
        """Test that filtered output is a valid PCAP file."""
        pcap_file = CASES_DIR / "V-001" / "VOIP.pcap"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        output_file = temp_dir / "output.pcap"
        
        exit_code = filter_plugin.execute(
            input_path=pcap_file,
            output_path=output_file,
            ack_threshold=20,
        )
        
        assert exit_code == 0
        assert output_file.exists()
        
        # Try to read the output with tshark to validate it's a valid PCAP
        import subprocess
        result = subprocess.run(
            ["tshark", "-r", str(output_file), "-c", "1"],
            capture_output=True,
            text=True,
        )
        
        # Should succeed (exit code 0) or have no packets (exit code 0)
        assert result.returncode == 0
    
    @pytest.mark.skipif(not CASES_DIR.exists(), reason="cases directory not found")
    def test_output_size_reasonable(self, filter_plugin, temp_dir):
        """Test that output size is reasonable (not empty, not larger than input)."""
        pcap_file = CASES_DIR / "V-001" / "VOIP.pcap"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        output_file = temp_dir / "output.pcap"
        
        exit_code = filter_plugin.execute(
            input_path=pcap_file,
            output_path=output_file,
            ack_threshold=20,
        )
        
        assert exit_code == 0
        assert output_file.exists()
        
        input_size = pcap_file.stat().st_size
        output_size = output_file.stat().st_size
        
        # Output should be positive size
        assert output_size > 0
        # Output should not be larger than input
        assert output_size <= input_size

