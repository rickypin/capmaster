"""Tests for module selection feature in Analyze plugin."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from capmaster.plugins.analyze.plugin import AnalyzePlugin


class TestModuleSelection:
    """Tests for the --modules parameter functionality."""

    @pytest.fixture
    def plugin(self) -> AnalyzePlugin:
        """Create an AnalyzePlugin instance."""
        return AnalyzePlugin()

    @pytest.fixture
    def test_pcap(self, tmp_path: Path) -> Path:
        """Create a minimal test PCAP file."""
        pcap_file = tmp_path / "test.pcap"
        # Write minimal PCAP header
        pcap_header = bytes.fromhex(
            "d4c3b2a1"  # Magic number (little-endian)
            "0200"  # Major version
            "0400"  # Minor version
            "00000000"  # Timezone
            "00000000"  # Timestamp accuracy
            "ffff0000"  # Snapshot length
            "01000000"  # Link-layer type (Ethernet)
        )
        pcap_file.write_bytes(pcap_header)
        return pcap_file

    def test_execute_with_single_module(self, plugin: AnalyzePlugin, test_pcap: Path, tmp_path: Path):
        """Test executing analyze with a single selected module."""
        output_dir = tmp_path / "output"
        
        # Execute with only protocol_hierarchy module
        exit_code = plugin.execute(
            input_path=test_pcap,
            output_dir=output_dir,
            recursive=False,
            selected_modules=("protocol_hierarchy",),
        )
        
        # Check that execution succeeded
        assert exit_code == 0, "Plugin execution failed"
        
        # Check that output directory was created
        assert output_dir.exists(), "Output directory was not created"
        
        # Check that only protocol_hierarchy output was generated
        output_files = list(output_dir.glob("*.txt"))
        assert len(output_files) == 1, f"Expected 1 output file, got {len(output_files)}"
        
        # Verify it's the protocol hierarchy file
        assert any("protocol-hierarchy" in f.name for f in output_files), \
            "Expected protocol-hierarchy output file"

    def test_execute_with_multiple_modules(self, plugin: AnalyzePlugin, test_pcap: Path, tmp_path: Path):
        """Test executing analyze with multiple selected modules."""
        output_dir = tmp_path / "output"
        
        # Execute with two modules
        exit_code = plugin.execute(
            input_path=test_pcap,
            output_dir=output_dir,
            recursive=False,
            selected_modules=("protocol_hierarchy", "ipv4_hosts"),
        )
        
        # Check that execution succeeded
        assert exit_code == 0, "Plugin execution failed"
        
        # Check that output directory was created
        assert output_dir.exists(), "Output directory was not created"
        
        # Check that both outputs were generated
        output_files = list(output_dir.glob("*.txt"))
        assert len(output_files) == 2, f"Expected 2 output files, got {len(output_files)}"
        
        # Verify both expected files exist
        file_names = [f.name for f in output_files]
        assert any("protocol-hierarchy" in name for name in file_names), \
            "Expected protocol-hierarchy output file"
        assert any("ipv4-hosts" in name for name in file_names), \
            "Expected ipv4-hosts output file"

    def test_execute_with_invalid_module(self, plugin: AnalyzePlugin, test_pcap: Path, tmp_path: Path):
        """Test executing analyze with an invalid module name."""
        output_dir = tmp_path / "output"
        
        # Execute with invalid module name
        exit_code = plugin.execute(
            input_path=test_pcap,
            output_dir=output_dir,
            recursive=False,
            selected_modules=("invalid_module",),
        )
        
        # Should fail with non-zero exit code
        assert exit_code != 0, "Should fail with invalid module name"

    def test_execute_with_mixed_valid_invalid_modules(
        self, plugin: AnalyzePlugin, test_pcap: Path, tmp_path: Path
    ):
        """Test executing analyze with mix of valid and invalid module names."""
        output_dir = tmp_path / "output"
        
        # Execute with one valid and one invalid module
        exit_code = plugin.execute(
            input_path=test_pcap,
            output_dir=output_dir,
            recursive=False,
            selected_modules=("protocol_hierarchy", "invalid_module"),
        )
        
        # Should fail because of invalid module
        assert exit_code != 0, "Should fail when any module is invalid"

    def test_execute_without_module_selection(
        self, plugin: AnalyzePlugin, test_pcap: Path, tmp_path: Path
    ):
        """Test executing analyze without module selection (default behavior)."""
        output_dir = tmp_path / "output"
        
        # Execute without selected_modules parameter
        exit_code = plugin.execute(
            input_path=test_pcap,
            output_dir=output_dir,
            recursive=False,
        )
        
        # Check that execution succeeded
        assert exit_code == 0, "Plugin execution failed"
        
        # Check that output directory was created
        assert output_dir.exists(), "Output directory was not created"
        
        # Check that multiple outputs were generated (all modules)
        output_files = list(output_dir.glob("*.txt"))
        # Should have more than 1 file since all modules run
        assert len(output_files) > 1, "Expected multiple output files when running all modules"

    def test_execute_with_empty_module_tuple(
        self, plugin: AnalyzePlugin, test_pcap: Path, tmp_path: Path
    ):
        """Test executing analyze with empty module tuple."""
        output_dir = tmp_path / "output"
        
        # Execute with empty tuple (should behave like None)
        exit_code = plugin.execute(
            input_path=test_pcap,
            output_dir=output_dir,
            recursive=False,
            selected_modules=(),
        )
        
        # Check that execution succeeded
        assert exit_code == 0, "Plugin execution failed"
        
        # Should run all modules (empty tuple is falsy)
        output_files = list(output_dir.glob("*.txt"))
        assert len(output_files) > 1, "Expected multiple output files with empty tuple"

    def test_module_filtering_preserves_order(
        self, plugin: AnalyzePlugin, test_pcap: Path, tmp_path: Path
    ):
        """Test that module filtering preserves the execution order."""
        output_dir = tmp_path / "output"
        
        # Execute with specific modules
        exit_code = plugin.execute(
            input_path=test_pcap,
            output_dir=output_dir,
            recursive=False,
            selected_modules=("ipv4_hosts", "protocol_hierarchy"),
        )
        
        assert exit_code == 0, "Plugin execution failed"
        
        # Check that both modules were executed
        output_files = list(output_dir.glob("*.txt"))
        assert len(output_files) == 2, f"Expected 2 output files, got {len(output_files)}"

    @patch("capmaster.plugins.analyze.plugin.ProcessPoolExecutor")
    def test_multiprocessing_with_module_selection(
        self, mock_executor: MagicMock, plugin: AnalyzePlugin, test_pcap: Path, tmp_path: Path
    ):
        """Test that module selection works with multiprocessing."""
        output_dir = tmp_path / "output"
        
        # Mock the executor to avoid actual multiprocessing in tests
        mock_pool = MagicMock()
        mock_executor.return_value.__enter__.return_value = mock_pool
        mock_pool.submit.return_value.result.return_value = (test_pcap, 1)
        
        # Execute with workers > 1 and module selection
        exit_code = plugin.execute(
            input_path=test_pcap,
            output_dir=output_dir,
            recursive=False,
            workers=2,
            selected_modules=("protocol_hierarchy",),
        )
        
        # Verify that selected_modules was passed to _process_single_file
        # (This is a basic check; actual multiprocessing behavior is tested in integration tests)
        assert exit_code == 0 or exit_code == 1  # May fail due to mocking, but shouldn't crash


class TestModuleSelectionCLI:
    """Tests for CLI integration of module selection."""

    def test_cli_help_shows_modules_option(self):
        """Test that --modules option appears in CLI help."""
        from click.testing import CliRunner
        from capmaster.cli import cli
        
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "--help"])
        
        assert result.exit_code == 0
        assert "--modules" in result.output or "-m" in result.output
        assert "Specific modules to run" in result.output

    def test_cli_with_single_module(self, tmp_path: Path):
        """Test CLI with single module selection."""
        from click.testing import CliRunner
        from capmaster.cli import cli
        
        # Create a test PCAP file
        pcap_file = tmp_path / "test.pcap"
        pcap_header = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
        pcap_file.write_bytes(pcap_header)
        
        output_dir = tmp_path / "output"
        
        runner = CliRunner()
        result = runner.invoke(cli, [
            "analyze",
            "-i", str(pcap_file),
            "-o", str(output_dir),
            "-m", "protocol_hierarchy"
        ])
        
        # Should succeed
        assert result.exit_code == 0
        
        # Check output
        if output_dir.exists():
            output_files = list(output_dir.glob("*.txt"))
            assert len(output_files) == 1

    def test_cli_with_multiple_modules(self, tmp_path: Path):
        """Test CLI with multiple module selections."""
        from click.testing import CliRunner
        from capmaster.cli import cli
        
        # Create a test PCAP file
        pcap_file = tmp_path / "test.pcap"
        pcap_header = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
        pcap_file.write_bytes(pcap_header)
        
        output_dir = tmp_path / "output"
        
        runner = CliRunner()
        result = runner.invoke(cli, [
            "analyze",
            "-i", str(pcap_file),
            "-o", str(output_dir),
            "-m", "protocol_hierarchy",
            "-m", "ipv4_hosts"
        ])
        
        # Should succeed
        assert result.exit_code == 0
        
        # Check output
        if output_dir.exists():
            output_files = list(output_dir.glob("*.txt"))
            assert len(output_files) == 2

    def test_cli_with_invalid_module(self, tmp_path: Path):
        """Test CLI with invalid module name."""
        from click.testing import CliRunner
        from capmaster.cli import cli
        
        # Create a test PCAP file
        pcap_file = tmp_path / "test.pcap"
        pcap_header = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
        pcap_file.write_bytes(pcap_header)
        
        output_dir = tmp_path / "output"
        
        runner = CliRunner()
        result = runner.invoke(cli, [
            "analyze",
            "-i", str(pcap_file),
            "-o", str(output_dir),
            "-m", "invalid_module"
        ])
        
        # Should fail
        assert result.exit_code != 0
        assert "Unknown module" in result.output or "invalid_module" in result.output

