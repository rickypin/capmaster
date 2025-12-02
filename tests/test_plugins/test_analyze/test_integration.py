"""Integration tests for Analyze plugin."""

from pathlib import Path

import pytest
import click

from capmaster.plugins.analyze.plugin import AnalyzePlugin


@pytest.mark.integration
class TestAnalyzeIntegration:
    """Integration tests for the Analyze plugin using real test cases."""

    @pytest.fixture
    def plugin(self) -> AnalyzePlugin:
        """Create an AnalyzePlugin instance."""
        return AnalyzePlugin()

    @pytest.fixture
    def test_pcap(self) -> Path:
        """Return path to test PCAP file."""
        candidates = [
            Path("data/cases/V-001/VOIP.pcap"),
            Path("data/cases_02/V-001/VOIP.pcap"),
        ]
        for pcap_path in candidates:
            if pcap_path.exists():
                return pcap_path
        pytest.skip("Test PCAP file not found under data/cases or data/cases_02")

    def test_plugin_name(self, plugin: AnalyzePlugin):
        """Test that plugin has correct name."""
        assert plugin.name == "analyze"

    def test_execute_with_single_file(self, plugin: AnalyzePlugin, test_pcap: Path, tmp_path: Path):
        """Test executing analyze on a single PCAP file."""
        output_dir = tmp_path / "output"
        
        # Execute the plugin
        exit_code = plugin.execute(
            input_path=test_pcap,
            output_dir=output_dir,
        )
        
        # Check that execution succeeded
        assert exit_code == 0, "Plugin execution failed"
        
        # Check that output directory was created
        assert output_dir.exists(), "Output directory was not created"
        
        # Check that output files were generated
        output_files = list(output_dir.glob("*.txt"))
        assert len(output_files) > 0, "No output files were generated"
        
        # Check that we have expected modules (at least some of them)
        # Output files have format: <filename>-<seq>-<module>.txt
        expected_modules = [
            "protocol-hierarchy",
            "tcp-conversations",
            "udp-conversations",
            "dns-stats",
        ]

        output_names = [f.stem for f in output_files]
        found_modules = [m for m in expected_modules if any(m in name for name in output_names)]
        assert len(found_modules) > 0, f"Expected modules not found. Got: {output_names}"

    def test_execute_with_directory(self, plugin: AnalyzePlugin, test_pcap: Path, tmp_path: Path):
        """Test executing analyze on a directory containing PCAP files."""
        output_dir = tmp_path / "output"
        input_dir = test_pcap.parent
        
        # Execute the plugin on directory
        exit_code = plugin.execute(
            input_path=input_dir,
            output_dir=output_dir,
        )
        
        # Check that execution succeeded
        assert exit_code == 0, "Plugin execution failed"
        
        # Check that output directory was created
        assert output_dir.exists(), "Output directory was not created"
        
        # Check that output files were generated
        output_files = list(output_dir.glob("*.txt"))
        assert len(output_files) > 0, "No output files were generated"

    def test_execute_with_invalid_input(self, plugin: AnalyzePlugin, tmp_path: Path):
        """Test executing analyze with invalid input."""
        # Test with non-existent file
        non_existent = tmp_path / "non_existent.pcap"
        
        # Should surface as click.BadParameter (InputManager wraps FileNotFoundError)
        with pytest.raises(click.BadParameter):
            plugin.execute(
                input_path=non_existent,
                output_dir=tmp_path / "output",
            )

    def test_execute_with_empty_directory(self, plugin: AnalyzePlugin, tmp_path: Path):
        """Test executing analyze on an empty directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        
        # Should raise BadParameter due to no files found
        with pytest.raises(click.BadParameter):
            plugin.execute(
                input_path=empty_dir,
                output_dir=tmp_path / "output",
                recursive=False,
            )

    def test_execute_without_input_path(self, plugin: AnalyzePlugin, tmp_path: Path):
        """Test executing analyze without input_path."""
        # Should raise BadParameter due to missing input
        with pytest.raises(click.BadParameter):
            plugin.execute(
                output_dir=tmp_path / "output",
                recursive=False,
            )

    def test_execute_with_invalid_output_dir_type(self, plugin: AnalyzePlugin, test_pcap: Path):
        """Test executing analyze with invalid output_dir type."""
        exit_code = plugin.execute(
            input_path=test_pcap,
            output_dir="not_a_path_object",  # type: ignore
            recursive=False,
        )
        
        # Should fail gracefully
        assert exit_code != 0, "Should fail with invalid output_dir type"

    def test_output_file_content(self, plugin: AnalyzePlugin, test_pcap: Path, tmp_path: Path):
        """Test that output files contain expected content."""
        output_dir = tmp_path / "output"
        
        # Execute the plugin
        exit_code = plugin.execute(
            input_path=test_pcap,
            output_dir=output_dir,
            recursive=False,
        )
        
        assert exit_code == 0, "Plugin execution failed"

        # Check protocol_hierarchy output (with sequence number prefix)
        protocol_files = list(output_dir.glob("*protocol-hierarchy.txt"))
        if protocol_files:
            content = protocol_files[0].read_text()
            assert len(content) > 0, "Protocol hierarchy file is empty"
            # Should contain some protocol information
            assert "frame" in content.lower() or "eth" in content.lower(), \
                "Protocol hierarchy should contain frame/eth information"

        # Check tcp_conversations output
        tcp_files = list(output_dir.glob("*tcp-conversations.txt"))
        if tcp_files:
            content = tcp_files[0].read_text()
            assert len(content) > 0, "TCP conversations file is empty"

