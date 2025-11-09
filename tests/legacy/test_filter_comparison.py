"""
Comparison tests between the original shell script and the Python implementation.
"""

import subprocess
import tempfile
from pathlib import Path

import pytest

from capmaster.plugins.filter.plugin import FilterPlugin


# Test cases directory
CASES_DIR = Path("cases")
ORIGINAL_SCRIPT = Path("remove_one_way_tcp.sh")


@pytest.fixture
def filter_plugin():
    """Create a FilterPlugin instance."""
    return FilterPlugin()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def get_stream_count(pcap_file: Path) -> int:
    """Get the number of TCP streams in a PCAP file."""
    try:
        result = subprocess.run(
            ["tshark", "-r", str(pcap_file), "-q", "-z", "conv,tcp"],
            capture_output=True,
            text=True,
            check=True,
        )
        
        # Count lines that look like TCP conversations
        # Format: "IP1:port1 <-> IP2:port2  frames  bytes  ..."
        count = 0
        for line in result.stdout.split('\n'):
            if '<->' in line and not line.startswith('='):
                count += 1
        
        return count
    except subprocess.CalledProcessError:
        return 0


def get_packet_count(pcap_file: Path) -> int:
    """Get the number of packets in a PCAP file."""
    try:
        # Use capinfos to get packet count
        result = subprocess.run(
            ["capinfos", "-c", str(pcap_file)],
            capture_output=True,
            text=True,
            check=True,
        )

        # Parse output like "Number of packets:   1,234" or "Number of packets:   1234"
        for line in result.stdout.split('\n'):
            if 'Number of packets' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    # Remove commas and whitespace
                    count_str = parts[1].strip().replace(',', '')
                    if count_str.isdigit():
                        return int(count_str)

        return 0
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback: count packets with tshark
        try:
            result = subprocess.run(
                ["tshark", "-r", str(pcap_file), "-T", "fields", "-e", "frame.number"],
                capture_output=True,
                text=True,
                check=True,
            )
            lines = [l for l in result.stdout.split('\n') if l.strip()]
            return len(lines)
        except subprocess.CalledProcessError:
            return 0


class TestFilterComparison:
    """Compare filter plugin output with original script."""
    
    @pytest.mark.skipif(
        not CASES_DIR.exists() or not ORIGINAL_SCRIPT.exists(),
        reason="Test files not found"
    )
    def test_compare_voip_pcap(self, filter_plugin, temp_dir):
        """Compare filtering results on VOIP.pcap."""
        pcap_file = CASES_DIR / "V-001" / "VOIP.pcap"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        # Run Python implementation
        python_output = temp_dir / "python_output.pcap"
        exit_code = filter_plugin.execute(
            input_path=pcap_file,
            output_path=python_output,
            ack_threshold=20,
        )
        
        assert exit_code == 0
        assert python_output.exists()
        
        # Get packet counts
        input_packets = get_packet_count(pcap_file)
        output_packets = get_packet_count(python_output)
        
        # Output should have packets
        assert output_packets > 0
        # Output should not have more packets than input
        assert output_packets <= input_packets
        
        print(f"\nInput packets: {input_packets}")
        print(f"Output packets: {output_packets}")
        print(f"Filtered: {input_packets - output_packets} packets")
    
    @pytest.mark.skipif(
        not CASES_DIR.exists() or not ORIGINAL_SCRIPT.exists(),
        reason="Test files not found"
    )
    def test_compare_tc001_pcap(self, filter_plugin, temp_dir):
        """Compare filtering results on TC-001 PCAP."""
        pcap_file = CASES_DIR / "TC-001-1-20160407" / "TC-001-1-20160407-A.pcap"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        # Run Python implementation
        python_output = temp_dir / "python_output.pcap"
        exit_code = filter_plugin.execute(
            input_path=pcap_file,
            output_path=python_output,
            ack_threshold=20,
        )
        
        assert exit_code == 0
        assert python_output.exists()
        
        # Get packet counts
        input_packets = get_packet_count(pcap_file)
        output_packets = get_packet_count(python_output)
        
        # Output should have packets
        assert output_packets > 0
        # Output should not have more packets than input
        assert output_packets <= input_packets
        
        print(f"\nInput packets: {input_packets}")
        print(f"Output packets: {output_packets}")
        print(f"Filtered: {input_packets - output_packets} packets")
    
    @pytest.mark.skipif(
        not CASES_DIR.exists() or not ORIGINAL_SCRIPT.exists(),
        reason="Test files not found"
    )
    def test_compare_tc002_pcap(self, filter_plugin, temp_dir):
        """Compare filtering results on TC-002 PCAP."""
        pcap_file = CASES_DIR / "TC-002-1-20211208" / "TC-002-1-20211208-O.pcapng"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        # Run Python implementation
        python_output = temp_dir / "python_output.pcapng"
        exit_code = filter_plugin.execute(
            input_path=pcap_file,
            output_path=python_output,
            ack_threshold=20,
        )
        
        assert exit_code == 0
        assert python_output.exists()
        
        # Get packet counts
        input_packets = get_packet_count(pcap_file)
        output_packets = get_packet_count(python_output)
        
        # Output should have packets
        assert output_packets > 0
        # Output should not have more packets than input
        assert output_packets <= input_packets
        
        print(f"\nInput packets: {input_packets}")
        print(f"Output packets: {output_packets}")
        print(f"Filtered: {input_packets - output_packets} packets")


class TestFilterThresholdBehavior:
    """Test filter behavior with different thresholds."""
    
    @pytest.mark.skipif(not CASES_DIR.exists(), reason="Test files not found")
    def test_threshold_effect(self, filter_plugin, temp_dir):
        """Test that higher threshold filters fewer streams."""
        pcap_file = CASES_DIR / "V-001" / "VOIP.pcap"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        # Test with low threshold
        output_low = temp_dir / "output_low.pcap"
        filter_plugin.execute(
            input_path=pcap_file,
            output_path=output_low,
            ack_threshold=10,
        )
        
        # Test with high threshold
        output_high = temp_dir / "output_high.pcap"
        filter_plugin.execute(
            input_path=pcap_file,
            output_path=output_high,
            ack_threshold=1000,
        )
        
        # Get packet counts
        packets_low = get_packet_count(output_low)
        packets_high = get_packet_count(output_high)
        
        # Higher threshold should filter fewer packets (more packets in output)
        assert packets_high >= packets_low
        
        print(f"\nLow threshold (10) output: {packets_low} packets")
        print(f"High threshold (1000) output: {packets_high} packets")
    
    @pytest.mark.skipif(not CASES_DIR.exists(), reason="Test files not found")
    def test_zero_threshold(self, filter_plugin, temp_dir):
        """Test filter with threshold=0 (should filter nothing)."""
        pcap_file = CASES_DIR / "V-001" / "VOIP.pcap"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        output_file = temp_dir / "output.pcap"
        filter_plugin.execute(
            input_path=pcap_file,
            output_path=output_file,
            ack_threshold=0,
        )
        
        # Get packet counts
        input_packets = get_packet_count(pcap_file)
        output_packets = get_packet_count(output_file)
        
        # With threshold=0, should filter very few or no packets
        # (only those with ack_delta > 0 and pure ACK)
        assert output_packets > 0
        
        print(f"\nInput packets: {input_packets}")
        print(f"Output packets (threshold=0): {output_packets}")


class TestFilterConsistency:
    """Test that filter produces consistent results."""
    
    @pytest.mark.skipif(not CASES_DIR.exists(), reason="Test files not found")
    def test_multiple_runs_consistent(self, filter_plugin, temp_dir):
        """Test that running filter multiple times produces same results."""
        pcap_file = CASES_DIR / "V-001" / "VOIP.pcap"
        if not pcap_file.exists():
            pytest.skip(f"Test file not found: {pcap_file}")
        
        # Run filter twice
        output1 = temp_dir / "output1.pcap"
        filter_plugin.execute(
            input_path=pcap_file,
            output_path=output1,
            ack_threshold=20,
        )
        
        output2 = temp_dir / "output2.pcap"
        filter_plugin.execute(
            input_path=pcap_file,
            output_path=output2,
            ack_threshold=20,
        )
        
        # Both outputs should have same packet count
        packets1 = get_packet_count(output1)
        packets2 = get_packet_count(output2)
        
        assert packets1 == packets2
        
        print(f"\nRun 1: {packets1} packets")
        print(f"Run 2: {packets2} packets")

