"""Pytest configuration and shared fixtures."""

from pathlib import Path
from typing import Iterator

import pytest
from click.testing import CliRunner


@pytest.fixture
def runner() -> CliRunner:
    """Provide a Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def tmp_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Provide a temporary directory path."""
    return tmp_path_factory.mktemp("test")


@pytest.fixture
def test_pcap(tmp_path: Path) -> Path:
    """
    Create a test PCAP file.

    Note: This creates a dummy file. For real tests, use actual PCAP files
    from the cases/ directory.
    """
    pcap_file = tmp_path / "test.pcap"
    # Write minimal PCAP header (24 bytes)
    # Magic number (4 bytes): 0xa1b2c3d4 (microsecond resolution)
    # Version (4 bytes): 2.4
    # Timezone (4 bytes): 0
    # Timestamp accuracy (4 bytes): 0
    # Snapshot length (4 bytes): 65535
    # Link-layer type (4 bytes): 1 (Ethernet)
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


@pytest.fixture
def test_dir(tmp_path: Path) -> Path:
    """
    Create a test directory with multiple PCAP files.
    """
    test_dir = tmp_path / "pcaps"
    test_dir.mkdir()

    # Create multiple test PCAP files
    for i in range(3):
        pcap_file = test_dir / f"test{i}.pcap"
        pcap_header = bytes.fromhex(
            "d4c3b2a1020004000000000000000000ffff000001000000"
        )
        pcap_file.write_bytes(pcap_header)

    return test_dir


@pytest.fixture
def temp_output(tmp_path: Path) -> Iterator[Path]:
    """
    Provide a temporary output directory.

    Yields:
        Path to temporary output directory
    """
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    yield output_dir


@pytest.fixture
def real_pcap() -> Path:
    """
    Provide path to a real PCAP file from cases directory.

    Returns:
        Path to a real PCAP file, or None if not available
    """
    # Try to find a real PCAP file in cases directory
    cases_dir = Path(__file__).parent.parent / "cases"
    if not cases_dir.exists():
        pytest.skip("cases directory not found")

    # Look for VOIP.pcap in V-001
    voip_pcap = cases_dir / "V-001" / "VOIP.pcap"
    if voip_pcap.exists():
        return voip_pcap

    # Look for any .pcap file
    for pcap_file in cases_dir.rglob("*.pcap"):
        if pcap_file.is_file() and pcap_file.stat().st_size > 0:
            return pcap_file

    pytest.skip("No real PCAP files found in cases directory")

