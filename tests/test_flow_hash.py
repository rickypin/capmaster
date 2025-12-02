"""Tests for flow hash calculation.

This module contains basic unit tests for the flow hash functionality.
For Rust compatibility tests, see test_flow_hash_rust_compatibility.py.
"""

import pytest

from capmaster.plugins.compare_common.flow_hash import (
    FlowSide,
    calculate_connection_flow_hash,
    calculate_flow_hash,
    format_flow_hash,
)


class TestFlowHash:
    """Test flow hash calculation."""

    def test_bidirectional_consistency(self):
        """Test that flow hash is the same for both directions."""
        # Forward direction
        hash1, side1 = calculate_flow_hash(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol=6,
        )

        # Reverse direction
        hash2, side2 = calculate_flow_hash(
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=54321,
            protocol=6,
        )

        # Hashes should be identical
        assert hash1 == hash2, "Flow hash should be the same for both directions"

        # Sides should be opposite
        assert side1 != side2, "Flow sides should be different"

    def test_different_connections_different_hash(self):
        """Test that different connections have different hashes."""
        hash1, _ = calculate_flow_hash(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol=6,
        )

        hash2, _ = calculate_flow_hash(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54322,  # Different port
            dst_port=80,
            protocol=6,
        )

        assert hash1 != hash2, "Different connections should have different hashes"

    def test_port_comparison(self):
        """Test flow side determination based on ports.

        Note: Ports are compared as little-endian integers to match Rust implementation.
        54321 (0xD431) in little-endian = 0x31D4 = 12756
        80 (0x0050) in little-endian = 0x5000 = 20480
        Since 12756 < 20480, dst_port is considered larger, so RHS_GT_LHS.
        """
        hash1, side1 = calculate_flow_hash(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol=6,
        )

        # When src_port (little-endian) < dst_port (little-endian), flow_side should be RHS_GT_LHS
        assert side1 == FlowSide.RHS_GT_LHS

    def test_same_ports_ip_comparison(self):
        """Test flow side determination based on IPs when ports are equal."""
        hash1, side1 = calculate_flow_hash(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=8080,
            dst_port=8080,  # Same port
            protocol=6,
        )

        # 192.168.1.100 > 10.0.0.1, so LHS_GE_RHS
        assert side1 == FlowSide.LHS_GE_RHS

    def test_ipv6_support(self):
        """Test that IPv6 addresses are supported."""
        hash1, side1 = calculate_flow_hash(
            src_ip="2001:db8::1",
            dst_ip="2001:db8::2",
            src_port=12345,
            dst_port=80,
            protocol=6,
        )

        # Should not raise an exception and return an integer
        assert isinstance(hash1, int)
        # Should be in signed 64-bit range
        assert -(2**63) <= hash1 < 2**63

    def test_format_flow_hash(self):
        """Test flow hash formatting."""
        hash_val = -1234567890123456789

        formatted = format_flow_hash(hash_val, FlowSide.LHS_GE_RHS)
        assert str(hash_val) in formatted
        assert "LHS>=RHS" in formatted

        formatted = format_flow_hash(hash_val, FlowSide.RHS_GT_LHS)
        assert str(hash_val) in formatted
        assert "RHS>LHS" in formatted

    def test_calculate_connection_flow_hash(self):
        """Test convenience wrapper for connection flow hash."""
        hash1, side1 = calculate_connection_flow_hash(
            client_ip="192.168.1.100",
            server_ip="10.0.0.1",
            client_port=54321,
            server_port=80,
        )

        # Should produce same result as calculate_flow_hash
        hash2, side2 = calculate_flow_hash(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol=6,
        )

        assert hash1 == hash2
        assert side1 == side2

    def test_hash_value_range(self):
        """Test that hash is a valid 64-bit signed integer."""
        hash_val, _ = calculate_flow_hash(
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol=6,
        )

        # Should be an integer in i64 range
        assert isinstance(hash_val, int)
        assert -(2**63) <= hash_val < 2**63, "Hash should be in signed 64-bit range"

    def test_protocol_affects_hash(self):
        """Test that different protocols produce different hashes."""
        hash1, _ = calculate_flow_hash(
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol=6,  # TCP
        )

        hash2, _ = calculate_flow_hash(
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol=17,  # UDP
        )

        assert hash1 != hash2, "Different protocols should produce different hashes"
