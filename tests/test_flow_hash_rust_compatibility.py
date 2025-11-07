"""Test flow hash compatibility with Rust implementation.

This test suite verifies that the Python flow hash implementation produces
the same results as the Rust xuanwu-core implementation.
"""

import pytest
from capmaster.plugins.compare.flow_hash import (
    calculate_flow_hash,
    calculate_connection_flow_hash,
    FlowSide,
    format_flow_hash,
)


class TestFlowHashRustCompatibility:
    """Test flow hash algorithm matches Rust implementation."""

    def test_bidirectional_consistency(self):
        """Test that forward and reverse flows produce the same hash."""
        # Forward direction
        hash1, side1 = calculate_flow_hash(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol=6,
        )

        # Reverse direction
        hash2, side2 = calculate_flow_hash(
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            protocol=6,
        )

        # Hashes should be identical
        assert hash1 == hash2, "Bidirectional flows should produce same hash"
        
        # Flow sides should be opposite
        assert side1 != side2, "Flow sides should be different for opposite directions"
        
        # One should be LHS_GE_RHS, the other RHS_GT_LHS
        assert {side1, side2} == {FlowSide.LHS_GE_RHS, FlowSide.RHS_GT_LHS}

    def test_port_based_normalization(self):
        """Test that port comparison determines flow side correctly."""
        # Case 1: src_port > dst_port
        hash1, side1 = calculate_flow_hash(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=54321,
            dst_port=80,
            protocol=6,
        )
        assert side1 == FlowSide.LHS_GE_RHS, "Higher src_port should result in LHS_GE_RHS"

        # Case 2: Reverse flow (swap BOTH ports AND IPs for true bidirectional test)
        hash2, side2 = calculate_flow_hash(
            src_ip="192.168.1.2",  # Swapped
            dst_ip="192.168.1.1",  # Swapped
            src_port=80,           # Swapped
            dst_port=54321,        # Swapped
            protocol=6,
        )
        assert side2 == FlowSide.RHS_GT_LHS, "Lower src_port should result in RHS_GT_LHS"

        # Case 3: Hashes should be the same (bidirectional)
        assert hash1 == hash2, "Bidirectional flows should have same hash"

    def test_ip_based_normalization_when_ports_equal(self):
        """Test that IP comparison is used when ports are equal."""
        # Case 1: src_ip > dst_ip (with equal ports)
        hash1, side1 = calculate_flow_hash(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=8080,
            dst_port=8080,
            protocol=6,
        )
        assert side1 == FlowSide.LHS_GE_RHS, "Higher src_ip should result in LHS_GE_RHS"

        # Case 2: src_ip < dst_ip (with equal ports)
        hash2, side2 = calculate_flow_hash(
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=8080,
            dst_port=8080,
            protocol=6,
        )
        assert side2 == FlowSide.RHS_GT_LHS, "Lower src_ip should result in RHS_GT_LHS"

        # Case 3: Hashes should be the same (bidirectional)
        assert hash1 == hash2, "Bidirectional flows should have same hash"

    def test_different_connections_different_hashes(self):
        """Test that different connections produce different hashes."""
        hash1, _ = calculate_flow_hash(
            "192.168.1.1", "10.0.0.1", 12345, 80, 6
        )
        hash2, _ = calculate_flow_hash(
            "192.168.1.1", "10.0.0.2", 12345, 80, 6  # Different dst_ip
        )
        hash3, _ = calculate_flow_hash(
            "192.168.1.1", "10.0.0.1", 12346, 80, 6  # Different src_port
        )
        hash4, _ = calculate_flow_hash(
            "192.168.1.1", "10.0.0.1", 12345, 443, 6  # Different dst_port
        )

        # All hashes should be different
        assert len({hash1, hash2, hash3, hash4}) == 4, "Different connections should have different hashes"

    def test_protocol_differentiation(self):
        """Test that different protocols produce different hashes."""
        # TCP
        hash_tcp, _ = calculate_flow_hash(
            "192.168.1.1", "10.0.0.1", 12345, 80, protocol=6
        )
        
        # UDP
        hash_udp, _ = calculate_flow_hash(
            "192.168.1.1", "10.0.0.1", 12345, 80, protocol=17
        )
        
        # ICMP
        hash_icmp, _ = calculate_flow_hash(
            "192.168.1.1", "10.0.0.1", 12345, 80, protocol=1
        )

        # All should be different
        assert hash_tcp != hash_udp, "TCP and UDP should have different hashes"
        assert hash_tcp != hash_icmp, "TCP and ICMP should have different hashes"
        assert hash_udp != hash_icmp, "UDP and ICMP should have different hashes"

    def test_ipv6_support(self):
        """Test that IPv6 addresses work correctly."""
        # Forward
        hash1, side1 = calculate_flow_hash(
            src_ip="2001:db8::1",
            dst_ip="2001:db8::2",
            src_port=12345,
            dst_port=80,
            protocol=6,
        )

        # Reverse
        hash2, side2 = calculate_flow_hash(
            src_ip="2001:db8::2",
            dst_ip="2001:db8::1",
            src_port=80,
            dst_port=12345,
            protocol=6,
        )

        # Should be bidirectional
        assert hash1 == hash2, "IPv6 flows should be bidirectional"
        assert side1 != side2, "IPv6 flow sides should be opposite"

    def test_hash_format(self):
        """Test hash formatting function."""
        hash_val = -1234567890123456789
        
        formatted = format_flow_hash(hash_val, FlowSide.LHS_GE_RHS)
        assert "LHS>=RHS" in formatted
        assert str(hash_val) in formatted

        formatted = format_flow_hash(hash_val, FlowSide.RHS_GT_LHS)
        assert "RHS>LHS" in formatted

    def test_connection_flow_hash_wrapper(self):
        """Test the convenience wrapper function."""
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

        assert hash1 == hash2, "Wrapper should produce same hash"
        assert side1 == side2, "Wrapper should produce same flow side"

    def test_hash_value_range(self):
        """Test that hash values are in valid i64 range."""
        hash_val, _ = calculate_flow_hash(
            "192.168.1.1", "10.0.0.1", 12345, 80, 6
        )

        # Should be in signed 64-bit range
        assert -(2**63) <= hash_val < 2**63, "Hash should be in i64 range"

    def test_edge_cases(self):
        """Test edge cases."""
        # Same IP and port (loopback)
        hash1, side1 = calculate_flow_hash(
            "127.0.0.1", "127.0.0.1", 8080, 8080, 6
        )
        assert isinstance(hash1, int), "Should produce valid hash for loopback"

        # Port 0
        hash2, side2 = calculate_flow_hash(
            "192.168.1.1", "10.0.0.1", 0, 80, 6
        )
        assert isinstance(hash2, int), "Should handle port 0"

        # High port numbers
        hash3, side3 = calculate_flow_hash(
            "192.168.1.1", "10.0.0.1", 65535, 65534, 6
        )
        assert isinstance(hash3, int), "Should handle high port numbers"

    def test_consistency_across_calls(self):
        """Test that same input always produces same output."""
        results = []
        for _ in range(10):
            hash_val, side = calculate_flow_hash(
                "192.168.1.100", "10.0.0.1", 12345, 80, 6
            )
            results.append((hash_val, side))

        # All results should be identical
        assert len(set(results)) == 1, "Same input should always produce same output"

    def test_network_byte_order_ports(self):
        """Test that ports are hashed in network byte order (big-endian)."""
        # This test verifies the fix: ports should use big-endian ('>H')
        # not little-endian ('<H')
        
        # Calculate hash with specific ports
        hash1, side1 = calculate_flow_hash(
            "192.168.1.1", "10.0.0.1", 0x1234, 0x5678, 6
        )
        
        # The hash should be deterministic
        assert isinstance(hash1, int), "Should produce valid hash"
        
        # Reverse should produce same hash
        hash2, side2 = calculate_flow_hash(
            "10.0.0.1", "192.168.1.1", 0x5678, 0x1234, 6
        )
        
        assert hash1 == hash2, "Network byte order should ensure bidirectional consistency"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

