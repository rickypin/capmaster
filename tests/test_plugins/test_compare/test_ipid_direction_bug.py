"""Test to verify IPID direction confusion bug in packet comparator.

This test demonstrates the critical bug where the packet comparator
incorrectly matches packets from different directions (client->server vs server->client)
based solely on IPID, without considering packet direction.

Bug Description:
- PacketExtractor extracts bidirectional packets (both C->S and S->C)
- TcpPacket dataclass lacks direction information (no src_ip, dst_ip, direction field)
- PacketComparator uses only IPID as matching key, ignoring direction
- Result: Client packets can be incorrectly matched with server packets if they share the same IPID

Expected Behavior:
- Packets should only be matched if they have the same IPID AND same direction
- Client->Server packets should only match with Client->Server packets
- Server->Client packets should only match with Server->Client packets
"""

from __future__ import annotations

from pathlib import Path

import pytest

from capmaster.plugins.compare.packet_comparator import PacketComparator, DiffType
from capmaster.plugins.compare.packet_extractor import PacketExtractor, TcpPacket


@pytest.mark.integration
class TestIPIDDirectionBug:
    """Test cases demonstrating the IPID direction confusion bug."""

    @pytest.fixture
    def comparator(self) -> PacketComparator:
        """Create a PacketComparator instance."""
        return PacketComparator()

    @pytest.fixture
    def extractor(self) -> PacketExtractor:
        """Create a PacketExtractor instance."""
        return PacketExtractor()

    def test_direction_confusion_with_same_ipid(self, comparator: PacketComparator):
        """
        Test that demonstrates the bug: packets from different directions
        with the same IPID are incorrectly matched.

        Scenario:
        - Connection A: Client->Server (IPID=0x1234), Server->Client (IPID=0x5678)
        - Connection B: Client->Server (IPID=0x1234), Server->Client (IPID=0x1234)

        Bug: The comparator will match:
        - A's Client->Server (IPID=0x1234) with B's Client->Server (IPID=0x1234) ✓ CORRECT
        - A's Client->Server (IPID=0x1234) with B's Server->Client (IPID=0x1234) ✗ WRONG!

        The second match is incorrect because they are from different directions.
        """
        # Connection A packets (different IPIDs for each direction)
        packets_a = [
            # Client -> Server: IPID=0x1234, Seq=1000, Ack=0
            TcpPacket(
                frame_number=1,
                ip_id=0x1234,
                tcp_flags="0x002",  # SYN
                seq=1000,
                ack=0,
                timestamp=1000.0,
            ),
            # Server -> Client: IPID=0x5678, Seq=2000, Ack=1001
            TcpPacket(
                frame_number=2,
                ip_id=0x5678,
                tcp_flags="0x012",  # SYN-ACK
                seq=2000,
                ack=1001,
                timestamp=1000.1,
            ),
        ]

        # Connection B packets (same IPID for both directions - this happens in real networks!)
        packets_b = [
            # Client -> Server: IPID=0x1234, Seq=1000, Ack=0
            TcpPacket(
                frame_number=1,
                ip_id=0x1234,
                tcp_flags="0x002",  # SYN
                seq=1000,
                ack=0,
                timestamp=1000.0,
            ),
            # Server -> Client: IPID=0x1234, Seq=2000, Ack=1001 (SAME IPID!)
            TcpPacket(
                frame_number=2,
                ip_id=0x1234,  # Same IPID as client packet!
                tcp_flags="0x012",  # SYN-ACK
                seq=2000,
                ack=1001,
                timestamp=1000.1,
            ),
        ]

        result = comparator.compare(packets_a, packets_b, "test_conn")

        # Current buggy behavior: The comparator will match by IPID only
        # It will find IPID=0x1234 in both A and B
        # For IPID=0x1234, it will compare:
        #   - A's frame 1 (Client->Server) with B's frame 1 (Client->Server) ✓
        #   - A's frame 1 (Client->Server) with B's frame 2 (Server->Client) ✗ BUG!

        # The bug manifests as incorrect comparison results
        # Let's check what differences are reported
        print(f"\n=== IPID Direction Bug Test Results ===")
        print(f"Total differences: {len(result.differences)}")
        for diff in result.differences:
            print(f"  {diff}")

        # Expected behavior (if bug is fixed):
        # - Should only compare packets with same IPID AND same direction
        # - Should report that IPID=0x5678 only exists in A
        # - Should NOT compare A's frame 1 with B's frame 2 (different directions)

        # Current buggy behavior:
        # - Compares A's frame 1 with B's frame 1 (correct)
        # - Compares A's frame 1 with B's frame 2 (WRONG - different directions!)
        # - Reports differences in TCP flags, seq, ack (all wrong because directions differ)

        # This test will FAIL with current implementation, demonstrating the bug
        # When the bug is fixed, this assertion should pass
        ipid_diffs = [d for d in result.differences if d.diff_type == DiffType.IP_ID]
        
        # We expect to see IPID=0x5678 only in A
        assert any(d.value_a == "0x5678" for d in ipid_diffs), \
            "Should report IPID=0x5678 only in A"

    def test_real_world_scenario_with_pcap(
        self, tmp_path: Path, pcap_builder, extractor: PacketExtractor, comparator: PacketComparator
    ):
        """
        Test with real PCAP files to demonstrate the bug in a realistic scenario.

        This test creates two PCAP files with TCP connections where:
        - PCAP A: Client and server use different IPID sequences
        - PCAP B: Client and server happen to use overlapping IPID values

        The bug will cause incorrect matching of packets from different directions.
        """
        # Create PCAP A: Client uses IPID 0x1000-0x1002, Server uses IPID 0x2000-0x2002
        pcap_a = (
            pcap_builder()
            .add_tcp_packet(
                "192.168.1.100", "10.0.0.1", 54321, 80,
                flags=0x02, seq=1000, ack=0, timestamp_sec=1000,
                ip_id=0x1000,  # Client->Server
            )
            .add_tcp_packet(
                "10.0.0.1", "192.168.1.100", 80, 54321,
                flags=0x12, seq=2000, ack=1001, timestamp_sec=1000, timestamp_usec=10000,
                ip_id=0x2000,  # Server->Client
            )
            .add_tcp_packet(
                "192.168.1.100", "10.0.0.1", 54321, 80,
                flags=0x10, seq=1001, ack=2001, timestamp_sec=1000, timestamp_usec=20000,
                ip_id=0x1001,  # Client->Server
            )
            .build(tmp_path / "pcap_a.pcap")
        )

        # Create PCAP B: Both client and server use IPID 0x1000-0x1002 (overlapping!)
        pcap_b = (
            pcap_builder()
            .add_tcp_packet(
                "192.168.1.100", "10.0.0.1", 54321, 80,
                flags=0x02, seq=1000, ack=0, timestamp_sec=1000,
                ip_id=0x1000,  # Client->Server
            )
            .add_tcp_packet(
                "10.0.0.1", "192.168.1.100", 80, 54321,
                flags=0x12, seq=2000, ack=1001, timestamp_sec=1000, timestamp_usec=10000,
                ip_id=0x1000,  # Server->Client (SAME IPID as client!)
            )
            .add_tcp_packet(
                "192.168.1.100", "10.0.0.1", 54321, 80,
                flags=0x10, seq=1001, ack=2001, timestamp_sec=1000, timestamp_usec=20000,
                ip_id=0x1001,  # Client->Server
            )
            .build(tmp_path / "pcap_b.pcap")
        )

        # Extract packets from both PCAPs
        packets_a = extractor.extract_packets(
            pcap_a, "192.168.1.100", 54321, "10.0.0.1", 80
        )
        packets_b = extractor.extract_packets(
            pcap_b, "192.168.1.100", 54321, "10.0.0.1", 80
        )

        print(f"\n=== Extracted Packets ===")
        print(f"PCAP A packets: {len(packets_a)}")
        for pkt in packets_a:
            print(f"  Frame {pkt.frame_number}: IPID={pkt.ip_id:#06x}, Flags={pkt.tcp_flags}, Seq={pkt.seq}, Ack={pkt.ack}")
        print(f"PCAP B packets: {len(packets_b)}")
        for pkt in packets_b:
            print(f"  Frame {pkt.frame_number}: IPID={pkt.ip_id:#06x}, Flags={pkt.tcp_flags}, Seq={pkt.seq}, Ack={pkt.ack}")

        # Compare packets
        result = comparator.compare(packets_a, packets_b, "192.168.1.100:54321 <-> 10.0.0.1:80")

        print(f"\n=== Comparison Results ===")
        print(f"Total differences: {len(result.differences)}")
        for diff in result.differences:
            print(f"  {diff}")

        # The bug will cause incorrect comparisons:
        # - IPID=0x1000 appears in both A and B
        # - A's IPID=0x1000 is frame 1 (Client->Server, SYN)
        # - B's IPID=0x1000 appears in frame 1 (Client->Server, SYN) AND frame 2 (Server->Client, SYN-ACK)
        # - The comparator will incorrectly compare A's frame 1 with B's frame 2

        # Check for the bug: if we see TCP flags differences for IPID=0x1000,
        # it means the comparator is comparing packets from different directions
        flag_diffs = [d for d in result.differences if d.diff_type == DiffType.TCP_FLAGS]
        
        if flag_diffs:
            print(f"\n=== BUG DETECTED ===")
            print(f"Found {len(flag_diffs)} TCP flags differences")
            print("This indicates the comparator is matching packets from different directions!")
            for diff in flag_diffs:
                print(f"  Frame A={diff.frame_a}, Frame B={diff.frame_b}: {diff.value_a} != {diff.value_b}")

    def test_proposed_fix_with_direction_field(self):
        """
        Test demonstrating how the bug should be fixed by adding direction awareness.

        Proposed fix:
        1. Add direction field to TcpPacket (e.g., 'C->S' or 'S->C')
        2. Use (direction, ipid) as the matching key instead of just ipid
        3. Only compare packets with same direction and same IPID

        This test shows the expected behavior after the fix.
        """
        # This is a conceptual test showing what the fix should look like
        # The actual implementation would require modifying TcpPacket dataclass

        # Expected behavior:
        # - Packets should be grouped by (direction, ipid)
        # - Only packets with matching (direction, ipid) should be compared
        # - Packets with same IPID but different directions should NOT be compared

        # Example grouping:
        # A: {('C->S', 0x1234): [pkt1], ('S->C', 0x5678): [pkt2]}
        # B: {('C->S', 0x1234): [pkt1], ('S->C', 0x1234): [pkt2]}
        # 
        # Comparisons:
        # - ('C->S', 0x1234): A[pkt1] vs B[pkt1] ✓
        # - ('S->C', 0x5678): A[pkt2] vs B[nothing] -> report IPID only in A
        # - ('S->C', 0x1234): A[nothing] vs B[pkt2] -> report IPID only in B

        pytest.skip("This test demonstrates the proposed fix - implementation pending")

