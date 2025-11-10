"""Integration test for net_area feature with endpoint statistics.

This test simulates the complete flow of writing endpoint statistics to database
with net_area field population based on TTL analysis.
"""

from unittest.mock import Mock, MagicMock, patch
from capmaster.plugins.match.endpoint_stats import EndpointPairStats, EndpointTuple
from capmaster.plugins.match.db_writer import MatchDatabaseWriter


def create_test_endpoint_stats():
    """Create test endpoint statistics with various TTL scenarios."""
    
    stats = []
    
    # Scenario 1: A closer to client, B closer to server
    # Client -> A -> B -> Server
    stats.append(EndpointPairStats(
        tuple_a=EndpointTuple(
            client_ip="10.0.0.1",
            server_ip="10.0.0.2",
            server_port=80,
            protocol=6,
        ),
        tuple_b=EndpointTuple(
            client_ip="10.0.0.1",
            server_ip="10.0.0.2",
            server_port=80,
            protocol=6,
        ),
        count=10,
        confidence="HIGH",
        client_ttl_a=64,
        server_ttl_a=60,
        client_ttl_b=62,
        server_ttl_b=64,
        client_hops_a=0,   # A directly connected to client
        server_hops_a=4,   # A has 4 hops to server
        client_hops_b=2,   # B has 2 hops from client
        server_hops_b=0,   # B directly connected to server
    ))
    
    # Scenario 2: B closer to client, A closer to server
    # Client -> B -> A -> Server
    stats.append(EndpointPairStats(
        tuple_a=EndpointTuple(
            client_ip="10.0.0.3",
            server_ip="10.0.0.4",
            server_port=443,
            protocol=6,
        ),
        tuple_b=EndpointTuple(
            client_ip="10.0.0.3",
            server_ip="10.0.0.4",
            server_port=443,
            protocol=6,
        ),
        count=5,
        confidence="HIGH",
        client_ttl_a=62,
        server_ttl_a=64,
        client_ttl_b=64,
        server_ttl_b=60,
        client_hops_a=2,   # A has 2 hops from client
        server_hops_a=0,   # A directly connected to server
        client_hops_b=0,   # B directly connected to client
        server_hops_b=4,   # B has 4 hops to server
    ))
    
    # Scenario 3: A closer to server
    stats.append(EndpointPairStats(
        tuple_a=EndpointTuple(
            client_ip="10.0.0.5",
            server_ip="10.0.0.6",
            server_port=3306,
            protocol=6,
        ),
        tuple_b=EndpointTuple(
            client_ip="10.0.0.5",
            server_ip="10.0.0.6",
            server_port=3306,
            protocol=6,
        ),
        count=3,
        confidence="MEDIUM",
        client_ttl_a=64,
        server_ttl_a=61,
        client_ttl_b=64,
        server_ttl_b=64,
        client_hops_a=0,   # A directly connected to client
        server_hops_a=3,   # A has 3 hops to server
        client_hops_b=0,   # B directly connected to client
        server_hops_b=0,   # B directly connected to server
    ))
    
    # Scenario 4: Same position
    stats.append(EndpointPairStats(
        tuple_a=EndpointTuple(
            client_ip="10.0.0.7",
            server_ip="10.0.0.8",
            server_port=22,
            protocol=6,
        ),
        tuple_b=EndpointTuple(
            client_ip="10.0.0.7",
            server_ip="10.0.0.8",
            server_port=22,
            protocol=6,
        ),
        count=1,
        confidence="LOW",
        client_ttl_a=64,
        server_ttl_a=64,
        client_ttl_b=64,
        server_ttl_b=64,
        client_hops_a=0,
        server_hops_a=0,
        client_hops_b=0,
        server_hops_b=0,
    ))
    
    return stats


def test_integration():
    """Test the complete integration of net_area feature."""

    print("=" * 80)
    print("Integration Test: net_area Feature with Endpoint Statistics")
    print("=" * 80)

    # Create test data
    endpoint_stats = create_test_endpoint_stats()
    pcap_id_mapping = {
        "file_a.pcap": 0,
        "file_b.pcap": 1,
    }

    # Create database writer
    writer = MatchDatabaseWriter(
        connection_string="postgresql://test:test@localhost:5432/test",
        kase_id=999
    )

    # Mock the connection and cursor
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    writer._conn = mock_conn
    writer._cursor = mock_cursor

    # Track all insert_node calls
    insert_calls = []
    original_insert = writer.insert_node

    def track_insert(*args, **kwargs):
        insert_calls.append(kwargs)
        return original_insert(*args, **kwargs)

    writer.insert_node = track_insert

    # Write endpoint statistics
    print("\nWriting endpoint statistics...")
    records_inserted = writer.write_endpoint_stats(
        endpoint_stats=endpoint_stats,
        pcap_id_mapping=pcap_id_mapping,
        file1_path="file_a.pcap",
        file2_path="file_b.pcap",
    )

    print(f"Total records inserted: {records_inserted}")

    # Verify results
    print("\n" + "=" * 80)
    print("Verification Results")
    print("=" * 80)

    # Group 1: A_CLOSER_TO_CLIENT (Client -> A -> B -> Server)
    print("\nGroup 1: Client -> A -> B -> Server")
    group1_calls = [c for c in insert_calls if c['group_id'] == 1]

    # Find A server and B client nodes
    a_server = next(c for c in group1_calls if c['pcap_id'] == 0 and c['node_type'] == 2)
    b_client = next(c for c in group1_calls if c['pcap_id'] == 1 and c['node_type'] == 1)

    print(f"  A Server net_area: {a_server['net_area']}")
    print(f"  B Client net_area: {b_client['net_area']}")

    assert a_server['net_area'] == [1], f"Expected [1], got {a_server['net_area']}"
    assert b_client['net_area'] == [0], f"Expected [0], got {b_client['net_area']}"
    print("  ✓ PASS")

    # Group 2: B_CLOSER_TO_CLIENT (Client -> B -> A -> Server)
    print("\nGroup 2: Client -> B -> A -> Server")
    group2_calls = [c for c in insert_calls if c['group_id'] == 2]

    b_server = next(c for c in group2_calls if c['pcap_id'] == 1 and c['node_type'] == 2)
    a_client = next(c for c in group2_calls if c['pcap_id'] == 0 and c['node_type'] == 1)

    print(f"  B Server net_area: {b_server['net_area']}")
    print(f"  A Client net_area: {a_client['net_area']}")

    assert b_server['net_area'] == [0], f"Expected [0], got {b_server['net_area']}"
    assert a_client['net_area'] == [1], f"Expected [1], got {a_client['net_area']}"
    print("  ✓ PASS")

    # Group 3: A_CLOSER_TO_SERVER
    print("\nGroup 3: A closer to Server")
    group3_calls = [c for c in insert_calls if c['group_id'] == 3]

    b_client_g3 = next(c for c in group3_calls if c['pcap_id'] == 1 and c['node_type'] == 1)

    print(f"  B Client net_area: {b_client_g3['net_area']}")

    assert b_client_g3['net_area'] == [0], f"Expected [0], got {b_client_g3['net_area']}"
    print("  ✓ PASS")

    # Group 4: SAME_POSITION
    print("\nGroup 4: Same position")
    group4_calls = [c for c in insert_calls if c['group_id'] == 4]

    # All net_area should be empty
    for call in group4_calls:
        if call['node_type'] in [1, 2]:  # Client or Server
            print(f"  {call['node_type']} (pcap_id={call['pcap_id']}) net_area: {call['net_area']}")
            assert call['net_area'] == [], f"Expected [], got {call['net_area']}"

    print("  ✓ PASS")

    # Verify network device nodes have empty net_area
    print("\nNetwork Device Nodes:")
    net_device_calls = [c for c in insert_calls if c['node_type'] in [1001, 1002]]
    for call in net_device_calls:
        print(f"  Group {call['group_id']}, Type {call['node_type']}, net_area: {call['net_area']}")
        assert call['net_area'] == [], f"Network device should have empty net_area"
    print("  ✓ All network devices have empty net_area")

    print("\n" + "=" * 80)
    print("Integration Test PASSED! ✓✓✓")
    print("=" * 80)


if __name__ == "__main__":
    test_integration()

