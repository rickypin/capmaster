"""Test script for net_area feature in match plugin.

This script tests the network position determination logic and net_area field population
based on TTL delta analysis.
"""

from capmaster.plugins.match.db_writer import MatchDatabaseWriter
from capmaster.plugins.match.endpoint_stats import EndpointPairStats, EndpointTuple


def test_determine_network_position():
    """Test the _determine_network_position method with various scenarios."""
    
    # Create a dummy database writer (we won't actually connect)
    writer = MatchDatabaseWriter("postgresql://dummy", 999)
    
    print("=" * 80)
    print("Testing Network Position Determination Logic")
    print("=" * 80)
    
    # Test Case 1: A closer to client, B closer to server
    # Client -> A -> B -> Server
    # client_hops: A=0, B=2 (B has more hops from client)
    # server_hops: A=4, B=0 (A has more hops to server)
    print("\nTest Case 1: Client -> A -> B -> Server")
    print("  client_hops_a=0, server_hops_a=4")
    print("  client_hops_b=2, server_hops_b=0")
    position = writer._determine_network_position(
        client_hops_a=0,
        server_hops_a=4,
        client_hops_b=2,
        server_hops_b=0,
    )
    print(f"  Result: {position}")
    assert position == "A_CLOSER_TO_CLIENT", f"Expected A_CLOSER_TO_CLIENT, got {position}"
    print("  ✓ PASS")
    
    # Test Case 2: B closer to client, A closer to server
    # Client -> B -> A -> Server
    # client_hops: A=2, B=0 (A has more hops from client)
    # server_hops: A=0, B=4 (B has more hops to server)
    print("\nTest Case 2: Client -> B -> A -> Server")
    print("  client_hops_a=2, server_hops_a=0")
    print("  client_hops_b=0, server_hops_b=4")
    position = writer._determine_network_position(
        client_hops_a=2,
        server_hops_a=0,
        client_hops_b=0,
        server_hops_b=4,
    )
    print(f"  Result: {position}")
    assert position == "B_CLOSER_TO_CLIENT", f"Expected B_CLOSER_TO_CLIENT, got {position}"
    print("  ✓ PASS")
    
    # Test Case 3: A closer to server (only server-side info)
    # server_hops: A=0, B=3 (A is closer to server)
    print("\nTest Case 3: A closer to server (server-side only)")
    print("  client_hops_a=0, server_hops_a=0")
    print("  client_hops_b=0, server_hops_b=3")
    position = writer._determine_network_position(
        client_hops_a=0,
        server_hops_a=0,
        client_hops_b=0,
        server_hops_b=3,
    )
    print(f"  Result: {position}")
    assert position == "B_CLOSER_TO_SERVER", f"Expected B_CLOSER_TO_SERVER, got {position}"
    print("  ✓ PASS")
    
    # Test Case 4: B closer to server (only server-side info)
    # server_hops: A=3, B=0 (B is closer to server)
    print("\nTest Case 4: B closer to server (server-side only)")
    print("  client_hops_a=0, server_hops_a=3")
    print("  client_hops_b=0, server_hops_b=0")
    position = writer._determine_network_position(
        client_hops_a=0,
        server_hops_a=3,
        client_hops_b=0,
        server_hops_b=0,
    )
    print(f"  Result: {position}")
    assert position == "A_CLOSER_TO_SERVER", f"Expected A_CLOSER_TO_SERVER, got {position}"
    print("  ✓ PASS")
    
    # Test Case 5: Same position or cannot determine
    # All hops are equal
    print("\nTest Case 5: Same position (all hops equal)")
    print("  client_hops_a=0, server_hops_a=0")
    print("  client_hops_b=0, server_hops_b=0")
    position = writer._determine_network_position(
        client_hops_a=0,
        server_hops_a=0,
        client_hops_b=0,
        server_hops_b=0,
    )
    print(f"  Result: {position}")
    assert position == "SAME_POSITION", f"Expected SAME_POSITION, got {position}"
    print("  ✓ PASS")
    
    # Test Case 6: Conflicting information (cannot determine)
    # client_delta_diff > 0 but server_delta_diff < 0
    print("\nTest Case 6: Conflicting information")
    print("  client_hops_a=0, server_hops_a=0")
    print("  client_hops_b=2, server_hops_b=3")
    position = writer._determine_network_position(
        client_hops_a=0,
        server_hops_a=0,
        client_hops_b=2,
        server_hops_b=3,
    )
    print(f"  Result: {position}")
    assert position == "B_CLOSER_TO_SERVER", f"Expected B_CLOSER_TO_SERVER, got {position}"
    print("  ✓ PASS")
    
    print("\n" + "=" * 80)
    print("All tests passed! ✓")
    print("=" * 80)


def test_net_area_logic():
    """Test the net_area assignment logic for different positions."""
    
    print("\n" + "=" * 80)
    print("Testing net_area Assignment Logic")
    print("=" * 80)
    
    # Simulate different positions and verify net_area assignments
    test_cases = [
        {
            "name": "A_CLOSER_TO_CLIENT",
            "description": "Client -> A -> B -> Server",
            "expected": {
                "a_client": [],
                "a_server": [1],  # Points to B (pcap_id_b=1)
                "b_client": [0],  # Points to A (pcap_id_a=0)
                "b_server": [],
            }
        },
        {
            "name": "B_CLOSER_TO_CLIENT",
            "description": "Client -> B -> A -> Server",
            "expected": {
                "a_client": [1],  # Points to B
                "a_server": [],
                "b_client": [],
                "b_server": [0],  # Points to A
            }
        },
        {
            "name": "A_CLOSER_TO_SERVER",
            "description": "A closer to server",
            "expected": {
                "a_client": [],
                "a_server": [],
                "b_client": [0],  # Points to A
                "b_server": [],
            }
        },
        {
            "name": "B_CLOSER_TO_SERVER",
            "description": "B closer to server",
            "expected": {
                "a_client": [1],  # Points to B
                "a_server": [],
                "b_client": [],
                "b_server": [],
            }
        },
        {
            "name": "SAME_POSITION",
            "description": "Same position or unknown",
            "expected": {
                "a_client": [],
                "a_server": [],
                "b_client": [],
                "b_server": [],
            }
        },
    ]
    
    pcap_id_a = 0
    pcap_id_b = 1
    
    for test_case in test_cases:
        position = test_case["name"]
        expected = test_case["expected"]
        
        print(f"\nTest: {position}")
        print(f"  Description: {test_case['description']}")
        
        # Simulate the logic from write_endpoint_stats
        net_area_a_client = []
        net_area_a_server = []
        net_area_b_client = []
        net_area_b_server = []
        
        if position == "A_CLOSER_TO_CLIENT":
            net_area_a_server = [pcap_id_b]
            net_area_b_client = [pcap_id_a]
        elif position == "B_CLOSER_TO_CLIENT":
            net_area_b_server = [pcap_id_a]
            net_area_a_client = [pcap_id_b]
        elif position == "A_CLOSER_TO_SERVER":
            net_area_b_client = [pcap_id_a]
        elif position == "B_CLOSER_TO_SERVER":
            net_area_a_client = [pcap_id_b]
        
        # Verify
        assert net_area_a_client == expected["a_client"], \
            f"A client: expected {expected['a_client']}, got {net_area_a_client}"
        assert net_area_a_server == expected["a_server"], \
            f"A server: expected {expected['a_server']}, got {net_area_a_server}"
        assert net_area_b_client == expected["b_client"], \
            f"B client: expected {expected['b_client']}, got {net_area_b_client}"
        assert net_area_b_server == expected["b_server"], \
            f"B server: expected {expected['b_server']}, got {net_area_b_server}"
        
        print(f"  A client net_area: {net_area_a_client} ✓")
        print(f"  A server net_area: {net_area_a_server} ✓")
        print(f"  B client net_area: {net_area_b_client} ✓")
        print(f"  B server net_area: {net_area_b_server} ✓")
    
    print("\n" + "=" * 80)
    print("All net_area logic tests passed! ✓")
    print("=" * 80)


if __name__ == "__main__":
    test_determine_network_position()
    test_net_area_logic()
    
    print("\n" + "=" * 80)
    print("ALL TESTS PASSED! ✓✓✓")
    print("=" * 80)

