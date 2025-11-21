"""Tests for topology output descriptions."""

from __future__ import annotations

import pytest

from capmaster.plugins.topology.analysis import (
    ServiceTopologyInfoDual,
    TopologyInfo,
    format_topology,
)


def _make_service(**overrides) -> ServiceTopologyInfoDual:
    """Create a ServiceTopologyInfoDual instance for tests."""
    base = {
        "server_port": 80,
        "protocol": 6,  # TCP
        "client_ips_a": {"10.0.0.1"},
        "client_ips_b": {"10.0.0.2"},
        "server_ips_a": {"20.0.0.1"},
        "server_ips_b": {"20.0.0.2"},
        "client_hops_a": 10,
        "server_hops_a": 2,
        "client_hops_b": 8,
        "server_hops_b": 4,
        "position": "A_CLOSER_TO_CLIENT",
        "connection_count": 10,
    }
    base.update(overrides)
    return ServiceTopologyInfoDual(**base)


def _make_topology(services: list[ServiceTopologyInfoDual] | None = None) -> TopologyInfo:
    """Create a TopologyInfo instance for tests."""
    if services is None:
        services = [_make_service()]
    return TopologyInfo(
        file1_name="capture_a.pcap",
        file2_name="capture_b.pcap",
        services=services,
    )


@pytest.mark.unit
def test_format_topology_balanced_ba_description():
    """Balanced hops with capture point B closer to the client."""
    service = _make_service(
        client_hops_a=23,
        server_hops_a=0,
        client_hops_b=17,
        server_hops_b=6,
        position="A_CLOSER_TO_CLIENT",
    )
    topology = _make_topology(services=[service])

    output = format_topology(topology)

    assert (
        "Capture Point B: Clients 10.0.0.2 -> Servers 20.0.0.2:80, "
        "17 hops away from the client and 6 hops away from the server."
    ) in output
    assert (
        "Capture Point A: Clients 10.0.0.1 -> Servers 20.0.0.1:80, "
        "23 hops away from the client and 0 hops away from the server."
    ) in output


@pytest.mark.unit
def test_format_topology_balanced_ab_description():
    """Balanced hops with capture point A closer to the client."""
    service = _make_service(
        client_hops_a=17,
        server_hops_a=6,
        client_hops_b=20,
        server_hops_b=3,
        position="B_CLOSER_TO_CLIENT",
    )
    topology = _make_topology(services=[service])

    output = format_topology(topology)

    assert (
        "Capture Point A: Clients 10.0.0.1 -> Servers 20.0.0.1:80, "
        "17 hops away from the client and 6 hops away from the server."
    ) in output
    assert (
        "Capture Point B: Clients 10.0.0.2 -> Servers 20.0.0.2:80, "
        "20 hops away from the client and 3 hops away from the server."
    ) in output


@pytest.mark.unit
def test_format_topology_unbalanced_description():
    """Unbalanced hops should reference the intermediate network device."""
    service = _make_service(
        client_hops_a=0,
        server_hops_a=3,
        client_hops_b=12,
        server_hops_b=0,
        position="A_CLOSER_TO_CLIENT",
    )
    topology = _make_topology(services=[service])

    output = format_topology(topology)

    # Capture point B is adjacent to the intermediate device on the client side.
    assert (
        "Capture Point B: Clients 10.0.0.2 -> Servers 20.0.0.2:80, "
        "12 hops away from the client and 0 hops away from the intermediate network device."
        in output
    )

    # Capture point A is adjacent to the intermediate device on the server side.
    assert (
        "Capture Point A: Clients 10.0.0.1 -> Servers 20.0.0.1:80, "
        "0 hops away from the intermediate network device and 3 hops away from the server."
        in output
    )


@pytest.mark.unit
def test_format_topology_unknown_position():
    """Fallback description is used when ordering cannot be determined."""
    # When both capture points observe identical hop counts, TTL data alone
    # cannot determine an ordering, so we fall back to the generic topology
    # description.
    service = _make_service(
        client_hops_a=0,
        server_hops_a=0,
        client_hops_b=0,
        server_hops_b=0,
    )
    topology = _make_topology(services=[service])

    output = format_topology(topology)

    assert "Topology: Cannot determine (same position or insufficient TTL data)" in output
    assert "Capture Point A: Clients" in output
    assert "Capture Point B: Clients" in output



@pytest.mark.unit
def test_format_topology_orders_by_client_hops_and_marks_devices():
    """Capture point closest to the client should come first in the path."""
    service = _make_service(
        # Capture Point A is adjacent to the client, far from the server.
        client_hops_a=0,
        server_hops_a=23,
        # Capture Point B is further from the client and closer to the server.
        client_hops_b=6,
        server_hops_b=17,
        position="A_CLOSER_TO_CLIENT",
    )
    topology = _make_topology(services=[service])

    output = format_topology(topology)

    # Communication path should be Client -> A ->[ND]-> B ->[ND]-> Server.
    assert (
        "Client -> Capture Point A ->[Network Device]-> Capture Point B ->[Network Device]-> Server"
        in output
    )

    # There should be no Network Device marker between the client and Capture Point A
    # because client_hops_a == 0.
    assert "Client ->[Network Device]-> Capture Point A" not in output




@pytest.mark.unit
def test_format_topology_middle_terminating_device_sequence():
    """Opposite zero hops with asymmetric deltas should follow middle-device rule."""
    service = _make_service(
        # Capture Point A: TTL appears to start from a middle device toward the client.
        client_hops_a=0,
        server_hops_a=5,
        # Capture Point B: TTL appears to start from the middle device toward the server.
        client_hops_b=7,
        server_hops_b=0,
    )
    topology = _make_topology(services=[service])

    output = format_topology(topology)

    # According to the middle-device rule, the capture point with zero hops to
    # the server (B) should be on the left, and the one with zero hops to the
    # client (A) should be on the right.
    assert (
        "Client ->[Network Device]-> Capture Point B ->[Network Device]-> Capture Point A ->[Network Device]-> Server"
        in output
    )


@pytest.mark.unit
def test_format_topology_reports_per_file_server_ports_when_different():
    """Per-file summaries should show server IP:port as seen in each capture."""
    service = _make_service(
        server_port=8443,
        client_ips_a={"10.93.137.244"},
        client_ips_b={"104.23.175.191"},
        server_ips_a={"10.93.75.130"},
        server_ips_b={"10.93.136.244"},
        # A sees backend service on 8443, B sees VIP on 443
        server_ports_a={8443},
        server_ports_b={443},
        position="B_CLOSER_TO_CLIENT",
    )
    topology = _make_topology(services=[service])

    output = format_topology(topology)

    assert (
        "Capture Point A: Clients 10.93.137.244 -> Servers 10.93.75.130:8443, "
        "10 hops away from the client and 2 hops away from the server."
    ) in output
    assert (
        "Capture Point B: Clients 104.23.175.191 -> Servers 10.93.136.244:443, "
        "8 hops away from the client and 4 hops away from the server."
    ) in output
    assert "10.93.136.244:8443" not in output


@pytest.mark.unit
def test_format_topology_multiple_services():
    """Multiple services should be displayed separately with a summary."""
    service1 = _make_service(
        server_port=80,
        client_hops_a=10,
        server_hops_a=2,
        client_hops_b=8,
        server_hops_b=4,
        position="A_CLOSER_TO_CLIENT",
        connection_count=100,
    )
    service2 = _make_service(
        server_port=443,
        client_hops_a=12,
        server_hops_a=3,
        client_hops_b=9,
        server_hops_b=5,
        position="A_CLOSER_TO_CLIENT",
        connection_count=50,
    )
    topology = _make_topology(services=[service1, service2])

    output = format_topology(topology)

    # Check that both services are displayed
    assert "=== Service 1: Port 80 (TCP) ===" in output
    assert "=== Service 2: Port 443 (TCP) ===" in output
