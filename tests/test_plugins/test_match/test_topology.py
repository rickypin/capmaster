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
        "There are two capture points between the client and the server, with a network device between them."
        in output
    )
    assert (
        "Capture Point B is closer to the client, located between the client and the intermediate network device, 17 hops away from the client and 6 hops away from the server."
        in output
    )
    assert (
        "Capture Point A is closer to the server, located between the intermediate network device and the server, directly adjacent to the server, 23 hops away from the client and 0 hops away from the server."
        in output
    )


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
        "Capture Point A is closer to the client, located between the client and the intermediate network device, 17 hops away from the client and 6 hops away from the server."
        in output
    )
    assert (
        "Capture Point B is closer to the server, located between the intermediate network device and the server, 20 hops away from the client and 3 hops away from the server."
        in output
    )


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

    assert (
        "Capture Point B is closer to the client, located between the client and the intermediate network device, directly adjacent to the intermediate network device, 12 hops away from the client and 0 hops away from the intermediate network device."
        in output
    )
    assert (
        "Capture Point A is closer to the server, located between the intermediate network device and the server, directly adjacent to the intermediate network device, 0 hops away from the intermediate network device and 3 hops away from the server."
        in output
    )


@pytest.mark.unit
def test_format_topology_unknown_position():
    """Fallback description is used when ordering cannot be determined."""
    service = _make_service(position="SAME_POSITION")
    topology = _make_topology(services=[service])

    output = format_topology(topology)

    assert "Topology: Cannot determine (same position or insufficient TTL data)" in output
    assert "File A: Clients" in output
    assert "File B: Clients" in output


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

    # Check that summary is displayed
    assert "Summary:" in output
    assert "Total services detected: 2" in output
    assert "Service 1 (Port 80 TCP): 100 matched connections" in output
    assert "Service 2 (Port 443 TCP): 50 matched connections" in output
