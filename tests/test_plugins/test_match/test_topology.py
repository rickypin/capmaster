"""Tests for topology output descriptions."""

from __future__ import annotations

import pytest

from capmaster.plugins.match.topology import TopologyInfo, format_topology


def _make_topology(**overrides) -> TopologyInfo:
    """Create a TopologyInfo instance for tests."""
    base = {
        "file1_name": "capture_a.pcap",
        "file2_name": "capture_b.pcap",
        "client_ips_a": {"10.0.0.1"},
        "client_ips_b": {"10.0.0.2"},
        "server_ips_a": {"20.0.0.1"},
        "server_ips_b": {"20.0.0.2"},
        "server_ports_a": {80},
        "server_ports_b": {80},
        "client_hops_a": 10,
        "server_hops_a": 2,
        "client_hops_b": 8,
        "server_hops_b": 4,
        "position": "A_CLOSER_TO_CLIENT",
    }
    base.update(overrides)
    return TopologyInfo(**base)


@pytest.mark.unit
def test_format_topology_balanced_ba_description():
    """Balanced hops with capture point B closer to the client."""
    topology = _make_topology(
        client_hops_a=23,
        server_hops_a=0,
        client_hops_b=17,
        server_hops_b=6,
        position="A_CLOSER_TO_CLIENT",
    )

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
    topology = _make_topology(
        client_hops_a=17,
        server_hops_a=6,
        client_hops_b=20,
        server_hops_b=3,
        position="B_CLOSER_TO_CLIENT",
    )

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
    topology = _make_topology(
        client_hops_a=0,
        server_hops_a=3,
        client_hops_b=12,
        server_hops_b=0,
        position="A_CLOSER_TO_CLIENT",
    )

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
    topology = _make_topology(position="SAME_POSITION")

    output = format_topology(topology)

    assert "TTL data is insufficient to determine capture point ordering." in output
    assert "Capture Point A observed" in output
    assert "Capture Point B observed" in output
