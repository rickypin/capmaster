"""Unit tests for EndpointStatsCollector server detection integration."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from capmaster.core.connection.matcher import ConnectionMatch
from capmaster.core.connection.models import TcpConnection
from capmaster.plugins.match.endpoint_stats import EndpointStatsCollector
from capmaster.plugins.match.server_detector import ServerInfo


class FakeDetector:
    """Minimal detector that can optionally swap server/client roles.

    This avoids depending on the real ServerDetector heuristics while still
    exercising EndpointStatsCollector's logic that consumes ServerInfo.
    """

    def __init__(self, swap_stream_ids: set[int] | None = None) -> None:
        self.swap_stream_ids = swap_stream_ids or set()

    def collect_connection(self, connection: TcpConnection) -> None:  # pragma: no cover - not used
        return None

    def finalize_cardinality(self) -> None:  # pragma: no cover - not used
        return None

    def detect(self, connection: TcpConnection) -> ServerInfo:
        """Return ServerInfo with or without swapped roles based on stream_id."""
        if connection.stream_id in self.swap_stream_ids:
            # Swap roles: treat original client as server
            return ServerInfo(
                server_ip=connection.client_ip,
                server_port=connection.client_port,
                client_ip=connection.server_ip,
                client_port=connection.server_port,
                confidence="HIGH",
                method="TEST_SWAP",
            )
        # Keep roles as-is
        return ServerInfo(
            server_ip=connection.server_ip,
            server_port=connection.server_port,
            client_ip=connection.client_ip,
            client_port=connection.client_port,
            confidence="HIGH",
            method="TEST_KEEP",
        )


def _make_connection(
    stream_id: int,
    client_ip: str,
    client_port: int,
    server_ip: str,
    server_port: int,
    client_ttl: int,
    server_ttl: int,
) -> TcpConnection:
    """Create a minimal TcpConnection for tests."""
    return TcpConnection(
        stream_id=stream_id,
        protocol=6,
        client_ip=client_ip,
        client_port=client_port,
        server_ip=server_ip,
        server_port=server_port,
        syn_timestamp=0.0,
        syn_options="",
        client_isn=0,
        server_isn=0,
        tcp_timestamp_tsval="",
        tcp_timestamp_tsecr="",
        client_payload_md5="",
        server_payload_md5="",
        length_signature="",
        is_header_only=False,
        ipid_first=0,
        ipid_set=set(),
        client_ipid_set=set(),
        server_ipid_set=set(),
        first_packet_time=0.0,
        last_packet_time=0.0,
        packet_count=1,
        client_ttl=client_ttl,
        server_ttl=server_ttl,
        total_bytes=100,
        has_syn=False,
    )


@pytest.mark.unit
def test_uses_detector_roles_and_swaps_ttls() -> None:
    """When detector swaps roles, stats should follow detector + swap TTLs."""
    detector = FakeDetector(swap_stream_ids={1, 2})
    collector = EndpointStatsCollector(detector)

    conn1 = _make_connection(
        stream_id=1,
        client_ip="10.0.0.1",
        client_port=12345,
        server_ip="10.0.0.2",
        server_port=80,
        client_ttl=50,
        server_ttl=60,
    )
    conn2 = _make_connection(
        stream_id=2,
        client_ip="10.0.0.3",
        client_port=23456,
        server_ip="10.0.0.4",
        server_port=80,
        client_ttl=40,
        server_ttl=70,
    )

    match = ConnectionMatch(conn1=conn1, conn2=conn2, score=SimpleNamespace())
    collector.add_match(match)
    collector.finalize()
    stats = collector.get_stats()

    assert len(stats) == 1
    pair = stats[0]

    # Endpoint tuples should follow detector roles (client/server swapped)
    assert pair.tuple_a.client_ip == conn1.server_ip
    assert pair.tuple_a.server_ip == conn1.client_ip
    assert pair.tuple_a.server_port == conn1.client_port

    assert pair.tuple_b.client_ip == conn2.server_ip
    assert pair.tuple_b.server_ip == conn2.client_ip
    assert pair.tuple_b.server_port == conn2.client_port

    # TTLs should also be swapped to stay aligned with corrected roles
    assert pair.client_ttl_a == 60
    assert pair.server_ttl_a == 50
    assert pair.client_ttl_b == 70
    assert pair.server_ttl_b == 40


@pytest.mark.unit
def test_keeps_roles_and_ttls_when_no_swap() -> None:
    """When detector does not swap, roles and TTLs should be preserved."""
    detector = FakeDetector(swap_stream_ids=set())
    collector = EndpointStatsCollector(detector)

    conn1 = _make_connection(
        stream_id=10,
        client_ip="192.168.0.1",
        client_port=40000,
        server_ip="192.168.0.2",
        server_port=8080,
        client_ttl=55,
        server_ttl=65,
    )
    conn2 = _make_connection(
        stream_id=11,
        client_ip="192.168.0.3",
        client_port=50000,
        server_ip="192.168.0.4",
        server_port=8080,
        client_ttl=45,
        server_ttl=75,
    )

    match = ConnectionMatch(conn1=conn1, conn2=conn2, score=SimpleNamespace())
    collector.add_match(match)
    collector.finalize()
    stats = collector.get_stats()

    assert len(stats) == 1
    pair = stats[0]

    # Roles unchanged
    assert pair.tuple_a.client_ip == conn1.client_ip
    assert pair.tuple_a.server_ip == conn1.server_ip
    assert pair.tuple_a.server_port == conn1.server_port

    assert pair.tuple_b.client_ip == conn2.client_ip
    assert pair.tuple_b.server_ip == conn2.server_ip
    assert pair.tuple_b.server_port == conn2.server_port

    # TTLs unchanged
    assert pair.client_ttl_a == 55
    assert pair.server_ttl_a == 65
    assert pair.client_ttl_b == 45
    assert pair.server_ttl_b == 75

