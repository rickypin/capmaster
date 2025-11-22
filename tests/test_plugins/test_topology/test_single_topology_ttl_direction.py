from __future__ import annotations

"""Unit tests for single-capture topology TTL direction alignment.

These tests ensure that when ServerDetector decides the true server is on the
"client" side of the original TcpConnection, the single-capture topology
statistics (client_hops/server_hops) follow the corrected client/server
roles rather than the raw connection orientation.
"""

from pathlib import Path

import pytest

from capmaster.core.connection.models import TcpConnection
from capmaster.plugins.topology.runner import _run_single_capture_pipeline


@pytest.mark.unit
def test_single_topology_ttl_direction_swapped(monkeypatch, tmp_path: Path) -> None:
    """TTL direction should follow ServerDetector's corrected server side.

    We construct a TcpConnection where the original server endpoint has TTL=0
    (no data), while the original client endpoint has a positive TTL value.
    The ServerDetector is stubbed to *swap* roles, declaring the original
    client as the true server.

    The single-capture pipeline should:
    - group the connection under the corrected server_port (client_port), and
    - swap client/server TTLs before aggregating, so that the resulting
      ServiceTopologyInfo has non-None server_hops and None client_hops.
    """

    # Prepare a fake pcap path; the real parser will be stubbed out.
    pcap_path = tmp_path / "single.pcap"
    pcap_path.touch()

    # Original orientation: client -> server
    # - server_ttl is 0 (no TTL data on the server side)
    # - client_ttl is 60 (valid TTL sample on the client side)
    connection = TcpConnection(
        stream_id=1,
        protocol=6,
        client_ip="10.0.0.1",
        client_port=50000,
        server_ip="10.0.0.2",
        server_port=80,
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
        client_ttl=60,
        server_ttl=0,
        total_bytes=100,
        has_syn=False,
    )

    # Stub out PCAP extraction to return our single connection.
    monkeypatch.setattr(
        "capmaster.plugins.topology.runner.extract_connections_from_pcap",
        lambda _path: [connection],
    )

    # Stub ServerDetector to swap roles: treat the original client as server.
    class DummyServerInfo:
        def __init__(self) -> None:
            self.server_ip = connection.client_ip
            self.server_port = connection.client_port
            self.client_ip = connection.server_ip
            self.client_port = connection.server_port

    class DummyDetector:
        def __init__(self, *_, **__) -> None:
            self._collected: list[TcpConnection] = []

        def collect_connection(self, conn: TcpConnection) -> None:
            self._collected.append(conn)

        def finalize_cardinality(self) -> None:  # pragma: no cover - no-op
            pass

        def detect(self, conn: TcpConnection) -> DummyServerInfo:  # type: ignore[override]
            assert conn is connection
            return DummyServerInfo()

    monkeypatch.setattr(
        "capmaster.plugins.topology.runner.ServerDetector", DummyDetector
    )

    topology = _run_single_capture_pipeline(pcap_path, service_list=None)

    # We expect exactly one service, keyed by the corrected server_port
    # (the original client_port).
    assert len(topology.services) == 1
    service = topology.services[0]

    assert service.server_port == connection.client_port

    # Because TTLs were swapped before aggregation, the non-zero TTL should be
    # interpreted as a server-side TTL, yielding non-None server_hops, while
    # client_hops should remain None (no positive client TTL samples).
    assert service.client_hops is None
    assert service.server_hops is not None

