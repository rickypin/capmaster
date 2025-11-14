from __future__ import annotations

import pytest

from capmaster.core.connection.behavioral_matcher import BehavioralMatcher
from capmaster.core.connection.matcher import BucketStrategy, MatchMode
from capmaster.core.connection.models import TcpConnection


def _conn(**kwargs) -> TcpConnection:
    defaults = dict(
        stream_id=0,
        protocol=6,
        client_ip="1.1.1.1",
        client_port=11111,
        server_ip="2.2.2.2",
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
        client_ttl=0,
        server_ttl=0,
        total_bytes=0,
    )
    defaults.update(kwargs)
    return TcpConnection(**defaults)


@pytest.mark.unit
def test_behavioral_matcher_basic_positive():
    # Side A
    a1 = _conn(
        stream_id=1,
        first_packet_time=100.0,
        last_packet_time=110.0,
        packet_count=6,
        total_bytes=1000,
    )

    # Side B: similar behavior
    b1 = _conn(
        stream_id=101,
        first_packet_time=101.0,
        last_packet_time=111.0,
        packet_count=6,
        total_bytes=1050,
    )

    matcher = BehavioralMatcher(
        bucket_strategy=BucketStrategy.NONE,
        score_threshold=0.60,
        match_mode=MatchMode.ONE_TO_ONE,
    )

    matches = matcher.match([a1], [b1])
    assert len(matches) == 1
    m = matches[0]
    assert m.conn1.stream_id == 1 and m.conn2.stream_id == 101
    assert m.score.normalized_score >= 0.60


@pytest.mark.unit
def test_behavioral_matcher_negative_and_selection():
    # Side A
    a1 = _conn(
        stream_id=1,
        first_packet_time=100.0,
        last_packet_time=110.0,
        packet_count=6,
        total_bytes=1000,
    )

    # Side B: one good, one bad
    b_good = _conn(
        stream_id=201,
        first_packet_time=100.5,
        last_packet_time=110.5,
        packet_count=6,
        total_bytes=980,
    )
    b_bad = _conn(
        stream_id=202,
        first_packet_time=200.0,
        last_packet_time=204.0,
        packet_count=2,
        total_bytes=5000,
    )

    matcher = BehavioralMatcher(
        bucket_strategy=BucketStrategy.NONE,
        score_threshold=0.60,
        match_mode=MatchMode.ONE_TO_ONE,
    )

    matches = matcher.match([a1], [b_good, b_bad])
    assert len(matches) == 1
    assert matches[0].conn2.stream_id == 201

