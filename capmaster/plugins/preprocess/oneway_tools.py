"""Helpers and core logic for one-way TCP connection filtering in the preprocess pipeline.

This module defines the one-way detection algorithm (OneWayDetector) and exposes
helpers that detect one-way stream IDs and filter PCAP files by excluding those
streams.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable
import shutil
from collections.abc import Iterator
from dataclasses import dataclass

from capmaster.core.tshark_wrapper import TsharkWrapper
from capmaster.utils.errors import CapMasterError
from capmaster.utils.logger import get_logger


logger = get_logger(__name__)

MAX_SEQ_ACK = 2**32


@dataclass
class TcpPacketInfo:
    stream_id: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    ack: int
    tcp_len: int


@dataclass
class DirectionStats:
    packet_count: int = 0
    first_ack: int = 0
    last_ack: int = 0
    has_pure_ack: bool = False
    prev_ack: int = 0


@dataclass
class StreamAnalysis:
    stream_id: int
    is_one_way: bool
    active_direction: str
    ack_delta: int
    has_pure_ack: bool


class OneWayDetector:
    def __init__(self, ack_threshold: int = 20) -> None:
        self.ack_threshold = ack_threshold
        self._streams: dict[int, dict[str, DirectionStats]] = {}
        self._stream_first_direction: dict[int, str] = {}

    def add_packet(self, packet: TcpPacketInfo) -> None:
        direction = f"{packet.src_ip}:{packet.src_port}->{packet.dst_ip}:{packet.dst_port}"
        if packet.stream_id not in self._streams:
            self._streams[packet.stream_id] = {}
            self._stream_first_direction[packet.stream_id] = direction
        stream = self._streams[packet.stream_id]
        stats = stream.setdefault(direction, DirectionStats())
        stats.packet_count += 1
        if packet.ack > 0:
            if stats.first_ack == 0:
                stats.first_ack = packet.ack
            stats.last_ack = packet.ack
            if packet.tcp_len == 0 and stats.prev_ack > 0 and packet.ack > stats.prev_ack:
                stats.has_pure_ack = True
            stats.prev_ack = packet.ack

    def analyze(self) -> Iterator[StreamAnalysis]:
        for stream_id, directions in self._streams.items():
            first_dir = self._stream_first_direction[stream_id]
            reverse_dir = self._get_reverse_direction(first_dir)
            fwd = directions.get(first_dir, DirectionStats())
            rev = directions.get(reverse_dir, DirectionStats())
            if fwd.packet_count == 0 and rev.packet_count == 0:
                continue
            if fwd.packet_count > 0 and rev.packet_count == 0:
                active_dir, active_stats = first_dir, fwd
            elif rev.packet_count > 0 and fwd.packet_count == 0:
                active_dir, active_stats = reverse_dir, rev
            else:
                continue
            if active_stats.first_ack == 0 or active_stats.last_ack == 0:
                continue
            ack_delta = self._calculate_ack_delta(active_stats.first_ack, active_stats.last_ack)
            if ack_delta > self.ack_threshold and active_stats.has_pure_ack:
                yield StreamAnalysis(
                    stream_id=stream_id,
                    is_one_way=True,
                    active_direction=active_dir,
                    ack_delta=ack_delta,
                    has_pure_ack=active_stats.has_pure_ack,
                )

    def _get_reverse_direction(self, direction: str) -> str:
        parts = direction.split("->", 1)
        if len(parts) != 2:
            return direction
        return f"{parts[1]}->{parts[0]}"

    def _calculate_ack_delta(self, first_ack: int, last_ack: int) -> int:
        if last_ack >= first_ack:
            return last_ack - first_ack
        return MAX_SEQ_ACK + last_ack - first_ack



def _feed_detector_from_lines(
    detector: OneWayDetector,
    lines: Iterable[str],
    *,
    strip_lines: bool,
    log_invalid_lines: bool,
) -> None:
    """Feed TCP packet lines into a one-way detector.

    The input format matches the ``tshark`` output built by
    :func:`detect_one_way_streams` in this module (the legacy filter plugin
    logic now lives entirely here).
    """

    for raw_line in lines:
        line = raw_line.strip() if strip_lines else raw_line
        if not line:
            continue

        parts = line.split("\t")
        if len(parts) < 7:
            if log_invalid_lines:
                logger.debug("Skipping invalid line: %s", line.strip())
            continue

        try:
            packet = TcpPacketInfo(
                stream_id=int(parts[0]),
                src_ip=parts[1],
                src_port=int(parts[2]),
                dst_ip=parts[3],
                dst_port=int(parts[4]),
                ack=int(parts[5]) if parts[5] else 0,
                tcp_len=int(parts[6]) if parts[6] else 0,
            )
            detector.add_packet(packet)
        except (ValueError, IndexError) as exc:
            if log_invalid_lines:
                logger.debug("Skipping invalid line: %s (%s)", line.strip(), exc)
            continue


def _collect_one_way_stream_ids(
    detector: OneWayDetector,
    *,
    log_analysis: bool,
) -> list[int]:
    """Collect one-way stream IDs from detector analysis."""

    one_way_streams: list[int] = []
    for analysis in detector.analyze():
        if log_analysis:
            logger.info(
                "One-way stream %s: %s, ACK delta=%s",
                analysis.stream_id,
                analysis.active_direction,
                analysis.ack_delta,
            )
        one_way_streams.append(analysis.stream_id)
    return one_way_streams


def detect_one_way_streams(*, input_file: Path, ack_threshold: int) -> list[int]:
    """Detect one-way TCP streams in a PCAP file.

    This mirrors the behaviour of the retired filter plugin's one-way detection but is
    exposed as a pure function for reuse in the preprocess pipeline.
    """

    tshark = TsharkWrapper()

    fields = [
        "tcp.stream",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.ack",
        "tcp.len",
    ]

    args: list[str] = ["-T", "fields", "-E", "separator=\t"]
    for field in fields:
        args.extend(["-e", field])
    args.extend(["-Y", "tcp"])

    logger.debug("Running tshark for one-way detection on %s", input_file)

    try:
        result = tshark.execute(args=args, input_file=input_file)
    except Exception as exc:  # RuntimeError, CalledProcessError, etc.
        raise CapMasterError(
            f"Failed to run tshark for one-way detection on {input_file}",
            "Ensure tshark is installed and the capture file is readable.",
        ) from exc

    detector = OneWayDetector(ack_threshold=ack_threshold)
    lines = (result.stdout or "").splitlines()
    _feed_detector_from_lines(
        detector,
        lines,
        strip_lines=False,
        log_invalid_lines=False,
    )

    return _collect_one_way_stream_ids(detector, log_analysis=False)


def filter_pcap_excluding_streams(
    *,
    input_file: Path,
    output_file: Path,
    exclude_streams: list[int],
) -> None:
    """Filter a PCAP file to exclude specified TCP stream IDs.

    When ``exclude_streams`` is empty, the input file is copied as-is.
    Otherwise, :class:`TsharkWrapper` is used to apply a display filter of
    the form ``tcp.stream != X and tcp.stream != Y`` and write a new PCAP.
    """

    if not exclude_streams:
        logger.debug("No one-way streams for %s; copying file", input_file)
        shutil.copy2(input_file, output_file)
        return

    stream_filters = [f"tcp.stream != {stream_id}" for stream_id in exclude_streams]
    display_filter = " and ".join(stream_filters)

    tshark = TsharkWrapper()
    args = [
        "-Y",
        display_filter,
        "-w",
        str(output_file),
    ]

    logger.debug(
        "Filtering %s -> %s with display filter: %s",
        input_file,
        output_file,
        display_filter,
    )

    try:
        tshark.execute(args=args, input_file=input_file)
    except Exception as exc:
        raise CapMasterError(
            f"Failed to filter {input_file} using tshark",
            "Check tshark installation and available disk space.",
        ) from exc

