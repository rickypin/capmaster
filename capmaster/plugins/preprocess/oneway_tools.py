"""Helpers for one-way TCP connection filtering in the preprocess pipeline.

This module reuses the detection logic from ``capmaster.plugins.filter``
by feeding TCP packet information into :class:`OneWayDetector`. It exposes
simple helpers that detect one-way stream IDs and filter PCAP files by
excluding those streams.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable
import shutil

from capmaster.core.tshark_wrapper import TsharkWrapper
from capmaster.plugins.filter.detector import OneWayDetector, TcpPacketInfo
from capmaster.utils.errors import CapMasterError
from capmaster.utils.logger import get_logger


logger = get_logger(__name__)


def _feed_detector_from_lines(
    detector: OneWayDetector,
    lines: Iterable[str],
    *,
    strip_lines: bool,
    log_invalid_lines: bool,
) -> None:
    """Feed TCP packet lines into a one-way detector.

    The input format matches the ``tshark`` output built by
    :func:`detect_one_way_streams` in this module and in the filter plugin.
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

    This mirrors the behaviour of the filter plugin's one-way detection but is
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

