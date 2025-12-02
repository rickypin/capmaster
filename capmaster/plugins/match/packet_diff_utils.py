"""Helper utilities shared by packet diff execution paths."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from capmaster.plugins.compare_common.flow_hash import calculate_connection_flow_hash
from capmaster.plugins.compare_common.output_formatter import build_report_text
from capmaster.plugins.compare_common.packet_comparator import DiffType
from capmaster.plugins.compare_common.utils import (
    format_tcp_flags_change,
    to_nanoseconds,
)

logger = logging.getLogger(__name__)


def load_matches_from_file(
    match_file: Path,
    baseline_file: Path,
    compare_file: Path,
    baseline_connections: list,
    compare_connections: list,
) -> list:
    """Load matches from a JSON file and validate against current connections."""

    from capmaster.core.connection.match_serializer import MatchSerializer

    matches, metadata = MatchSerializer.load_matches(match_file)

    expected_file1 = str(baseline_file)
    expected_file2 = str(compare_file)
    actual_file1 = metadata.get("file1")
    actual_file2 = metadata.get("file2")

    if (
        Path(actual_file1).name != baseline_file.name
        or Path(actual_file2).name != compare_file.name
    ):
        logger.warning(
            "Match file was created for different files:\n"
            "  Expected: %s, %s\n"
            "  Actual:   %s, %s\n"
            "Proceeding anyway, but results may be incorrect.",
            baseline_file.name,
            compare_file.name,
            Path(actual_file1).name,
            Path(actual_file2).name,
        )

    baseline_map = {conn.stream_id: conn for conn in baseline_connections}
    compare_map = {conn.stream_id: conn for conn in compare_connections}

    valid_matches = []
    invalid_count = 0

    for match in matches:
        stream_id1 = match.conn1.stream_id
        stream_id2 = match.conn2.stream_id

        if stream_id1 not in baseline_map or stream_id2 not in compare_map:
            invalid_count += 1
            logger.debug(
                "Skipping match: stream %s or %s not found in current connections",
                stream_id1,
                stream_id2,
            )
            continue

        valid_matches.append(match)

    if invalid_count > 0:
        logger.warning(
            "Skipped %s matches that don't exist in current connections. Using %s valid matches.",
            invalid_count,
            len(valid_matches),
        )

    if not valid_matches:
        raise ValueError(
            "No valid matches found in match file. The match file may be for different PCAP files."
        )

    return valid_matches


def output_packet_diff_results(
    baseline_file: Path,
    compare_file: Path,
    results: list,
    output_file: Path | None,
    show_flow_hash: bool = False,
    matched_only: bool = False,
    db_connection: str | None = None,
    kase_id: int | None = None,
    pcap_id_mapping: dict[str, int] | None = None,
    quiet: bool = False,
) -> None:
    """Output comparison results with categorized statistics."""

    flow_hash_cache: dict[tuple[str, str, int, int], tuple[int, Any]] = {}

    output_text = build_report_text(
        results=results,
        baseline_file=baseline_file,
        compare_file=compare_file,
        matched_only=matched_only,
        show_flow_hash=show_flow_hash,
        flow_hash_cache=flow_hash_cache,
    )

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(output_text)
        logger.info("Results written to: %s", output_file)

        from capmaster.utils.meta_writer import write_meta_json

        write_meta_json(
            output_file=output_file,
            command_id="packet_differences",
            source="basic",
        )
    elif not quiet:
        print(output_text)

    if db_connection and kase_id is not None:
        write_packet_diff_to_database(
            db_connection,
            kase_id,
            results,
            baseline_file,
            compare_file,
            pcap_id_mapping,
            flow_hash_cache,
        )


def write_packet_diff_to_database(
    db_connection: str,
    kase_id: int,
    results: list,
    baseline_file: Path,
    compare_file: Path,
    pcap_id_mapping: dict[str, int] | None = None,
    flow_hash_cache: dict[tuple[str, str, int, int], tuple[int, Any]] | None = None,
) -> None:
    """Write comparison results to database."""

    from capmaster.plugins.compare.db_writer import DatabaseWriter

    logger.info("Writing results to database (kase_id=%s)...", kase_id)

    if flow_hash_cache is None:
        flow_hash_cache = {}

    try:
        with DatabaseWriter(db_connection, kase_id) as db:
            db.ensure_table_exists()

            if pcap_id_mapping:
                pcap_id = pcap_id_mapping[str(baseline_file)]
                logger.info(
                    "Using pcap_id=%s from file1 (%s)", pcap_id, baseline_file.name
                )
            else:
                pcap_id = 0
                logger.warning("No pcap_id_mapping provided, defaulting to pcap_id=0")

            baseline_stream_groups = {}

            for match, packets_a, packets_b, result in results:
                conn = match.conn1
                cache_key = (
                    conn.client_ip,
                    conn.server_ip,
                    conn.client_port,
                    conn.server_port,
                )
                if cache_key not in flow_hash_cache:
                    flow_hash_cache[cache_key] = calculate_connection_flow_hash(
                        conn.client_ip,
                        conn.server_ip,
                        conn.client_port,
                        conn.server_port,
                    )
                flow_hash, _ = flow_hash_cache[cache_key]

                group_key = (conn.stream_id, flow_hash)

                if group_key not in baseline_stream_groups:
                    baseline_stream_groups[group_key] = {
                        "conn": conn,
                        "flow_hash": flow_hash,
                        "first_time": None,
                        "last_time": None,
                        "tcp_flags_diffs": [],
                        "seq_num_diffs": [],
                    }

                group = baseline_stream_groups[group_key]

                if packets_a:
                    first_timestamp = packets_a[0].timestamp
                    last_timestamp = packets_a[-1].timestamp

                    first_time_ns = to_nanoseconds(first_timestamp)
                    last_time_ns = to_nanoseconds(last_timestamp)

                    if group["first_time"] is None or first_time_ns < group["first_time"]:
                        group["first_time"] = first_time_ns
                    if group["last_time"] is None or last_time_ns > group["last_time"]:
                        group["last_time"] = last_time_ns

                tcp_flags_diffs = [
                    d for d in result.differences if d.diff_type == DiffType.TCP_FLAGS
                ]
                group["tcp_flags_diffs"].extend(tcp_flags_diffs)

                seq_num_diffs = [
                    d for d in result.differences if d.diff_type == DiffType.SEQ_NUM
                ]
                group["seq_num_diffs"].extend(seq_num_diffs)

            batch_records = []

            for group in baseline_stream_groups.values():
                tcp_flags_diffs = group["tcp_flags_diffs"]
                tcp_flags_cnt = len(tcp_flags_diffs)

                tcp_flags_type = None
                tcp_flags_text_list = []
                if tcp_flags_diffs:
                    flags_pairs = {}
                    for diff in tcp_flags_diffs:
                        pair = f"{diff.value_a}→{diff.value_b}"
                        flags_pairs.setdefault(pair, []).append(
                            (diff.frame_a, diff.frame_b)
                        )

                    if flags_pairs:
                        sorted_pairs = sorted(
                            flags_pairs.items(), key=lambda x: len(x[1]), reverse=True
                        )
                        most_common_pair = sorted_pairs[0][0]
                        flags_baseline, flags_compare = most_common_pair.split("→")
                        tcp_flags_type = format_tcp_flags_change(
                            flags_baseline, flags_compare
                        )

                    max_examples = 10
                    for diff in tcp_flags_diffs[:max_examples]:
                        tcp_flags_text_list.append(
                            f"Frame {diff.frame_a}→{diff.frame_b}"
                        )
                    if len(tcp_flags_diffs) > max_examples:
                        tcp_flags_text_list.append(
                            f"... and {len(tcp_flags_diffs) - max_examples} more"
                        )

                tcp_flags_text_string = (
                    "; ".join(tcp_flags_text_list) if tcp_flags_text_list else ""
                )

                seq_num_diffs = group["seq_num_diffs"]
                seq_num_cnt = len(seq_num_diffs)

                seq_num_text_list = []
                if seq_num_diffs:
                    max_examples = 10
                    for diff in seq_num_diffs[:max_examples]:
                        seq_num_text_list.append(
                            f"Frame {diff.frame_a}→{diff.frame_b}: {diff.value_a}→{diff.value_b}"
                        )
                    if len(seq_num_diffs) > max_examples:
                        seq_num_text_list.append(
                            f"... and {len(seq_num_diffs) - max_examples} more"
                        )

                seq_num_text_string = (
                    "; ".join(seq_num_text_list) if seq_num_text_list else ""
                )

                batch_records.append(
                    {
                        "pcap_id": pcap_id,
                        "flow_hash": group["flow_hash"],
                        "first_time": group["first_time"],
                        "last_time": group["last_time"],
                        "tcp_flags_different_cnt": tcp_flags_cnt,
                        "tcp_flags_different_type": tcp_flags_type,
                        "tcp_flags_different_text": tcp_flags_text_string,
                        "seq_num_different_cnt": seq_num_cnt,
                        "seq_num_different_text": seq_num_text_string,
                    }
                )

            db.insert_flow_hash_batch(batch_records)
            db.commit()

            logger.info(
                "Successfully wrote %s records to database (from %s matches)",
                len(baseline_stream_groups),
                len(results),
            )

    except ImportError as e:
        logger.error("Database functionality not available: %s", e)
        logger.error(
            "Install psycopg2-binary to enable database output: pip install psycopg2-binary"
        )
    except Exception as e:  # pragma: no cover
        logger.error("Failed to write to database: %s", e)
        raise
