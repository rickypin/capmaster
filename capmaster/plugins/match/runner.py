"""Execution helpers for the match plugin.

This module contains the heavy-weight execution pipeline that was previously
implemented inside MatchPlugin.execute and match_connections_in_memory.

Keeping this logic in a dedicated module keeps plugin.py small and focused
on plugin wiring.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)

from capmaster.core.connection.behavioral_matcher import BehavioralMatcher
from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.core.connection.f5_matcher import F5Matcher
from capmaster.core.connection.matcher import BucketStrategy, ConnectionMatch, ConnectionMatcher, MatchMode
from capmaster.core.connection.models import TcpConnection
from capmaster.core.connection.tls_matcher import TlsMatcher
from capmaster.plugins.match.output_formatter import output_match_results, save_matches_json
from capmaster.plugins.match.sampler import ConnectionSampler
from capmaster.plugins.match.server_detector import ServerDetector
from capmaster.plugins.match.strategies import (
    convert_f5_matches_to_connection_matches,
    convert_tls_matches_to_connection_matches,
)
from capmaster.plugins.match.stats_pipeline import (
    aggregate_and_output_service_stats,
    output_endpoint_stats,
    write_to_database,
    write_to_json,
)
from capmaster.utils.errors import CapMasterError, InsufficientFilesError, handle_error
from capmaster.utils.input_parser import DualFileInputParser

logger = logging.getLogger(__name__)


def run_match_pipeline(
    input_path: str | Path | None = None,
    file1: Path | None = None,
    file1_pcapid: int | None = None,
    file2: Path | None = None,
    file2_pcapid: int | None = None,
    output_file: Path | None = None,
    mode: str = "auto",
    bucket_strategy: str = "auto",
    score_threshold: float = 0.60,
    match_mode: str = "one-to-one",
    behavioral_weight_overlap: float = 0.35,
    behavioral_weight_duration: float = 0.25,
    behavioral_weight_iat: float = 0.20,
    behavioral_weight_bytes: float = 0.20,
    endpoint_stats: bool = False,
    endpoint_stats_output: Path | None = None,
    enable_sampling: bool = False,
    sample_threshold: int = 1000,
    sample_rate: float = 0.5,
    db_connection: str | None = None,
    kase_id: int | None = None,
    endpoint_stats_json: Path | None = None,
    merge_by_5tuple: bool = False,
    endpoint_pair_mode: bool = False,
    service_group_mapping: Path | None = None,
    match_json: Path | None = None,
    service_list: Path | None = None,
) -> int:
    """Run the main match pipeline.

    This function is a refactored version of :meth:`MatchPlugin.execute` that
    lives in a standalone module so it can be reused and tested in isolation.
    """

    # Parameter validation (kept identical to MatchPlugin.execute)
    if not 0.0 <= score_threshold <= 1.0:
        logger.error(
            f"Invalid score threshold: {score_threshold}. Must be between 0.0 and 1.0"
        )
        return 1

    if not 0.0 < sample_rate <= 1.0:
        logger.error(f"Invalid sample rate: {sample_rate}. Must be between 0.0 and 1.0")
        return 1

    if sample_threshold <= 0:
        logger.error(f"Invalid sample threshold: {sample_threshold}. Must be positive")
        return 1

    try:
        return _run_match_pipeline_core(
            input_path=input_path,
            file1=file1,
            file1_pcapid=file1_pcapid,
            file2=file2,
            file2_pcapid=file2_pcapid,
            output_file=output_file,
            mode=mode,
            bucket_strategy=bucket_strategy,
            score_threshold=score_threshold,
            match_mode=match_mode,
            behavioral_weight_overlap=behavioral_weight_overlap,
            behavioral_weight_duration=behavioral_weight_duration,
            behavioral_weight_iat=behavioral_weight_iat,
            behavioral_weight_bytes=behavioral_weight_bytes,
            endpoint_stats=endpoint_stats,
            endpoint_stats_output=endpoint_stats_output,
            enable_sampling=enable_sampling,
            sample_threshold=sample_threshold,
            sample_rate=sample_rate,
            db_connection=db_connection,
            kase_id=kase_id,
            endpoint_stats_json=endpoint_stats_json,
            merge_by_5tuple=merge_by_5tuple,
            endpoint_pair_mode=endpoint_pair_mode,
            service_group_mapping=service_group_mapping,
            match_json=match_json,
            service_list=service_list,
        )

    except InsufficientFilesError as e:
        # Expected business error - handle gracefully
        return handle_error(e, show_traceback=False)
    except (OSError, PermissionError) as e:
        # File system errors
        error = CapMasterError(
            f"File system error: {e}",
            "Check file permissions and ensure files are accessible",
        )
        return handle_error(error, show_traceback=logger.level <= logging.DEBUG)
    except RuntimeError as e:
        # Tshark or processing errors
        error = CapMasterError(
            f"Processing error: {e}",
            "Check that PCAP files are valid and tshark is working",
        )
        return handle_error(error, show_traceback=logger.level <= logging.DEBUG)
    except Exception as e:  # pragma: no cover - defensive
        # Unexpected errors - show traceback in debug mode
        return handle_error(e, show_traceback=logger.level <= logging.DEBUG)


def match_connections_in_memory(
    connections1: list[TcpConnection],
    connections2: list[TcpConnection],
    bucket_strategy: str = "auto",
    score_threshold: float = 0.60,
    match_mode: str = "one-to-one",
) -> list[ConnectionMatch]:
    """Match connections in memory with full ServerDetector processing.

    This function mirrors MatchPlugin.match_connections_in_memory but is located in
    a dedicated runner module so it can be reused by other components (e.g.,
    compare plugin) without depending on the plugin class itself).

    Args:
        connections1: Connections from the first PCAP.
        connections2: Connections from the second PCAP.
        bucket_strategy: Bucketing strategy name ("auto", "server", "port", "none").
        score_threshold: Minimum normalized score required to accept a match.
        match_mode: Matching mode string ("one-to-one" or "one-to-many").

    Returns:
        List of matched connection pairs.
    """

    logger.info("Matching connections in memory...")
    logger.info(f"Connections: {len(connections1)} vs {len(connections2)}")

    # Step 1: Improve server detection using cardinality analysis
    logger.info("Performing cardinality analysis for server detection...")

    # Create and populate detector using helper function
    detector = _create_and_populate_detector(connections1, connections2, service_list=None)

    # Re-detect server/client roles with improved detection
    connections1 = _improve_server_detection(connections1, detector)
    connections2 = _improve_server_detection(connections2, detector)
    logger.info("Server detection improved using cardinality analysis")

    # Step 2: Match connections
    logger.info("Matching connections...")
    bucket_enum = BucketStrategy(bucket_strategy)
    match_mode_enum = MatchMode(match_mode)
    matcher = ConnectionMatcher(
        bucket_strategy=bucket_enum,
        score_threshold=score_threshold,
        match_mode=match_mode_enum,
    )

    matches = matcher.match(connections1, connections2)
    logger.info(f"Found {len(matches)} matches")

    return matches


def _create_and_populate_detector(
    connections1: List[TcpConnection],
    connections2: List[TcpConnection],
    service_list: Path | None = None,
) -> ServerDetector:
    """Create a ServerDetector and populate it with connections from both files."""

    detector = ServerDetector(service_list_path=service_list)

    # Collect all connections for cardinality analysis
    for conn in connections1:
        detector.collect_connection(conn)
    for conn in connections2:
        detector.collect_connection(conn)

    # Finalize cardinality analysis
    detector.finalize_cardinality()

    return detector


def _improve_server_detection(
    connections: List[TcpConnection],
    detector: ServerDetector,
) -> List[TcpConnection]:
    """Improve server/client detection using ServerDetector.

    This helper re-detects server/client roles for connections where the
    original detection may be unreliable and rebuilds the IPID sets based on
    the corrected roles. The logic is copied from MatchPlugin._improve_server_detection
    to preserve behaviour exactly.
    """

    improved_connections: List[TcpConnection] = []

    for conn in connections:
        # Detect server using multi-layer approach
        server_info = detector.detect(conn)

        # Check if server/client roles need to be swapped
        needs_swap = (
            server_info.server_ip != conn.server_ip
            or server_info.server_port != conn.server_port
        )

        if needs_swap:
            # Swap server/client roles and rebuild IPID sets
            improved_conn = TcpConnection(
                stream_id=conn.stream_id,
                protocol=conn.protocol,
                client_ip=server_info.client_ip,
                client_port=server_info.client_port,
                server_ip=server_info.server_ip,
                server_port=server_info.server_port,
                syn_timestamp=conn.syn_timestamp,
                syn_options=conn.syn_options,
                has_syn=conn.has_syn,
                client_isn=conn.server_isn,  # Swap ISNs
                server_isn=conn.client_isn,
                tcp_timestamp_tsval=conn.tcp_timestamp_tsval,
                tcp_timestamp_tsecr=conn.tcp_timestamp_tsecr,
                client_payload_md5=conn.server_payload_md5,  # Swap payloads
                server_payload_md5=conn.client_payload_md5,
                length_signature=conn.length_signature,
                is_header_only=conn.is_header_only,
                ipid_set=conn.ipid_set,
                ipid_first=conn.ipid_first,
                client_ipid_set=conn.server_ipid_set,  # Swap IPID sets
                server_ipid_set=conn.client_ipid_set,
                first_packet_time=conn.first_packet_time,
                last_packet_time=conn.last_packet_time,
                packet_count=conn.packet_count,
                client_ttl=conn.server_ttl,  # Swap TTLs
                server_ttl=conn.client_ttl,
                total_bytes=conn.total_bytes,
            )
            improved_connections.append(improved_conn)
            logger.debug(
                f"Swapped server/client for stream {conn.stream_id}: "
                f"{conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port} "
                f"-> {improved_conn.client_ip}:{improved_conn.client_port} <-> "
                f"{improved_conn.server_ip}:{improved_conn.server_port} "
                f"(method: {server_info.method}, confidence: {server_info.confidence})"
            )
        else:
            # No swap needed, keep original connection
            improved_connections.append(conn)

    return improved_connections



def _run_match_pipeline_core(
    input_path: str | Path | None,
    file1: Path | None,
    file1_pcapid: int | None,
    file2: Path | None,
    file2_pcapid: int | None,
    output_file: Path | None,
    mode: str,
    bucket_strategy: str,
    score_threshold: float,
    match_mode: str,
    behavioral_weight_overlap: float,
    behavioral_weight_duration: float,
    behavioral_weight_iat: float,
    behavioral_weight_bytes: float,
    endpoint_stats: bool,
    endpoint_stats_output: Path | None,
    enable_sampling: bool,
    sample_threshold: int,
    sample_rate: float,
    db_connection: str | None,
    kase_id: int | None,
    endpoint_stats_json: Path | None,
    merge_by_5tuple: bool,
    endpoint_pair_mode: bool,
    service_group_mapping: Path | None,
    match_json: Path | None,
    service_list: Path | None,
) -> int:
    """Core implementation of the match pipeline.

    This function mirrors the logic of :meth:`MatchPlugin.execute` but is
    structured as a standalone helper so it can be called from
    :func:`run_match_pipeline`.
    """

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
    ) as progress:
        match_file1, match_file2, pcap_id_mapping = _parse_dual_input(
            progress,
            input_path=input_path,
            file1=file1,
            file2=file2,
            file1_pcapid=file1_pcapid,
            file2_pcapid=file2_pcapid,
        )

        (
            use_f5_matching,
            use_tls_matching,
            use_behavioral,
        ) = _determine_matching_strategy(progress, match_file1, match_file2, mode)

        connections1, connections2 = _extract_connections_for_files(
            progress,
            match_file1,
            match_file2,
            merge_by_5tuple=merge_by_5tuple,
        )

        connections1, connections2 = _apply_sampling_if_enabled(
            progress,
            connections1,
            connections2,
            enable_sampling=enable_sampling,
            sample_threshold=sample_threshold,
            sample_rate=sample_rate,
        )

        matcher, matches = _match_connections_with_strategy(
            progress,
            match_file1,
            match_file2,
            connections1,
            connections2,
            use_f5_matching=use_f5_matching,
            use_tls_matching=use_tls_matching,
            use_behavioral=use_behavioral,
            bucket_strategy=bucket_strategy,
            score_threshold=score_threshold,
            match_mode=match_mode,
            behavioral_weight_overlap=behavioral_weight_overlap,
            behavioral_weight_duration=behavioral_weight_duration,
            behavioral_weight_iat=behavioral_weight_iat,
            behavioral_weight_bytes=behavioral_weight_bytes,
            service_list=service_list,
        )

        stats = matcher.get_match_stats(connections1, connections2, matches)

        _handle_outputs(
            progress,
            matches,
            stats,
            match_file1,
            match_file2,
            pcap_id_mapping,
            output_file=output_file,
            match_json=match_json,
            endpoint_stats=endpoint_stats,
            endpoint_stats_output=endpoint_stats_output,
            db_connection=db_connection,
            kase_id=kase_id,
            endpoint_stats_json=endpoint_stats_json,
            endpoint_pair_mode=endpoint_pair_mode,
            service_group_mapping=service_group_mapping,
            service_list=service_list,
        )

    logger.info("Matching complete")
    return 0


def _parse_dual_input(
    progress: Progress,
    input_path: str | Path | None,
    file1: Path | None,
    file2: Path | None,
    file1_pcapid: int | None,
    file2_pcapid: int | None,
) -> tuple[Path, Path, dict[str, int] | None]:
    """Parse dual file input using DualFileInputParser.

    This mirrors the parsing logic in MatchPlugin.execute.
    """

    scan_task = progress.add_task("[cyan]Scanning for PCAP files...", total=1)

    dual_input = DualFileInputParser.parse(input_path, file1, file2, file1_pcapid, file2_pcapid)
    progress.update(scan_task, advance=1)

    match_file1 = dual_input.file1
    match_file2 = dual_input.file2
    pcap_id_mapping = dual_input.pcap_id_mapping

    logger.info(f"File 1: {match_file1.name}")
    logger.info(f"File 2: {match_file2.name}")
    if pcap_id_mapping:
        logger.info(
            f"PCAP ID mapping: {match_file1.name} -> {pcap_id_mapping[str(match_file1)]}, "
            f"{match_file2.name} -> {pcap_id_mapping[str(match_file2)]}"
        )
    logger.info(f"Matching: {match_file1.name} <-> {match_file2.name}")

    return match_file1, match_file2, pcap_id_mapping


def _determine_matching_strategy(
    progress: Progress,
    match_file1: Path,
    match_file2: Path,
    mode: str,
) -> tuple[bool, bool, bool]:
    """Determine whether to use F5, TLS, behavioral or feature-based matching.

    In non-behavioral modes this performs lightweight header-level detection
    only. The actual matching pipeline may then use F5/TLS/feature in multiple
    stages.
    """

    use_f5_matching = False
    use_tls_matching = False
    use_behavioral = mode.lower() == "behavioral"

    if use_behavioral:
        logger.info("Behavioral-only mode selected - skipping F5/TLS detection")
    else:
        # Check for F5 Ethernet Trailer (highest priority stage)
        detect_task = progress.add_task(
            "[cyan]Detecting F5 Ethernet Trailer...", total=2
        )
        f5_matcher = F5Matcher()

        has_f5_file1 = f5_matcher.detect_f5_trailer(match_file1)
        progress.update(detect_task, advance=1)

        has_f5_file2 = f5_matcher.detect_f5_trailer(match_file2)
        progress.update(detect_task, advance=1)

        use_f5_matching = has_f5_file1 and has_f5_file2

        if use_f5_matching:
            logger.info(
                "F5 Ethernet Trailer detected in both files - enabling F5 matching stage"
            )
        elif has_f5_file1 or has_f5_file2:
            logger.warning(
                f"F5 trailer found in {'file1' if has_f5_file1 else 'file2'} only - "
                "F5-based matching will be disabled for this run"
            )

        # Check for TLS Client Hello independently of F5 so that both stages can run.
        detect_task = progress.add_task(
            "[cyan]Detecting TLS Client Hello...", total=2
        )
        tls_matcher = TlsMatcher()

        has_tls_file1 = tls_matcher.detect_tls_client_hello(match_file1)
        progress.update(detect_task, advance=1)

        has_tls_file2 = tls_matcher.detect_tls_client_hello(match_file2)
        progress.update(detect_task, advance=1)

        use_tls_matching = has_tls_file1 and has_tls_file2

        if use_tls_matching:
            logger.info(
                "TLS Client Hello detected in both files - enabling TLS matching stage"
            )
        elif has_tls_file1 or has_tls_file2:
            logger.warning(
                f"TLS Client Hello found in {'file1' if has_tls_file1 else 'file2'} only - "
                "TLS-based matching will be disabled for this run"
            )

    # Log final matching strategy
    if use_behavioral:
        logger.info("Final matching strategy: Behavioral (behavior-only)")
    else:
        stages = []
        if use_f5_matching:
            stages.append("F5")
        if use_tls_matching:
            stages.append("TLS")
        stages.append("feature-based")
        logger.info("Final matching strategy: " + " + ".join(stages))

    return use_f5_matching, use_tls_matching, use_behavioral



def _extract_connections_for_files(
    progress: Progress,
    match_file1: Path,
    match_file2: Path,
    merge_by_5tuple: bool,
) -> tuple[list[TcpConnection], list[TcpConnection]]:
    """Extract TCP connections from both files.

    This mirrors the extraction logic in MatchPlugin.execute.
    """

    extract_task = progress.add_task("[cyan]Extracting connections...", total=2)

    progress.update(
        extract_task,
        description=f"[cyan]Extracting from {match_file1.name}...",
    )
    connections1 = extract_connections_from_pcap(
        match_file1, merge_by_5tuple=merge_by_5tuple
    )
    logger.info(f"Found {len(connections1)} connections in {match_file1.name}")
    if merge_by_5tuple:
        logger.info("  (merged by direction-independent 5-tuple)")
    progress.update(extract_task, advance=1)

    progress.update(
        extract_task,
        description=f"[cyan]Extracting from {match_file2.name}...",
    )
    connections2 = extract_connections_from_pcap(
        match_file2, merge_by_5tuple=merge_by_5tuple
    )
    logger.info(f"Found {len(connections2)} connections in {match_file2.name}")
    if merge_by_5tuple:
        logger.info("  (merged by direction-independent 5-tuple)")
    progress.update(extract_task, advance=1)

    return connections1, connections2


def _apply_sampling_if_enabled(
    progress: Progress,
    connections1: list[TcpConnection],
    connections2: list[TcpConnection],
    enable_sampling: bool,
    sample_threshold: int,
    sample_rate: float,
) -> tuple[list[TcpConnection], list[TcpConnection]]:
    """Apply sampling to connections if enabled.

    The behaviour matches the sampling logic in MatchPlugin.execute.
    """

    if not enable_sampling:
        logger.info(
            "Sampling disabled (default behavior). Use --enable-sampling to enable."
        )
        return connections1, connections2

    # Validate sampling parameters
    rate = sample_rate
    threshold = sample_threshold
    if rate <= 0.0 or rate > 1.0:
        logger.warning(f"Invalid sample rate {rate}, using default 0.5")
        rate = 0.5

    if threshold < 1:
        logger.warning(f"Invalid sample threshold {threshold}, using default 1000")
        threshold = 1000

    sampler = ConnectionSampler(
        threshold=threshold,
        sample_rate=rate,
    )

    if sampler.should_sample(connections1):
        sample_task = progress.add_task("[yellow]Sampling connections...", total=1)
        logger.info(
            f"Applying sampling to first file (threshold={threshold}, rate={rate})..."
        )
        original_count1 = len(connections1)
        connections1 = sampler.sample(connections1)
        logger.info(
            f"Sampled from {original_count1} to {len(connections1)} connections "
            f"({len(connections1)/original_count1:.1%} retained)"
        )
        progress.update(sample_task, advance=1)

    if sampler.should_sample(connections2):
        sample_task = progress.add_task("[yellow]Sampling connections...", total=1)
        logger.info(
            f"Applying sampling to second file (threshold={threshold}, rate={rate})..."
        )
        original_count2 = len(connections2)
        connections2 = sampler.sample(connections2)
        logger.info(
            f"Sampled from {original_count2} to {len(connections2)} connections "
            f"({len(connections2)/original_count2:.1%} retained)"
        )
        progress.update(sample_task, advance=1)

    return connections1, connections2


def _match_connections_with_strategy(
    progress: Progress,
    match_file1: Path,
    match_file2: Path,
    connections1: list[TcpConnection],
    connections2: list[TcpConnection],
    use_f5_matching: bool,
    use_tls_matching: bool,
    use_behavioral: bool,
    bucket_strategy: str,
    score_threshold: float,
    match_mode: str,
    behavioral_weight_overlap: float,
    behavioral_weight_duration: float,
    behavioral_weight_iat: float,
    behavioral_weight_bytes: float,
    service_list: Path | None = None,
) -> tuple[ConnectionMatcher | BehavioralMatcher, list]:
    """Perform matching using F5, TLS, behavioral or feature-based strategy.

    In non-behavioral modes this runs a multi-stage header/feature pipeline:
    F5 (if available) -> TLS (if available) -> feature/IPID-based matching.
    """

    # Behavioral-only matching keeps its own dedicated path.
    if use_behavioral:
        detector_task = progress.add_task(
            "[yellow]Analyzing server/client roles...", total=1
        )
        logger.info(
            "Performing cardinality analysis for server detection (behavioral mode)..."
        )
        detector = _create_and_populate_detector(
            connections1, connections2, service_list=service_list
        )
        connections1 = _improve_server_detection(connections1, detector)
        connections2 = _improve_server_detection(connections2, detector)
        progress.update(detector_task, advance=1)

        match_task = progress.add_task(
            "[green]Matching connections (behavioral)...", total=1
        )
        logger.info("Matching connections using behavioral features only...")
        bucket_enum = BucketStrategy(bucket_strategy)
        match_mode_enum = MatchMode(match_mode)
        matcher = BehavioralMatcher(
            bucket_strategy=bucket_enum,
            score_threshold=score_threshold,
            match_mode=match_mode_enum,
            weight_overlap=behavioral_weight_overlap,
            weight_duration=behavioral_weight_duration,
            weight_iat=behavioral_weight_iat,
            weight_bytes=behavioral_weight_bytes,
        )
        matches = matcher.match(connections1, connections2)
        logger.info(f"Found {len(matches)} matches (behavioral)")
        progress.update(match_task, advance=1)
        return matcher, matches

    # Helper to remove already matched connections from the candidate pools.
    def _remove_matched(
        remaining1: list[TcpConnection],
        remaining2: list[TcpConnection],
        new_matches: list[ConnectionMatch],
    ) -> tuple[list[TcpConnection], list[TcpConnection]]:
        if not new_matches:
            return remaining1, remaining2
        matched1_ids = {id(m.conn1) for m in new_matches}
        matched2_ids = {id(m.conn2) for m in new_matches}
        remaining1 = [c for c in remaining1 if id(c) not in matched1_ids]
        remaining2 = [c for c in remaining2 if id(c) not in matched2_ids]
        return remaining1, remaining2

    remaining1 = list(connections1)
    remaining2 = list(connections2)
    all_matches: list[ConnectionMatch] = []

    # Stage 1: F5-based matching (if enabled).
    if use_f5_matching:
        match_task = progress.add_task(
            "[green]Matching connections using F5 trailers...", total=1
        )
        logger.info("Matching connections using F5 Ethernet Trailer...")

        f5_matcher = F5Matcher()
        f5_matches = f5_matcher.match(match_file1, match_file2)
        logger.info(f"Found {len(f5_matches)} F5-based matches")

        f5_conn_matches = convert_f5_matches_to_connection_matches(
            f5_matches, remaining1, remaining2
        )
        progress.update(match_task, advance=1)

        if f5_conn_matches:
            logger.info(
                "Converted %d F5-based matches to ConnectionMatch objects",
                len(f5_conn_matches),
            )
        else:
            logger.info("No F5-based matches could be converted to connections")

        all_matches.extend(f5_conn_matches)
        remaining1, remaining2 = _remove_matched(remaining1, remaining2, f5_conn_matches)

    # Stage 2: TLS-based matching on remaining connections (if enabled).
    if use_tls_matching:
        match_task = progress.add_task(
            "[green]Matching connections using TLS Client Hello...", total=1
        )
        logger.info("Matching connections using TLS Client Hello...")

        tls_matcher = TlsMatcher()
        tls_matches = tls_matcher.match(match_file1, match_file2)
        logger.info(f"Found {len(tls_matches)} TLS-based matches")

        tls_conn_matches = convert_tls_matches_to_connection_matches(
            tls_matches, remaining1, remaining2
        )
        progress.update(match_task, advance=1)

        if not tls_conn_matches:
            logger.warning(
                "TLS Client Hello detected in both files but produced 0 "
                "connection-level matches"
            )

        all_matches.extend(tls_conn_matches)
        remaining1, remaining2 = _remove_matched(remaining1, remaining2, tls_conn_matches)

    # Decide whether to run server detection for the feature-based stage.
    # For pure feature-based runs (no F5/TLS), we keep the original behaviour and
    # run server detection. When F5/TLS stages were used, we match the previous
    # fallback behaviour and skip server detection for the remaining subset.
    run_server_detection = not use_f5_matching and not use_tls_matching

    bucket_enum = BucketStrategy(bucket_strategy)
    match_mode_enum = MatchMode(match_mode)
    matcher = ConnectionMatcher(
        bucket_strategy=bucket_enum,
        score_threshold=score_threshold,
        match_mode=match_mode_enum,
    )

    # Stage 3: feature/IPID-based matching on remaining connections.
    if remaining1 and remaining2:
        if run_server_detection:
            detector_task = progress.add_task(
                "[yellow]Analyzing server/client roles...", total=1
            )
            logger.info("Performing cardinality analysis for server detection...")

            detector = _create_and_populate_detector(
                remaining1, remaining2, service_list=service_list
            )
            remaining1 = _improve_server_detection(remaining1, detector)
            remaining2 = _improve_server_detection(remaining2, detector)
            logger.info("Server detection improved using cardinality analysis")
            progress.update(detector_task, advance=1)

        match_task = progress.add_task(
            "[green]Matching connections (feature-based)...", total=1
        )
        logger.info("Matching connections using feature/IPID-based matcher...")
        feature_matches = matcher.match(remaining1, remaining2)
        logger.info(
            "Found %d matches using feature-based matcher", len(feature_matches)
        )
        progress.update(match_task, advance=1)
        all_matches.extend(feature_matches)
    else:
        logger.info(
            "No remaining connections for feature-based matching after F5/TLS stages"
        )

    return matcher, all_matches


def _handle_outputs(
    progress: Progress,
    matches: list,
    stats: dict,
    match_file1: Path,
    match_file2: Path,
    pcap_id_mapping: dict[str, int] | None,
    output_file: Path | None,
    match_json: Path | None,
    endpoint_stats: bool,
    endpoint_stats_output: Path | None,
    db_connection: str | None,
    kase_id: int | None,
    endpoint_stats_json: Path | None,
    endpoint_pair_mode: bool,
    service_group_mapping: Path | None,
    service_list: Path | None,
) -> None:
    """Handle all output steps after matching.

    This includes match results, JSON outputs, endpoint statistics,
    service aggregation, and database/JSON persistence.
    """

    # Output match results
    output_task = progress.add_task("[green]Writing results...", total=1)
    output_match_results(matches, stats, output_file)
    progress.update(output_task, advance=1)

    # Save matches to JSON if requested
    if match_json:
        json_task = progress.add_task("[green]Saving matches to JSON...", total=1)
        save_matches_json(
            matches,
            match_json,
            match_file1,
            match_file2,
            stats,
        )
        progress.update(json_task, advance=1)

    # Generate endpoint statistics if requested
    if not endpoint_stats:
        return

    endpoint_task = progress.add_task(
        "[green]Generating endpoint statistics...", total=1
    )
    endpoint_stats_list = output_endpoint_stats(
        matches,
        match_file1,
        match_file2,
        endpoint_stats_output,
        service_list=service_list,
    )
    progress.update(endpoint_task, advance=1)

    # Aggregate by service by default (unless endpoint_pair_mode is enabled)
    service_stats_list = None
    if not endpoint_pair_mode:
        service_task = progress.add_task("[green]Aggregating by service...", total=1)
        service_stats_list = aggregate_and_output_service_stats(
            endpoint_stats_list,
            match_file1,
            match_file2,
            endpoint_stats_output,
        )
        progress.update(service_task, advance=1)

    # Write to database if connection parameters provided
    if db_connection and kase_id is not None:
        db_task = progress.add_task("[green]Writing to database...", total=1)
        write_to_database(
            db_connection,
            kase_id,
            endpoint_stats_list,
            match_file1,
            match_file2,
            pcap_id_mapping,
            service_stats_list=service_stats_list,
            service_group_mapping_file=service_group_mapping,
        )
        progress.update(db_task, advance=1)

    # Write endpoint statistics to JSON file if requested
    if endpoint_stats_json:
        json_task = progress.add_task("[green]Writing to JSON file...", total=1)
        write_to_json(
            endpoint_stats_json,
            endpoint_stats_list,
            match_file1,
            match_file2,
            pcap_id_mapping,
            service_stats_list=service_stats_list,
            service_group_mapping_file=service_group_mapping,
        )
        progress.update(json_task, advance=1)
