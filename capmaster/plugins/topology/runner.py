"""Execution helpers for the topology plugin."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Sequence

from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.core.connection.matcher import ConnectionMatch
from capmaster.core.connection.models import TcpConnection
from capmaster.core.connection.scorer import MatchScore
from capmaster.core.file_scanner import PcapScanner
from capmaster.plugins.match.quality_analyzer import ConnectionPair, parse_matched_connections
from capmaster.plugins.match.server_detector import ServerDetector
from capmaster.plugins.match.ttl_utils import most_common_hops
from capmaster.plugins.topology.analysis import (
    ServiceTopologyInfo,
    SingleTopologyInfo,
    TopologyAnalyzer,
    TopologyInfo,
    format_single_topology,
    format_topology,
)
from capmaster.utils.errors import CapMasterError, handle_error
from capmaster.utils.meta_writer import write_meta_json

logger = logging.getLogger(__name__)


def run_topology_analysis(
    input_path: str | Path | None = None,
    single_file: Path | None = None,
    file1: Path | None = None,
    file2: Path | None = None,
    matched_connections_file: Path | None = None,
    empty_match_behavior: str = "error",
    output_file: Path | None = None,
    service_list: Path | None = None,
) -> int:
    """Run topology analysis for single-point or dual-point captures."""
    try:
        files = _resolve_input_files(
            single_file=single_file,
            input_path=input_path,
            file1=file1,
            file2=file2,
        )

        if len(files) == 1:
            if matched_connections_file:
                raise CapMasterError(
                    "Matched connections file is not needed for single-file topology analysis.",
                    "Remove --matched-connections or provide two PCAP files.",
                )
            result = _run_single_capture_pipeline(files[0], service_list=service_list)
            output_text = format_single_topology(result)
        else:
            if matched_connections_file is None:
                raise CapMasterError(
                    "Matched connections file is required for dual-file topology analysis.",
                    "Generate it with: capmaster match ... -o matched_connections.txt",
                )
            output_text = _run_dual_capture_pipeline(
                file_a=files[0],
                file_b=files[1],
                matched_file=matched_connections_file,
                service_list=service_list,
                empty_match_behavior=empty_match_behavior,
            )

        _output_results(output_text, output_file)
        return 0

    except Exception as error:  # pragma: no cover - handled via integration
        return handle_error(error, show_traceback=logger.level <= logging.DEBUG)


def _resolve_input_files(
    *,
    single_file: Path | None,
    input_path: str | Path | None,
    file1: Path | None,
    file2: Path | None,
) -> list[Path]:
    """
    Determine which PCAP files to analyze.
    """
    if single_file:
        if input_path or file1 or file2:
            raise CapMasterError(
                "Cannot combine --single-file with other input options.",
                "Provide exactly one input method.",
            )
        return [single_file]

    if input_path is not None and (file1 or file2):
        raise CapMasterError(
            "Cannot combine -i/--input with --file1/--file2.",
            "Provide exactly one input method.",
        )


    if file1 or file2:
        if not (file1 and file2):
            raise CapMasterError(
                "Both --file1 and --file2 must be specified for dual capture analysis.",
                "Provide paths for both capture points.",
            )
        return [file1, file2]

    if input_path is None:
        raise CapMasterError(
            "No input specified.",
            "Use --single-file for single capture or -i/--input for 1-2 files, "
            "or provide --file1/--file2.",
        )

    paths = PcapScanner.parse_input(input_path)
    preserve_order = "," in str(input_path)
    try:
        pcap_files = PcapScanner.scan(paths, recursive=False, preserve_order=preserve_order)
    except FileNotFoundError as exc:
        raise CapMasterError(
            str(exc),
            "Verify that the provided file or directory exists.",
        ) from exc

    if not pcap_files:
        raise CapMasterError(
            "No PCAP files found for topology analysis.",
            "Ensure the input path contains .pcap or .pcapng files.",
        )

    if len(pcap_files) not in (1, 2):
        raise CapMasterError(
            f"Topology plugin supports only 1 or 2 PCAP files, found {len(pcap_files)}.",
            "Limit the directory or comma-separated list to the desired capture points.",
        )

    return pcap_files


def _run_single_capture_pipeline(
    file_path: Path,
    *,
    service_list: Path | None,
) -> SingleTopologyInfo:
    """
    Execute single-capture topology analysis.

    Groups connections by service (server port + protocol) and creates
    separate topology information for each service.
    """
    logger.info(f"Analyzing topology for single capture: {file_path.name}")

    with _progress() as progress:
        extract_task = progress.add_task("[cyan]Extracting connections...", total=1)
        connections = extract_connections_from_pcap(file_path)
        logger.info(f"Found {len(connections)} connections in {file_path.name}")
        progress.update(extract_task, advance=1)

        detector_task = progress.add_task("[yellow]Identifying server roles...", total=1)
        detector = ServerDetector(service_list_path=service_list)
        for connection in connections:
            detector.collect_connection(connection)
        detector.finalize_cardinality()

        # Group connections by service (server_port + protocol)
        from collections import defaultdict

        service_data: dict[tuple[int, int], dict] = defaultdict(
            lambda: {
                "client_ips": set(),
                "server_ips": set(),
                "client_ttls": [],
                "server_ttls": [],
                "count": 0,
            }
        )

        for connection in connections:
            info = detector.detect(connection)
            # Use protocol from connection (6=TCP, 17=UDP)
            protocol = 6  # Assume TCP for now (TcpConnection)
            service_key = (info.server_port, protocol)

            service_data[service_key]["client_ips"].add(info.client_ip)
            service_data[service_key]["server_ips"].add(info.server_ip)
            service_data[service_key]["count"] += 1

            if connection.client_ttl > 0:
                service_data[service_key]["client_ttls"].append(connection.client_ttl)
            if connection.server_ttl > 0:
                service_data[service_key]["server_ttls"].append(connection.server_ttl)

        progress.update(detector_task, advance=1)

    # Build ServiceTopologyInfo for each service
    services = []
    for (server_port, protocol), data in service_data.items():
        services.append(
            ServiceTopologyInfo(
                server_port=server_port,
                protocol=protocol,
                client_ips=data["client_ips"],
                server_ips=data["server_ips"],
                client_hops=most_common_hops(data["client_ttls"]) if data["client_ttls"] else None,
                server_hops=most_common_hops(data["server_ttls"]) if data["server_ttls"] else None,
                connection_count=data["count"],
            )
        )

    # Sort services by port number
    services.sort(key=lambda s: s.server_port)

    return SingleTopologyInfo(
        file_name=file_path.name,
        services=services,
    )


def _run_dual_capture_pipeline(
    *,
    file_a: Path,
    file_b: Path,
    matched_file: Path,
    service_list: Path | None,
    empty_match_behavior: str = "error",
) -> str:
    """Execute dual-capture topology analysis using a matched connections file.

    When ``empty_match_behavior`` is set to ``"fallback-single"`` and no valid
    cross-capture matches can be reconstructed from the matched connections
    file, this function falls back to running single-capture topology analysis
    for each file and combines the results into a single text report.
    """
    logger.info("Analyzing topology for dual capture points")
    logger.info(f"Capture Point A: {file_a}")
    logger.info(f"Capture Point B: {file_b}")

    behavior = empty_match_behavior.lower()

    with _progress() as progress:
        parse_task = progress.add_task("[cyan]Parsing matched connections...", total=1)
        connection_pairs = parse_matched_connections(matched_file)
        if not connection_pairs:
            if behavior == "fallback-single":
                logger.warning(
                    "No valid connection pairs found in matched connections file. "
                    "Falling back to per-capture single-point topology analysis.",
                )
                return _run_dual_single_fallback(file_a, file_b, service_list)
            raise CapMasterError(
                "No valid connection pairs found in matched connections file.",
                "Verify the file was generated with 'capmaster match -o ...'.",
            )
        logger.info(f"Loaded {len(connection_pairs)} connection pairs from {matched_file}")
        progress.update(parse_task, advance=1)

        extract_task = progress.add_task("[cyan]Extracting connections...", total=2)
        connections_a = extract_connections_from_pcap(file_a)
        logger.info(f"Found {len(connections_a)} connections in {file_a.name}")
        progress.update(extract_task, advance=1)
        connections_b = extract_connections_from_pcap(file_b)
        logger.info(f"Found {len(connections_b)} connections in {file_b.name}")
        progress.update(extract_task, advance=1)

        match_task = progress.add_task("[yellow]Rebuilding matches...", total=1)
        matches = _build_matches_from_pairs(connection_pairs, connections_a, connections_b)
        if not matches:
            if behavior == "fallback-single":
                logger.warning(
                    "Could not rebuild any connection matches from the provided file. "
                    "Falling back to per-capture single-point topology analysis.",
                )
                return _run_dual_single_fallback(file_a, file_b, service_list)
            raise CapMasterError(
                "Could not rebuild any connection matches from the provided file.",
                "Ensure the matched_connections file matches the selected PCAP files.",
            )
        logger.info(
            f"Reconstructed {len(matches)} connection matches for topology analysis",
        )
        progress.update(match_task, advance=1)

    analyzer = TopologyAnalyzer(matches, file_a, file_b, service_list=service_list)
    topology = analyzer.analyze()
    return format_topology(topology)


def _run_dual_single_fallback(file_a: Path, file_b: Path, service_list: Path | None) -> str:
    """Run single-capture topology for each file and combine outputs.

    This is used when dual-capture analysis cannot proceed due to the absence
    of any valid cross-capture matches and ``empty_match_behavior`` is set to
    ``"fallback-single"``.
    """
    single_a = _run_single_capture_pipeline(file_a, service_list=service_list)
    single_b = _run_single_capture_pipeline(file_b, service_list=service_list)

    lines = []
    lines.append(
        "No matched connections detected between capture points. "
        "Falling back to per-capture topology analysis.",
    )
    lines.append("")

    lines.append(f"=== Single-capture topology for Capture Point A ({file_a.name}) ===")
    lines.append(format_single_topology(single_a))
    lines.append("")

    lines.append(f"=== Single-capture topology for Capture Point B ({file_b.name}) ===")
    lines.append(format_single_topology(single_b))

    return "\n".join(lines)


def _build_matches_from_pairs(
    pairs: Sequence[ConnectionPair],
    connections_a: Sequence[TcpConnection],
    connections_b: Sequence[TcpConnection],
) -> list[ConnectionMatch]:
    """
    Convert parsed connection pairs into ConnectionMatch objects using stream IDs.
    """
    map_a = {conn.stream_id: conn for conn in connections_a}
    map_b = {conn.stream_id: conn for conn in connections_b}

    matches: list[ConnectionMatch] = []
    missing = 0

    for pair in pairs:
        conn_a = map_a.get(pair.stream_a)
        conn_b = map_b.get(pair.stream_b)
        if not conn_a or not conn_b:
            missing += 1
            continue

        score = MatchScore(
            normalized_score=pair.confidence,
            raw_score=pair.confidence,
            available_weight=1.0,
            ipid_match=True,
            evidence="loaded_from_matched_connections",
        )
        matches.append(ConnectionMatch(conn1=conn_a, conn2=conn_b, score=score))

    if missing:
        logger.warning(
            "Skipped %s connection pairs because their stream IDs were not found in the captures.",
            missing,
        )

    return matches


def _output_results(output_text: str, output_file: Path | None) -> None:
    """
    Print or persist topology output (and meta.json when writing to file).
    """
    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(output_text)
        write_meta_json(
            output_file=output_file,
            command_id="topology",
            source="basic",
        )
        logger.info(f"Topology report written to: {output_file}")
    else:
        print(output_text)

@contextmanager
def _progress() -> Progress:
    """
    Context manager that yields a Progress instance with consistent styling.
    """
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
    )
    with progress as instance:
        yield instance
