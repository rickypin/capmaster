"""Packet diff execution helpers shared by compare and comparative-analysis."""

from __future__ import annotations

from contextlib import nullcontext
import logging
from pathlib import Path
from typing import Any

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)

from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.core.input_manager import InputManager
from capmaster.plugins.compare_common.packet_comparator import PacketComparator
from capmaster.plugins.compare_common.packet_extractor import PacketExtractor
from capmaster.plugins.match.packet_diff_utils import (
    load_matches_from_file,
    output_packet_diff_results,
)
from capmaster.plugins.match.runner import match_connections_in_memory as run_match_in_memory
from capmaster.utils.errors import (
    CapMasterError,
    InsufficientFilesError,
    handle_error,
)

logger = logging.getLogger(__name__)


def execute_packet_diff(
    input_path: str | None = None,
    file1: Path | None = None,
    file2: Path | None = None,
    file3: Path | None = None,
    file4: Path | None = None,
    file5: Path | None = None,
    file6: Path | None = None,
    allow_no_input: bool = False,
    strict: bool = False,
    quiet: bool = False,
    output_file: Path | None = None,
    score_threshold: float = 0.60,
    bucket_strategy: str = "auto",
    show_flow_hash: bool = False,
    matched_only: bool = False,
    db_connection: str | None = None,
    kase_id: int | None = None,
    match_mode: str = "one-to-one",
    match_file: Path | None = None,
) -> int:
    """Execute packet-level comparison between two PCAP files."""

    del strict  # Reserved for future behaviour parity

    try:
        file_args = {1: file1, 2: file2, 3: file3, 4: file4, 5: file5, 6: file6}
        input_files = InputManager.resolve_inputs(input_path, file_args)

        InputManager.validate_file_count(
            input_files,
            min_files=2,
            max_files=2,
            allow_no_input=allow_no_input,
        )

        baseline_file = input_files[0].path
        compare_file = input_files[1].path
        pcap_id_mapping = {
            str(baseline_file): input_files[0].pcapid,
            str(compare_file): input_files[1].pcapid,
        }

        effective_quiet = quiet

        logger.info("Starting packet diff comparison...")
        logger.info(f"Baseline file: {baseline_file.name}")
        logger.info(f"Compare file: {compare_file.name}")
        logger.info(
            "Comparison direction: %s relative to %s",
            compare_file.name,
            baseline_file.name,
        )
        if pcap_id_mapping:
            logger.info(
                "PCAP ID mapping: %s -> %s, %s -> %s",
                baseline_file.name,
                pcap_id_mapping[str(baseline_file)],
                compare_file.name,
                pcap_id_mapping[str(compare_file)],
            )

        progress_context = (
            nullcontext()
            if effective_quiet
            else Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
            )
        )

        with progress_context as progress:
            extract_task = (
                progress.add_task("[cyan]Extracting connections...", total=2)
                if not effective_quiet
                else None
            )

            baseline_connections = extract_connections_from_pcap(baseline_file)
            logger.info(
                "Found %s connections in %s",
                len(baseline_connections),
                baseline_file.name,
            )
            if not effective_quiet:
                progress.update(extract_task, advance=1)

            compare_connections = extract_connections_from_pcap(compare_file)
            logger.info(
                "Found %s connections in %s",
                len(compare_connections),
                compare_file.name,
            )
            if not effective_quiet:
                progress.update(extract_task, advance=1)

            match_task = (
                progress.add_task("[yellow]Matching connections...", total=1)
                if not effective_quiet
                else None
            )

            if match_file:
                matches = load_matches_from_file(
                    match_file,
                    baseline_file,
                    compare_file,
                    baseline_connections,
                    compare_connections,
                )
                logger.info("Loaded %s matches from %s", len(matches), match_file)
            else:
                matches = run_match_in_memory(
                    baseline_connections,
                    compare_connections,
                    bucket_strategy=bucket_strategy,
                    score_threshold=score_threshold,
                    match_mode=match_mode,
                )
                logger.info("Found %s matched connection pairs", len(matches))

            if not effective_quiet:
                progress.update(match_task, advance=1)

            if not matches:
                logger.warning("No matching connections found")
                return 0

            compare_task = (
                progress.add_task(
                    "[green]Comparing packets...",
                    total=len(matches),
                )
                if not effective_quiet
                else None
            )

            extractor = PacketExtractor()
            comparator = PacketComparator()
            results = []

            baseline_stream_ids = [match.conn1.stream_id for match in matches]
            compare_stream_ids = [match.conn2.stream_id for match in matches]

            baseline_packets_by_stream = extractor.extract_multiple_streams(
                baseline_file,
                baseline_stream_ids,
            )
            compare_packets_by_stream = extractor.extract_multiple_streams(
                compare_file,
                compare_stream_ids,
            )

            for match in matches:
                baseline_packets = baseline_packets_by_stream.get(
                    match.conn1.stream_id, []
                )
                compare_packets = compare_packets_by_stream.get(
                    match.conn2.stream_id, []
                )

                conn_id = (
                    f"{match.conn1.client_ip}:{match.conn1.client_port} <-> "
                    f"{match.conn1.server_ip}:{match.conn1.server_port}"
                )

                result = comparator.compare(
                    baseline_packets,
                    compare_packets,
                    conn_id,
                    matched_only,
                )
                results.append((match, baseline_packets, compare_packets, result))

                if not effective_quiet:
                    progress.update(compare_task, advance=1)

            output_task = (
                progress.add_task("[blue]Writing results...", total=1)
                if not effective_quiet
                else None
            )
            output_packet_diff_results(
                baseline_file=baseline_file,
                compare_file=compare_file,
                results=results,
                output_file=output_file,
                show_flow_hash=show_flow_hash,
                matched_only=matched_only,
                db_connection=db_connection,
                kase_id=kase_id,
                pcap_id_mapping=pcap_id_mapping,
                quiet=effective_quiet,
            )

            if not effective_quiet:
                progress.update(output_task, advance=1)

        logger.info("Comparison complete")
        return 0

    except InsufficientFilesError as e:
        return handle_error(e, show_traceback=False)
    except ImportError as e:
        error = CapMasterError(
            f"Missing dependency: {e}",
            "Install database support with: pip install capmaster[database]",
        )
        return handle_error(error, show_traceback=False)
    except (OSError, PermissionError) as e:
        error = CapMasterError(
            f"File system error: {e}",
            "Check file permissions and ensure files are accessible",
        )
        return handle_error(error, show_traceback=logger.level <= logging.DEBUG)
    except RuntimeError as e:
        error = CapMasterError(
            f"Processing error: {e}",
            "Check that PCAP files are valid and tshark is working",
        )
        return handle_error(error, show_traceback=logger.level <= logging.DEBUG)
    except Exception as e:
        return handle_error(e, show_traceback=logger.level <= logging.DEBUG)
