"""Comparative analysis execution helpers for the match plugin.

This module contains the heavy-weight logic that was previously implemented
inside MatchPlugin.execute_comparative_analysis.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def run_comparative_analysis(
    input_path: str | Path | None = None,
    file1: Path | None = None,
    file2: Path | None = None,
    analysis_type: str = "service",
    topology_file: Path | None = None,
    matched_connections_file: Path | None = None,
    top_n: int | None = None,
    output_file: Path | None = None,
) -> int:
    """Run comparative analysis between two PCAP files.

    This function contains the heavy-weight implementation that was previously
    in MatchPlugin.execute_comparative_analysis. It keeps behaviour identical
    while allowing plugin.py to remain small.
    """
    from capmaster.plugins.match.quality_analyzer import (
        QualityAnalyzer,
        format_connection_pair_report,
        format_quality_report,
        parse_matched_connections,
        parse_topology_services,
    )
    from capmaster.utils.errors import InsufficientFilesError, handle_error
    from capmaster.core.input_manager import InputManager
    from capmaster.utils.meta_writer import write_meta_json

    try:
        logger.info(f"Starting comparative analysis (type: {analysis_type})...")

        # Parse input to get file1 and file2
        file_args = {1: file1, 2: file2}
        try:
            input_files = InputManager.resolve_inputs(input_path, file_args)
            if input_files:
                InputManager.validate_file_count(input_files, min_files=2, max_files=2)
                file1 = input_files[0].path
                file2 = input_files[1].path
                logger.info("Using files:")
                logger.info(f"  File 1: {file1}")
                logger.info(f"  File 2: {file2}")
        except Exception as e:
            logger.error(str(e))
            return 1

        # Validate that we have both files
        if not file1 or not file2:
            logger.error("Both file1 and file2 must be specified")
            return 1

        analyzer = QualityAnalyzer()
        reports: list[str] = []

        # Service-level analysis
        if analysis_type in ("service", "both"):
            if not topology_file:
                logger.error("Topology file must be specified for service analysis")
                return 1

            # Parse topology file to extract services
            logger.info(f"Parsing topology file: {topology_file}")
            services = parse_topology_services(topology_file)

            if not services:
                logger.error("No services found in topology file")
                return 1

            logger.info(f"Found {len(services)} services to analyze")
            for ip, port in services:
                logger.info(f"  - {ip}:{port}")

            # Analyze quality metrics
            logger.info("Analyzing service-level quality metrics...")
            service_results = analyzer.analyze_service_quality(file1, file2, services)

            # Format report
            service_report = format_quality_report(service_results, file1.name, file2.name)
            reports.append(service_report)

        # Connection-pair analysis
        if analysis_type in ("connections", "both"):
            if not matched_connections_file:
                logger.error(
                    "Matched connections file must be specified for connection pair analysis"
                )
                return 1

            # Parse matched connections file
            logger.info(
                f"Parsing matched connections file: {matched_connections_file}"
            )
            connection_pairs = parse_matched_connections(matched_connections_file)

            if not connection_pairs:
                logger.error("No connection pairs found in matched connections file")
                return 1

            logger.info(f"Found {len(connection_pairs)} connection pairs to analyze")

            # Analyze quality metrics for each connection pair
            logger.info("Analyzing connection-pair quality metrics...")
            pair_results = analyzer.analyze_connection_pairs(file1, file2, connection_pairs)

            # Format report
            pair_report = format_connection_pair_report(
                pair_results, file1.name, file2.name, top_n=top_n
            )
            reports.append(pair_report)

        # Combine reports
        if analysis_type == "both":
            report = "\n\n".join(reports)
        else:
            report = reports[0] if reports else ""

        # Output results
        if output_file:
            logger.info(f"Writing comparative analysis report to: {output_file}")
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report)
            logger.info(f"Comparative analysis report written to: {output_file}")

            # Write meta.json file
            # Determine command_id based on analysis_type
            if analysis_type == "service":
                command_id = "comparative-analysis-service"
            elif analysis_type == "connections":
                command_id = "poor-quality-connections"
            else:  # both
                command_id = "comparative-analysis-both"

            write_meta_json(
                output_file=output_file,
                command_id=command_id,
                source="basic",
            )
        else:
            print(report)

        logger.info("Comparative analysis completed successfully")
        return 0

    except Exception as e:  # pragma: no cover - error paths exercised via integration
        return handle_error(e, show_traceback=True)

