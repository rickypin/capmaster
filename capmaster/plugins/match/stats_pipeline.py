"""Endpoint statistics and persistence helpers for the match plugin.

This module hosts the logic that was previously implemented as private
methods on MatchPlugin (endpoint stats, service aggregation, DB/JSON writes,
and topology output).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from capmaster.plugins.match.endpoint_stats import (
    EndpointStatsCollector,
    ServiceKey,
    aggregate_by_service,
    format_endpoint_stats,
    format_service_stats,
)
from capmaster.plugins.match.server_detector import ServerDetector
from capmaster.plugins.match.topology import TopologyAnalyzer, format_topology
from capmaster.utils.meta_writer import write_meta_json

logger = logging.getLogger(__name__)


def output_endpoint_stats(
    matches: List[object],
    file1: Path,
    file2: Path,
    output_file: Path | None,
    service_list: Path | None = None,
) -> list:
    """Output endpoint statistics for matched connections.

    Args:
        matches: List of ConnectionMatch objects
        file1: Path to first PCAP file
        file2: Path to second PCAP file
        output_file: Output file for statistics (None for stdout)

    Returns:
        List of EndpointPairStats objects
    """
    # Create detector and collector
    detector = ServerDetector(service_list_path=service_list)
    collector = EndpointStatsCollector(detector)

    # Collect statistics from matches
    for match in matches:
        collector.add_match(match)

    # Finalize collection (performs cardinality analysis)
    collector.finalize()

    # Get aggregated statistics
    stats = collector.get_stats()

    # Format output (use detailed format)
    output_text = format_endpoint_stats(
        stats,
        file1_name=file1.name,
        file2_name=file2.name,
    )

    # Write output
    if output_file:
        # Ensure parent directory exists
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(output_text)
        logger.info(f"Endpoint statistics written to: {output_file}")
    else:
        print(output_text)

    # Return stats for database writing
    return stats


def output_topology(
    matches: List[object],
    file1: Path,
    file2: Path,
    output_file: Path | None = None,
    service_list: Path | None = None,
) -> None:
    """Output network topology analysis for matched connections.

    Args:
        matches: List of ConnectionMatch objects
        file1: Path to first PCAP file
        file2: Path to second PCAP file
        output_file: Optional output file path (None for stdout)
    """
    # Analyze topology
    analyzer = TopologyAnalyzer(matches, file1, file2, service_list=service_list)
    topology_info = analyzer.analyze()

    # Format and output
    output_text = format_topology(topology_info)

    if output_file:
        # Ensure parent directory exists
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(output_text)
        logger.info(f"Topology analysis written to: {output_file}")

        # Write meta.json file
        write_meta_json(
            output_file=output_file,
            command_id="topology",
            source="basic",
        )
    else:
        print(output_text)


def aggregate_and_output_service_stats(
    endpoint_stats_list: list,
    file1: Path,
    file2: Path,
    output_file: Path | None,
) -> list:
    """Aggregate endpoint statistics by service and output.

    Args:
        endpoint_stats_list: List of EndpointPairStats objects
        file1: Path to first PCAP file
        file2: Path to second PCAP file
        output_file: Output file for statistics (None for stdout)

    Returns:
        List of ServiceStats objects
    """

    # Aggregate by service
    service_stats = aggregate_by_service(endpoint_stats_list)

    # Format output
    output_text = format_service_stats(
        service_stats,
        file1_name=file1.name,
        file2_name=file2.name,
    )

    # Write output
    if output_file:
        # Append to existing file or create new one
        with output_file.open("a") as f:
            f.write("\n\n")
            f.write(output_text)
        logger.info(f"Service statistics appended to: {output_file}")
    else:
        print("\n")
        print(output_text)

    return service_stats


def load_service_group_mapping(mapping_file: Path) -> dict[ServiceKey, int]:
    """Load service to group ID mapping from JSON file.

    Args:
        mapping_file: Path to JSON file with mapping

    Returns:
        Dictionary mapping ServiceKey to group_id

    Raises:
        ValueError: If JSON file is invalid
    """

    try:
        with mapping_file.open("r") as f:
            port_to_group = json.load(f)

        # Convert port strings to ServiceKey objects
        # Assume TCP (protocol 6) by default
        service_to_group: dict[ServiceKey, int] = {}
        for port_str, group_id in port_to_group.items():
            port = int(port_str)
            service_key = ServiceKey(server_port=port, protocol=6)
            service_to_group[service_key] = int(group_id)

        logger.info(f"Loaded service group mapping from {mapping_file}")
        logger.info(f"  Mappings: {len(service_to_group)} services")

        return service_to_group

    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Invalid service group mapping file: {e}") from e


def write_to_database(
    db_connection: str,
    kase_id: int,
    endpoint_stats: list,
    file1: Path,
    file2: Path,
    pcap_id_mapping: dict[str, int] | None = None,
    service_stats_list: list | None = None,
    service_group_mapping_file: Path | None = None,
) -> None:
    """Write endpoint statistics to database.

    Args:
        db_connection: Database connection string
        kase_id: Case ID for table name
        endpoint_stats: List of EndpointPairStats objects
        file1: Path to first PCAP file
        file2: Path to second PCAP file
        pcap_id_mapping: Mapping from file path to pcap_id (optional)
        service_stats_list: List of ServiceStats objects (optional, for service aggregation)
        service_group_mapping_file: JSON file with service to group mapping (optional)
    """
    from capmaster.plugins.match.db_writer import MatchDatabaseWriter

    # Skip database operations if no endpoint pairs or service stats were matched
    if not endpoint_stats and not service_stats_list:
        logger.warning(
            "No endpoint pairs found in match results. "
            "Skipping database write operation to preserve existing data."
        )
        return

    logger.info(f"Writing statistics to database (kase_id={kase_id})...")

    try:
        with MatchDatabaseWriter(db_connection, kase_id) as db:
            # Ensure table exists (create if not exists)
            db.ensure_table_exists()

            # Clear existing data from table before writing new data
            db.clear_table_data()

            # Write service statistics if available
            if service_stats_list:
                # Load service group mapping if provided
                service_to_group_mapping = None
                if service_group_mapping_file:
                    service_to_group_mapping = load_service_group_mapping(
                        service_group_mapping_file
                    )

                records_inserted = db.write_service_stats(
                    service_stats=service_stats_list,
                    pcap_id_mapping=pcap_id_mapping or {},
                    file1_path=str(file1),
                    file2_path=str(file2),
                    service_to_group_mapping=service_to_group_mapping,
                )
            else:
                # Write endpoint statistics (original behavior)
                records_inserted = db.write_endpoint_stats(
                    endpoint_stats=endpoint_stats,
                    pcap_id_mapping=pcap_id_mapping or {},
                    file1_path=str(file1),
                    file2_path=str(file2),
                )

            # Commit all inserts
            db.commit()

            logger.info(f"Successfully wrote {records_inserted} records to database")

    except ImportError as e:
        logger.error(f"Database functionality not available: {e}")
        logger.error(
            "Install psycopg2-binary to enable database output: pip install psycopg2-binary"
        )
    except Exception as e:
        logger.error(f"Failed to write to database: {e}")
        raise


def write_to_json(
    output_file: Path,
    endpoint_stats: list,
    file1: Path,
    file2: Path,
    pcap_id_mapping: dict[str, int] | None = None,
    service_stats_list: list | None = None,
    service_group_mapping_file: Path | None = None,
) -> None:
    """Write endpoint statistics to JSON file.

    Args:
        output_file: Path to output JSON file
        endpoint_stats: List of EndpointPairStats objects
        file1: Path to first PCAP file
        file2: Path to second PCAP file
        pcap_id_mapping: Mapping from file path to pcap_id (optional)
        service_stats_list: List of ServiceStats objects (optional, for service aggregation)
        service_group_mapping_file: JSON file with service to group mapping (optional)
    """
    from capmaster.plugins.match.db_writer import MatchDatabaseWriter

    # Skip JSON write if no endpoint pairs or service stats were matched
    if not endpoint_stats and not service_stats_list:
        logger.warning(
            "No endpoint pairs found in match results. " "Skipping JSON file write operation."
        )
        return

    logger.info(f"Writing statistics to JSON file: {output_file}")

    try:
        # Write service statistics if available
        if service_stats_list:
            # Load service group mapping if provided
            service_to_group_mapping = None
            if service_group_mapping_file:
                service_to_group_mapping = load_service_group_mapping(
                    service_group_mapping_file
                )

            records_written = MatchDatabaseWriter.write_service_stats_to_json(
                service_stats=service_stats_list,
                pcap_id_mapping=pcap_id_mapping or {},
                file1_path=str(file1),
                file2_path=str(file2),
                output_file=output_file,
                service_to_group_mapping=service_to_group_mapping,
            )
        else:
            # Write endpoint statistics (original behavior)
            records_written = MatchDatabaseWriter.write_endpoint_stats_to_json(
                endpoint_stats=endpoint_stats,
                pcap_id_mapping=pcap_id_mapping or {},
                file1_path=str(file1),
                file2_path=str(file2),
                output_file=output_file,
            )

        logger.info(f"Successfully wrote {records_written} records to {output_file}")

    except Exception as e:
        logger.error(f"Failed to write to JSON file: {e}")
        raise

