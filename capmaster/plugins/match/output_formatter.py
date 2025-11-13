"""Output formatting utilities for match plugin results."""
from __future__ import annotations

import logging
from pathlib import Path

from capmaster.utils.meta_writer import write_meta_json

logger = logging.getLogger(__name__)


def output_match_results(matches: list, stats: dict, output_file: Path | None) -> None:
    """Render match results as a markdown-like table and write to file/stdout."""
    lines: list[str] = []

    # Markdown title
    lines.append("## TCP Connection Matching Results")
    lines.append("")

    # Statistics section in code block
    lines.append("```text")
    lines.append("Statistics:")
    lines.append(f"  Total connections (file 1): {stats['total_connections_1']}")
    lines.append(f"  Total connections (file 2): {stats['total_connections_2']}")
    lines.append(f"  Matched pairs: {stats['matched_pairs']}")
    lines.append(f"  Unmatched (file 1): {stats['unmatched_1']}")
    lines.append(f"  Unmatched (file 2): {stats['unmatched_2']}")
    lines.append(f"  Match rate (file 1): {stats['match_rate_1']:.1%}")
    lines.append(f"  Match rate (file 2): {stats['match_rate_2']:.1%}")
    lines.append(f"  Average score: {stats['average_score']:.2f}")
    lines.append("")

    # Matched Connections Table
    lines.append("Matched Connections:")
    lines.append("-" * 180)

    # Table header
    header = (
        f"{'No.':<6} "
        f"{'Stream A':<10} "
        f"{'Client A':<22} "
        f"{'Server A':<22} "
        f"{'Stream B':<10} "
        f"{'Client B':<22} "
        f"{'Server B':<22} "
        f"{'Conf':<6} "
        f"{'Evidence':<40}"
    )
    lines.append(header)
    lines.append("-" * 180)

    # Table rows
    for i, match in enumerate(matches, 1):
        client_a = f"{match.conn1.client_ip}:{match.conn1.client_port}"
        server_a = f"{match.conn1.server_ip}:{match.conn1.server_port}"
        client_b = f"{match.conn2.client_ip}:{match.conn2.client_port}"
        server_b = f"{match.conn2.server_ip}:{match.conn2.server_port}"

        # Truncate evidence if too long
        evidence = match.score.evidence
        if len(evidence) > 40:
            evidence = evidence[:37] + "..."

        row = (
            f"{i:<6} "
            f"{match.conn1.stream_id:<10} "
            f"{client_a:<22} "
            f"{server_a:<22} "
            f"{match.conn2.stream_id:<10} "
            f"{client_b:<22} "
            f"{server_b:<22} "
            f"{match.score.normalized_score:<6.2f} "
            f"{evidence:<40}"
        )
        lines.append(row)

    lines.append("-" * 180)
    lines.append(f"Total: {len(matches)} matched pairs")
    lines.append("```")

    # Write output
    output_text = "\n".join(lines)

    if output_file:
        # Ensure parent directory exists
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(output_text)
        logger.info(f"Results written to: {output_file}")

        # Write meta.json file
        write_meta_json(
            output_file=output_file,
            command_id="matched_connections",
            source="basic",
        )
    else:
        print(output_text)


def save_matches_json(
    matches: list,
    output_file: Path,
    file1: Path,
    file2: Path,
    stats: dict,
) -> None:
    """Save match results to JSON file using MatchSerializer."""
    from capmaster.core.connection.match_serializer import MatchSerializer

    metadata = {
        "total_connections_1": stats["total_connections_1"],
        "total_connections_2": stats["total_connections_2"],
        "matched_pairs": stats["matched_pairs"],
        "unmatched_1": stats["unmatched_1"],
        "unmatched_2": stats["unmatched_2"],
        "match_rate_1": stats["match_rate_1"],
        "match_rate_2": stats["match_rate_2"],
        "average_score": stats["average_score"],
        "match_mode": stats["match_mode"],
    }

    MatchSerializer.save_matches(
        matches=matches,
        output_file=output_file,
        file1_path=str(file1),
        file2_path=str(file2),
        metadata=metadata,
    )

