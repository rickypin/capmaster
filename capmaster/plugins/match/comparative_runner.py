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
) -> int:  # pragma: no cover - stub, replaced in refactor
    """Run comparative analysis between two PCAP files.

    The full implementation is migrated from MatchPlugin.execute_comparative_analysis.
    """
    raise NotImplementedError("run_comparative_analysis is not yet implemented")

