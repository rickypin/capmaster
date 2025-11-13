"""Utility for writing meta.json files for plugin outputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_meta_json(
    output_file: Path,
    command_id: str,
    source: str = "basic",
    additional_fields: dict[str, Any] | None = None,
) -> None:
    """
    Write a meta.json file alongside the output file.

    Args:
        output_file: Path to the output file
        command_id: Identifier for the command (e.g., "matched_connections", "topology", "comparative-analysis-service")
        source: Source module name (default: "basic")
        additional_fields: Additional fields to include in the meta.json file
    """
    # Generate meta.json path (same name as output file but with .meta.json extension)
    meta_path = output_file.parent / f"{output_file.stem}.meta.json"

    # Build meta content
    meta_content: dict[str, Any] = {
        "id": command_id,
        "source": source,
    }

    # Add additional fields if provided
    if additional_fields:
        meta_content.update(additional_fields)

    # Write meta.json file
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta_content, f, indent=2, ensure_ascii=False)

