"""Configuration objects and helpers for the preprocess plugin.

This module defines the configuration dataclasses described in
`docs/DESIGN_preprocess_and_config.md` and provides helper functions to
construct a `PreprocessRuntimeConfig` from multiple sources (YAML
configuration file, environment variables and CLI overrides).

Pipeline code should only depend on ``PreprocessRuntimeConfig`` and must
not read environment variables or CLI options directly.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Mapping, Tuple
import os

import yaml

from capmaster.utils.errors import ConfigurationError

# Environment variable used to locate the main configuration file.
ENV_CONFIG_PATH = "CAPMASTER_CONFIG"

# Default YAML configuration file name (looked up in current working dir).
DEFAULT_CONFIG_FILE_NAME = "capmaster_config.yaml"


@dataclass
class ToolsConfig:
    """Paths for external tools used by preprocess.

    The paths here are *hints* for wrapper classes. If a path is ``None``,
    the corresponding wrapper is expected to fall back to environment
    variables or ``shutil.which()``.
    """

    tshark_path: Path | None = None
    editcap_path: Path | None = None
    capinfos_path: Path | None = None

    @classmethod
    def from_sources(
        cls,
        *,
        yaml_data: Mapping[str, Any] | None = None,
        env: Mapping[str, str] | None = None,
        overrides: Mapping[str, Any] | None = None,
    ) -> "ToolsConfig":
        """Build ``ToolsConfig`` from YAML, environment and overrides.

        Precedence (low -> high): defaults < YAML < ENV < overrides.
        """

        yaml_data = yaml_data or {}
        env = env or os.environ
        overrides = overrides or {}

        cfg = cls()

        # 1) YAML values
        for field in fields(cls):
            key = field.name
            if key in yaml_data and yaml_data[key] is not None:
                value = yaml_data[key]
                cfg_value = Path(value) if value is not None else None
                setattr(cfg, key, cfg_value)

        # 2) Environment variables
        env_map = {
            "tshark_path": "TSHARK_PATH",
            "editcap_path": "EDITCAP_PATH",
            "capinfos_path": "CAPINFOS_PATH",
        }
        for attr, env_name in env_map.items():
            env_value = env.get(env_name)
            if env_value:
                setattr(cfg, attr, Path(env_value))

        # 3) Explicit overrides (typically from CLI)
        for field in fields(cls):
            key = field.name
            if key in overrides and overrides[key] is not None:
                value = overrides[key]
                if isinstance(value, Path):
                    cfg_value = value
                else:
                    cfg_value = Path(str(value))
                setattr(cfg, key, cfg_value)

        return cfg


@dataclass
class PreprocessConfig:
    """Business configuration for preprocess steps.

    Field names and defaults follow the design document.
    """

    # Step toggles
    dedup_enabled: bool = True
    oneway_enabled: bool = True
    time_align_enabled: bool = True
    archive_original: bool = False
    archive_compress: bool = False

    # Dedup params (editcap-based)
    dedup_window_packets: int | None = None
    dedup_ignore_bytes: int = 0

    # Oneway params
    oneway_ack_threshold: int = 20

    # Time align params
    time_align_allow_empty: bool = False

    # Reporting
    report_enabled: bool = True
    report_path: str | None = None

    # Performance
    workers: int = 4

    @classmethod
    def from_sources(
        cls,
        *,
        yaml_data: Mapping[str, Any] | None = None,
        overrides: Mapping[str, Any] | None = None,
    ) -> "PreprocessConfig":
        """Build ``PreprocessConfig`` from YAML and overrides.

        Precedence (low -> high): defaults < YAML < overrides.
        Environment variables are intentionally *not* used here to avoid
        configuration sprawl for business parameters.
        """

        yaml_data = yaml_data or {}
        overrides = overrides or {}

        cfg = cls()
        field_names = {f.name for f in fields(cls)}

        # 1) YAML values
        for key, value in yaml_data.items():
            if key in field_names and value is not None:
                setattr(cfg, key, value)

        # 2) Explicit overrides (typically from CLI)
        for key, value in overrides.items():
            if key in field_names and value is not None:
                setattr(cfg, key, value)

        return cfg


@dataclass
class PreprocessRuntimeConfig:
    """Aggregated runtime configuration for the preprocess pipeline."""

    tools: ToolsConfig
    preprocess: PreprocessConfig


def _load_yaml_file(config_path: Path) -> dict[str, Any]:
    """Load a YAML config file and validate its structure.

    Raises ``ConfigurationError`` if the file cannot be parsed or the
    top-level structure is not a mapping.
    """

    try:
        with config_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:  # type: ignore[attr-defined]
        raise ConfigurationError(config_path, f"YAML parse error: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigurationError(config_path, "Top-level YAML must be a mapping")

    return data


def load_yaml_config(
    config_file: Path | None,
    *,
    env: Mapping[str, str] | None = None,
) -> Tuple[dict[str, Any], Path | None]:
    """Load YAML configuration from explicit/ENV/default locations.

    Resolution order:
    1) Explicit ``config_file`` argument (if provided).
    2) ``CAPMASTER_CONFIG`` environment variable.
    3) ``./capmaster_config.yaml`` if it exists.

    Returns a tuple of ``(config_dict, resolved_path)`` where
    ``config_dict`` is empty when no configuration file is found.
    """

    env = env or os.environ

    # 1) Explicit path has highest priority
    if config_file is not None:
        if not config_file.exists():
            raise ConfigurationError(config_file, "Configuration file not found")
        return _load_yaml_file(config_file), config_file

    # 2) Environment variable
    env_path_str = env.get(ENV_CONFIG_PATH)
    if env_path_str:
        env_path = Path(env_path_str)
        if not env_path.exists():
            raise ConfigurationError(env_path, "Configuration file not found")
        return _load_yaml_file(env_path), env_path

    # 3) Default file in current working directory (optional)
    default_path = Path(DEFAULT_CONFIG_FILE_NAME)
    if default_path.exists():
        return _load_yaml_file(default_path), default_path

    return {}, None


def build_runtime_config(
    *,
    existing: PreprocessRuntimeConfig | None = None,
    config_file: Path | None = None,
    env: Mapping[str, str] | None = None,
    cli_overrides: Mapping[str, Any] | None = None,
) -> PreprocessRuntimeConfig:
    """Construct ``PreprocessRuntimeConfig`` from multiple sources.

    Precedence (high -> low):
    1) ``existing`` (explicit runtime config from caller).
    2) CLI overrides (``cli_overrides``).
    3) Environment variables (tools & config file path only).
    4) YAML configuration file (if present).
    5) Dataclass defaults.
    """

    if existing is not None:
        return existing

    cli_overrides = cli_overrides or {}
    env = env or os.environ

    yaml_data, _ = load_yaml_config(config_file, env=env)
    tools_yaml = yaml_data.get("tools", {}) if isinstance(yaml_data, dict) else {}
    preprocess_yaml = (
        yaml_data.get("preprocess", {}) if isinstance(yaml_data, dict) else {}
    )

    tools = ToolsConfig.from_sources(
        yaml_data=tools_yaml,
        env=env,
        overrides=cli_overrides,
    )
    preprocess = PreprocessConfig.from_sources(
        yaml_data=preprocess_yaml,
        overrides=cli_overrides,
    )

    return PreprocessRuntimeConfig(tools=tools, preprocess=preprocess)

