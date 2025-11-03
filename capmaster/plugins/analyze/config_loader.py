"""Configuration loader for analysis modules."""

from pathlib import Path
from typing import Any

import yaml

from capmaster.utils.logger import get_logger

logger = get_logger(__name__)


class ConfigLoader:
    """Load and parse analysis module configuration from YAML files."""

    @staticmethod
    def load_config(config_file: Path) -> dict[str, Any]:
        """
        Load configuration from a YAML file.

        Args:
            config_file: Path to YAML configuration file

        Returns:
            Dictionary containing configuration data

        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file is invalid YAML
        """
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")

        logger.debug(f"Loading configuration from {config_file}")

        with open(config_file, encoding="utf-8") as f:
            config_data = yaml.safe_load(f)

        if config_data is None:
            config: dict[str, Any] = {}
        else:
            config = dict(config_data)

        logger.debug(f"Loaded configuration with {len(config.get('modules', []))} modules")
        return config

    @staticmethod
    def get_default_config_path() -> Path:
        """
        Get path to default configuration file.

        Returns:
            Path to default_commands.yaml in the config directory
        """
        # Get the package root directory
        package_root = Path(__file__).parent.parent.parent
        config_path = package_root / "config" / "default_commands.yaml"
        return config_path

    @staticmethod
    def validate_config(config: dict[str, Any]) -> bool:
        """
        Validate configuration structure.

        Args:
            config: Configuration dictionary to validate

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        if "modules" not in config:
            raise ValueError("Configuration must contain 'modules' key")

        modules = config["modules"]
        if not isinstance(modules, list):
            raise ValueError("'modules' must be a list")

        for i, module in enumerate(modules):
            if not isinstance(module, dict):
                raise ValueError(f"Module {i} must be a dictionary")

            required_keys = ["name", "output_suffix", "tshark_args"]
            for key in required_keys:
                if key not in module:
                    raise ValueError(f"Module {i} missing required key: {key}")

            # Validate types
            if not isinstance(module["name"], str):
                raise ValueError(f"Module {i} 'name' must be a string")
            if not isinstance(module["output_suffix"], str):
                raise ValueError(f"Module {i} 'output_suffix' must be a string")
            if not isinstance(module["tshark_args"], list):
                raise ValueError(f"Module {i} 'tshark_args' must be a list")

            # Optional fields
            if "protocols" in module and not isinstance(module["protocols"], list):
                raise ValueError(f"Module {i} 'protocols' must be a list")

        return True
