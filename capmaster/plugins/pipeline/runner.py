"""Pipeline runner logic."""

import inspect
import logging
import re
import types
from pathlib import Path
from typing import Any, Dict, Union

import yaml

from capmaster.plugins import get_all_plugins
from capmaster.plugins.base import PluginBase

logger = logging.getLogger(__name__)


class PipelineRunner:
    """Executes a pipeline defined in a YAML configuration file."""

    def __init__(
        self,
        config_path: Path,
        input_path: str,
        output_dir: Path,
        dry_run: bool = False,
        silent: bool = False,
    ):
        self.config_path = config_path
        self.input_path = input_path
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.silent = silent
        self.step_outputs: Dict[str, Dict[str, Any]] = {}
        self.plugins: Dict[str, PluginBase] = {}
        self._discover_plugins()

    def _discover_plugins(self) -> None:
        """Discover and instantiate all available plugins."""
        for plugin_cls in get_all_plugins():
            try:
                plugin = plugin_cls()
                # Map all supported commands to the plugin instance
                command_map = plugin.get_command_map()
                for command in command_map:
                    self.plugins[command] = plugin
            except Exception as e:
                logger.warning(f"Failed to instantiate plugin {plugin_cls}: {e}")

    def run(self) -> int:
        """Execute the pipeline."""
        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load pipeline config: {e}")
            return 1

        steps = config.get("steps", [])
        if not steps:
            logger.warning("No steps defined in pipeline configuration.")
            return 0

        logger.info(f"Starting pipeline: {config.get('name', 'Unnamed Pipeline')}")

        # Ensure output directory exists
        if not self.dry_run:
            self.output_dir.mkdir(parents=True, exist_ok=True)

        for step in steps:
            step_id = step.get("id")
            command = step.get("command")
            raw_args = step.get("args", {})

            if not step_id or not command:
                logger.error(f"Invalid step definition: {step}")
                return 1

            logger.info(f"Preparing step: {step_id} ({command})")

            # 1. Resolve variables
            try:
                resolved_args = self._resolve_variables(raw_args)
            except ValueError as e:
                logger.error(f"Variable resolution failed for step {step_id}: {e}")
                return 1

            # 2. Find plugin
            plugin = self.plugins.get(command)
            if not plugin:
                logger.error(f"Unknown command: {command}")
                return 1

            # 3. Resolve arguments (CLI -> Python)
            python_args = plugin.resolve_args(command, resolved_args)

            # Inject silent flag if enabled
            if self.silent:
                python_args["silent"] = True

            # 4. Type conversion
            method_name = plugin.get_command_map()[command]
            method = getattr(plugin, method_name)
            final_args = self._convert_types(method, python_args)

            # 5. Execute
            if self.dry_run:
                logger.info(
                    f"[Dry Run] Would execute {command} with args: {final_args}"
                )
                # Simulate output for subsequent steps
                self.step_outputs[step_id] = resolved_args
                continue

            logger.info(f"Executing step: {step_id}")
            try:
                exit_code = method(**final_args)
                if exit_code != 0:
                    logger.error(f"Step {step_id} failed with exit code {exit_code}")
                    return exit_code
            except Exception as e:
                logger.error(f"Step {step_id} raised exception: {e}")
                return 1

            # Store outputs for future steps
            self.step_outputs[step_id] = resolved_args

        logger.info("Pipeline completed successfully.")
        return 0

    def _resolve_variables(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively resolve variables in arguments."""
        resolved = {}
        for k, v in args.items():
            if isinstance(v, dict):
                resolved[k] = self._resolve_variables(v)
            elif isinstance(v, str):
                resolved[k] = self._resolve_string(v)
            else:
                resolved[k] = v
        return resolved

    def _resolve_string(self, value: str) -> str:
        """Resolve variables in a single string."""
        # Replace ${INPUT}
        value = value.replace("${INPUT}", self.input_path)

        # Replace ${OUTPUT}
        value = value.replace("${OUTPUT}", str(self.output_dir))

        # Replace ${STEP.id.arg}
        # Regex to find ${STEP.id.arg}
        pattern = re.compile(r"\$\{STEP\.([\w-]+)\.([\w-]+)\}")

        def replace_step_var(match):
            step_id = match.group(1)
            arg_name = match.group(2)

            step_output = self.step_outputs.get(step_id)
            if not step_output:
                raise ValueError(f"Step '{step_id}' not found or has not run yet.")

            val = step_output.get(arg_name)
            if val is None:
                raise ValueError(
                    f"Argument '{arg_name}' not found in output of step '{step_id}'."
                )

            return str(val)

        return pattern.sub(replace_step_var, value)

    def _convert_types(self, method, args: Dict[str, Any]) -> Dict[str, Any]:
        """Convert argument types based on method signature."""
        sig = inspect.signature(method)
        converted = {}

        has_kwargs = any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        )

        for k, v in args.items():
            if k not in sig.parameters:
                if has_kwargs:
                    converted[k] = v
                continue

            param = sig.parameters[k]
            annotation = param.annotation

            # Check if target type is Path or Optional[Path]
            is_path = False
            # logger.info(f"Checking param {k}, annotation: {annotation}, type: {type(annotation)}")
            if annotation is Path:
                is_path = True
            # Handle Optional[Path] / Union[Path, None] / Path | None
            elif hasattr(annotation, "__origin__") and annotation.__origin__ in (
                Union,
                types.UnionType,
            ):
                args_types = annotation.__args__
                if Path in args_types:
                    is_path = True

            # Handle string annotations (from __future__ import annotations)
            elif isinstance(annotation, str):
                if "Path" in annotation:
                    is_path = True

            if is_path and isinstance(v, str):
                converted[k] = Path(v)
            else:
                converted[k] = v

        return converted
