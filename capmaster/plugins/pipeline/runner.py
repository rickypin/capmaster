"""Pipeline runner logic."""

import inspect
import logging
import re
import types
from pathlib import Path
from typing import Any, Dict, Union, List

import click
import yaml

from capmaster.plugins import get_all_plugins
from capmaster.plugins.base import PluginBase
from capmaster.core.input_manager import InputFile


logger = logging.getLogger(__name__)


class PipelineRunner:
    """Executes a pipeline defined in a YAML configuration file."""

    def __init__(
        self,
        config_path: Path,
        original_input: str | None,
        input_files: list[InputFile],
        output_dir: Path,
        dry_run: bool = False,
        quiet: bool = False,
        allow_no_input: bool = False,
        strict: bool = False,
    ):
        self.config_path = config_path
        self.original_input = original_input
        self.input_files = input_files
        self.output_dir = output_dir
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.quiet = quiet
        self.allow_no_input = allow_no_input
        self.strict = strict
        self.step_outputs: Dict[str, Dict[str, Any]] = {}
        self.plugins: Dict[str, PluginBase] = {}
        self.shared_input_defaults = self._build_input_defaults()
        self.shared_file_defaults = self._build_file_defaults()
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

    def _build_input_defaults(self) -> Dict[str, Any]:
        """Return shared defaults for commands that expect -i/--input."""
        if not self.original_input:
            return {}
        return {"input": self.original_input}

    def _build_file_defaults(self) -> Dict[str, Any]:
        """Return shared defaults for commands that expect --fileX inputs."""
        shared: Dict[str, Any] = {}
        for idx, input_file in enumerate(self.input_files, start=1):
            shared[f"file{idx}"] = str(input_file.path)
        return shared

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
            when_clause = step.get("when")

            if not step_id or not command:
                logger.error(f"Invalid step definition: {step}")
                return 1

            if when_clause:
                try:
                    should_run = self._should_run_step(step_id, when_clause)
                except ValueError as exc:
                    logger.error("Invalid 'when' clause for step %s: %s", step_id, exc)
                    return 1

                if not should_run:
                    logger.info("Skipping step %s due to 'when' conditions.", step_id)
                    continue

            logger.info(f"Preparing step: {step_id} ({command})")

            # 1. Resolve variables
            try:
                resolved_args = self._resolve_variables(raw_args)
            except ValueError as e:
                logger.error(f"Variable resolution failed for step {step_id}: {e}")
                return 1

            # Inject shared input defaults and clean unresolved placeholders
            resolved_args = self._inject_shared_inputs(resolved_args, step_id)

            # 2. Find plugin
            plugin = self.plugins.get(command)
            if not plugin:
                logger.error(f"Unknown command: {command}")
                return 1

            # 3. Resolve arguments (CLI -> Python)
            python_args = plugin.resolve_args(command, resolved_args)

            method_name = plugin.get_command_map()[command]
            method = getattr(plugin, method_name)

            # Inject global flags (quiet/strict/allow_no_input) when supported
            python_args = self._inject_global_flags(method, python_args)

            # 4. Type conversion
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
            except click.exceptions.Exit as exc:
                if exc.exit_code == 0:
                    logger.info(
                        "Step %s exited silently (requested by --allow-no-input, formerly --silent-exit). Skipping step.",
                        step_id,
                    )
                    continue
                logger.error(
                    "Step %s raised click.Exit with code %s: %s",
                    step_id,
                    exc.exit_code,
                    exc,
                )
                return exc.exit_code or 1
            except SystemExit as exc:
                if exc.code == 0:
                    logger.info(
                        "Step %s exited quietly via SystemExit(0); assuming allow-no-input skip.",
                        step_id,
                    )
                    continue
                logger.error(
                    "Step %s raised SystemExit with code %s",
                    step_id,
                    exc.code,
                )
                return exc.code or 1
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
        # Replace ${INPUT} (backward compatibility)
        if self.original_input:
            value = value.replace("${INPUT}", self.original_input)
        elif self.input_files:
            value = value.replace("${INPUT}", str(self.input_files[0].path))

        # Replace ${FILE1}, ${FILE2}, etc.
        for i, input_file in enumerate(self.input_files, start=1):
            value = value.replace(f"${{FILE{i}}}", str(input_file.path))

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

            # Helper to check if a type is Path or Optional[Path]
            def is_path_type(tp):
                if tp is Path:
                    return True
                # Handle Optional[Path] / Union[Path, None]
                origin = getattr(tp, "__origin__", None)
                if origin in (Union, types.UnionType):
                    return any(is_path_type(arg) for arg in getattr(tp, "__args__", []))
                # Handle string annotations
                if isinstance(tp, str) and "Path" in tp:
                    return True
                return False

            # Helper to check if a type is List[Path]
            def is_list_path_type(tp):
                origin = getattr(tp, "__origin__", None)
                if origin is list or origin is List:
                    args = getattr(tp, "__args__", [])
                    if args and is_path_type(args[0]):
                        return True
                if isinstance(tp, str) and ("List[Path]" in tp or "list[Path]" in tp):
                    return True
                return False

            if is_path_type(annotation):
                if isinstance(v, str):
                    converted[k] = Path(v)
                else:
                    converted[k] = v
            elif is_list_path_type(annotation):
                if isinstance(v, list):
                    converted[k] = [Path(item) if isinstance(item, str) else item for item in v]
                elif isinstance(v, str):
                    # If a single string is passed for a list argument, wrap it
                    converted[k] = [Path(v)]
                else:
                    converted[k] = v
            else:
                converted[k] = v

        return converted

    def _inject_shared_inputs(self, args: Dict[str, Any], step_id: str) -> Dict[str, Any]:
        """Merge shared input arguments into step args and drop unresolved placeholders."""
        updated = dict(args)
        step_style = self._detect_step_input_style(updated)

        if step_style == "input":
            self._apply_input_defaults(updated)
        elif step_style == "files":
            self._apply_file_defaults(updated)
        elif step_style == "mixed":
            logger.debug(
                "Step %s already mixes input and file arguments; skipping defaults",
                step_id,
            )
        else:
            if self.shared_input_defaults:
                self._apply_input_defaults(updated)
            else:
                self._apply_file_defaults(updated)

        placeholder_tokens = ("${FILE", "${INPUT}")
        for key in list(updated.keys()):
            value = updated[key]
            if isinstance(value, str) and any(token in value for token in placeholder_tokens):
                logger.debug(
                    "Removing unresolved placeholder for %s in step %s (value=%s)",
                    key,
                    step_id,
                    value,
                )
                updated.pop(key)

        return updated

    @staticmethod
    def _detect_step_input_style(args: Dict[str, Any]) -> str:
        """Determine whether a step explicitly set -i or --fileX style arguments."""
        has_input = any(key in args for key in ("input", "input_path"))
        has_files = any(
            key.startswith("file") and key[4:].isdigit()
            for key in args
        )

        if has_input and has_files:
            return "mixed"
        if has_input:
            return "input"
        if has_files:
            return "files"
        return "none"

    def _apply_input_defaults(self, args: Dict[str, Any]) -> None:
        """Inject -i/--input defaults when the user selected that mode."""
        if not self.shared_input_defaults:
            return
        for key, value in self.shared_input_defaults.items():
            args.setdefault(key, value)

    def _apply_file_defaults(self, args: Dict[str, Any]) -> None:
        """Inject --fileX defaults when the user selected that mode."""
        if not self.shared_file_defaults:
            return
        for key, value in self.shared_file_defaults.items():
            args.setdefault(key, value)

    def _should_run_step(self, step_id: str, when_clause: Dict[str, Any]) -> bool:
        """Evaluate conditional execution rules for a step."""
        if not isinstance(when_clause, dict):
            raise ValueError("when clause must be a mapping of conditions")

        input_count = len(self.input_files)

        min_files = when_clause.get("min_input_files")
        if min_files is not None:
            if not isinstance(min_files, int) or min_files < 0:
                raise ValueError("min_input_files must be a non-negative integer")
            if input_count < min_files:
                logger.debug(
                    "Step %s skipped: requires at least %s input files (have %s)",
                    step_id,
                    min_files,
                    input_count,
                )
                return False

        max_files = when_clause.get("max_input_files")
        if max_files is not None:
            if not isinstance(max_files, int) or max_files < 0:
                raise ValueError("max_input_files must be a non-negative integer")
            if input_count > max_files:
                logger.debug(
                    "Step %s skipped: allows at most %s input files (have %s)",
                    step_id,
                    max_files,
                    input_count,
                )
                return False

        required_steps = when_clause.get("require_steps")
        if required_steps is not None:
            if isinstance(required_steps, str):
                required_set = {required_steps}
            elif isinstance(required_steps, list):
                required_set = set(required_steps)
            else:
                raise ValueError("require_steps must be a string or list of step ids")

            missing = [sid for sid in required_set if sid not in self.step_outputs]
            if missing:
                logger.debug(
                    "Step %s skipped: required steps missing (%s)",
                    step_id,
                    ", ".join(missing),
                )
                return False

        return True

    def _inject_global_flags(self, method, args: Dict[str, Any]) -> Dict[str, Any]:
        """Inject run-pipeline flags into step arguments when supported."""
        injections: list[tuple[str, bool]] = []
        if self.quiet:
            injections.append(("quiet", True))
        if self.strict:
            injections.append(("strict", True))
        if self.allow_no_input:
            injections.append(("allow_no_input", True))

        if not injections:
            return args

        updated = dict(args)
        for name, value in injections:
            if not self._method_accepts_flag(method, name):
                logger.debug(
                    "Skipping injection of %s for method %s (not supported)",
                    name,
                    method.__qualname__,
                )
                continue

            if name in updated:
                logger.debug(
                    "Step override detected for %s on method %s; keeping explicit value",
                    name,
                    method.__qualname__,
                )
                continue

            updated[name] = value
        return updated

    @staticmethod
    def _method_accepts_flag(method, flag_name: str) -> bool:
        """Check whether a method accepts a given flag argument."""
        sig = inspect.signature(method)
        if flag_name in sig.parameters:
            return True
        return any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        )
