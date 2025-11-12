"""Executor for running analysis modules."""

from __future__ import annotations

import json
from pathlib import Path

from rich.progress import Progress

from capmaster.core.output_manager import OutputManager
from capmaster.core.protocol_detector import ProtocolDetector
from capmaster.core.tshark_wrapper import TsharkWrapper
from capmaster.plugins.analyze.modules import AnalysisModule
from capmaster.utils.logger import get_logger

logger = get_logger(__name__)


class AnalysisExecutor:
    """Execute analysis modules on PCAP files."""

    def __init__(self, tshark: TsharkWrapper, protocol_detector: ProtocolDetector):
        """
        Initialize AnalysisExecutor.

        Args:
            tshark: TsharkWrapper instance for executing tshark commands
            protocol_detector: ProtocolDetector instance for detecting protocols
        """
        self.tshark = tshark
        self.protocol_detector = protocol_detector

    def execute_modules(
        self,
        input_file: Path,
        output_dir: Path,
        modules: list[AnalysisModule],
        progress: Progress | None = None,
        output_format: str = "txt",
        generate_sidecar: bool = False,
    ) -> dict[str, Path]:
        """
        Execute analysis modules on a PCAP file.

        Args:
            input_file: Path to input PCAP file
            output_dir: Path to output directory
            modules: List of analysis module instances to execute
            progress: Optional Progress instance for progress tracking
            output_format: Output format ("txt" or "md", default: "txt")
        generate_sidecar: Whether to emit metadata sidecar files per module output

        Returns:
            Dictionary mapping module names to output file paths
        """
        logger.info(f"Analyzing {input_file.name}...")

        # Detect protocols in the file
        logger.debug("Detecting protocols...")
        detected_protocols = self.protocol_detector.detect(input_file)
        logger.debug(f"Detected protocols: {sorted(detected_protocols)}")

        # Get base name for output files
        base_name = OutputManager.get_base_name(input_file)

        # Filter modules that should execute
        modules_to_run = [m for m in modules if m.should_execute(detected_protocols)]

        # Execute each module with progress tracking
        results: dict[str, Path] = {}
        module_task = None

        if progress:
            module_task = progress.add_task(
                f"[green]Running {len(modules_to_run)} module(s)...",
                total=len(modules_to_run)
            )

        # Use module index as sequence number (1-based) for each pcap file
        for module_sequence, module in enumerate(modules_to_run, start=1):
            if progress and module_task is not None:
                progress.update(module_task, description=f"[green]Running {module.name}...")

            logger.debug(f"Running module: {module.name}")
            output_file = self._execute_module(
                module,
                input_file,
                output_dir,
                base_name,
                module_sequence,
                output_format,
                generate_sidecar,
            )
            results[module.name] = output_file

            if progress and module_task is not None:
                progress.update(module_task, advance=1)

        logger.debug(f"Analysis complete. Generated {len(results)} output files.")
        return results

    def _execute_module(
        self,
        module: AnalysisModule,
        input_file: Path,
        output_dir: Path,
        base_name: str,
        sequence: int,
        output_format: str = "txt",
        generate_sidecar: bool = False,
    ) -> Path:
        """
        Execute a single analysis module.

        Args:
            module: Analysis module instance
            input_file: Path to input PCAP file
            output_dir: Path to output directory
            base_name: Base name for output file
            sequence: Sequence number for output file
            output_format: Output format ("txt" or "md", default: "txt")
            generate_sidecar: Whether to emit metadata sidecar files per module output

        Returns:
            Path to generated output file
        """
        # Build tshark arguments
        tshark_args = module.build_tshark_args(input_file)
        required_protocols = sorted(module.required_protocols)

        # Generate output file path with specified format
        output_file = OutputManager.get_output_path(
            output_dir, base_name, sequence, module.output_suffix, output_format
        )

        # Execute tshark command (without output_file parameter to capture stdout)
        logger.debug(f"Executing tshark with args: {tshark_args}")
        result = self.tshark.execute(
            args=tshark_args,
            input_file=input_file,
            timeout=300,  # 5 minutes timeout
        )

        # Post-process output if module provides custom processing
        processed_output = module.post_process(result.stdout, output_format)

        if output_format.lower() == "md":
            header = module.name.replace("_", " ")
            body = processed_output.rstrip("\n")
            processed_output = f"## {header}\n\n```\n{body}\n```\n"

        # Write processed output to file
        # Ensure parent directory exists
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(processed_output)

        if generate_sidecar:
            sidecar_path = output_file.parent / f"{output_file.stem}.meta.json"
            sidecar_content = {
                "id": module.name,
                "source": "basic",
                "tags": [],
                "source_pcap": input_file.name,
                "tshark_args": tshark_args,
                "protocols": required_protocols,
            }
            # Parent directory already created above
            with open(sidecar_path, "w", encoding="utf-8") as sidecar_file:
                json.dump(sidecar_content, sidecar_file, indent=2)

        # Log execution status
        if result.returncode == 0:
            logger.debug(f"Module {module.name} completed successfully")
        else:
            logger.warning(
                f"Module {module.name} completed with warnings (exit code: {result.returncode})"
            )

        return output_file
