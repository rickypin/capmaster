"""Executor for running analysis modules."""

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
        sequence: int = 1,
        progress: Progress | None = None,
        output_format: str = "txt",
    ) -> dict[str, Path]:
        """
        Execute analysis modules on a PCAP file.

        Args:
            input_file: Path to input PCAP file
            output_dir: Path to output directory
            modules: List of analysis module instances to execute
            sequence: Sequence number for output files (deprecated, not used)
            progress: Optional Progress instance for progress tracking
            output_format: Output format ("txt" or "md", default: "txt")

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
                module, input_file, output_dir, base_name, module_sequence, output_format
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

        Returns:
            Path to generated output file
        """
        # Build tshark arguments
        tshark_args = module.build_tshark_args(input_file)

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

        # Write processed output to file
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(processed_output)

        # Log execution status
        if result.returncode == 0:
            logger.debug(f"Module {module.name} completed successfully")
        else:
            logger.warning(
                f"Module {module.name} completed with warnings (exit code: {result.returncode})"
            )

        return output_file
