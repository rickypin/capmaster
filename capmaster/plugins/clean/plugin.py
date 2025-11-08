"""
Clean plugin for removing statistics directories.

This plugin recursively scans directories and removes all 'statistics' folders
and their contents.
"""

import shutil
from pathlib import Path

import click
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from capmaster.core.output_manager import OutputManager
from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.utils.errors import handle_error
from capmaster.utils.logger import get_logger

logger = get_logger(__name__)


def _find_statistics_dirs(root_path: Path, recursive: bool = True) -> list[Path]:
    """
    Find all 'statistics' directories under the given root path.

    Args:
        root_path: Root directory to search
        recursive: Whether to search recursively

    Returns:
        List of paths to 'statistics' directories
    """
    statistics_dirs = []
    dir_name = OutputManager.DEFAULT_OUTPUT_DIR_NAME

    if not root_path.exists():
        logger.warning(f"Path does not exist: {root_path}")
        return statistics_dirs

    if not root_path.is_dir():
        logger.warning(f"Path is not a directory: {root_path}")
        return statistics_dirs

    if recursive:
        # Recursively find all 'statistics' directories
        for item in root_path.rglob(dir_name):
            if item.is_dir():
                statistics_dirs.append(item)
    else:
        # Only check immediate subdirectories
        stats_dir = root_path / dir_name
        if stats_dir.exists() and stats_dir.is_dir():
            statistics_dirs.append(stats_dir)

    return statistics_dirs


def _get_dir_size(path: Path) -> int:
    """
    Calculate total size of a directory in bytes.

    Args:
        path: Directory path

    Returns:
        Total size in bytes
    """
    total_size = 0
    try:
        for item in path.rglob("*"):
            if item.is_file():
                total_size += item.stat().st_size
    except (OSError, PermissionError) as e:
        logger.warning(f"Error calculating size for {path}: {e}")
    return total_size


def _format_size(size_bytes: int) -> str:
    """
    Format size in bytes to human-readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted size string (e.g., "1.5 MB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


@register_plugin
class CleanPlugin(PluginBase):
    """Plugin for cleaning statistics directories."""

    @property
    def name(self) -> str:
        """Plugin name."""
        return "clean"

    def setup_cli(self, cli_group: click.Group) -> None:
        """Register the clean command."""

        @cli_group.command(name="clean")
        @click.option(
            "-i",
            "--input",
            "input_path",
            type=click.Path(exists=True, path_type=Path),
            required=True,
            help="Input directory to search for statistics folders",
        )
        @click.option(
            "-r",
            "--no-recursive",
            "no_recursive",
            is_flag=True,
            help="Do NOT recursively search directories (default: recursive)",
        )
        @click.option(
            "--dry-run",
            is_flag=True,
            help="Show what would be deleted without actually deleting",
        )
        @click.option(
            "-y",
            "--yes",
            "auto_confirm",
            is_flag=True,
            help="Skip confirmation prompt and delete immediately",
        )
        @click.pass_context
        def clean_command(
            ctx: click.Context,
            input_path: Path,
            no_recursive: bool,
            dry_run: bool,
            auto_confirm: bool,
        ) -> None:
            """
            Remove statistics directories and their contents.

            This command searches for all 'statistics' directories under the specified
            path and removes them along with all their contents. By default, it searches
            recursively through all subdirectories.

            \b
            Examples:
              # Clean statistics directories recursively (with confirmation)
              capmaster clean -i /path/to/data

              # Clean only top-level statistics directory
              capmaster clean -i /path/to/data -r

              # Dry run to see what would be deleted
              capmaster clean -i /path/to/data --dry-run

              # Clean without confirmation prompt
              capmaster clean -i /path/to/data -y

              # Clean with verbose output
              capmaster -v clean -i /path/to/data

            \b
            Safety:
              - By default, asks for confirmation before deleting
              - Use --dry-run to preview what will be deleted
              - Use -y/--yes to skip confirmation (use with caution!)
              - Only deletes directories named 'statistics'

            \b
            Output:
              Shows the number of directories found, total size, and deletion progress.
            """
            # Default is recursive
            recursive = not no_recursive
            exit_code = self.execute(
                input_path=input_path,
                recursive=recursive,
                dry_run=dry_run,
                auto_confirm=auto_confirm,
            )
            ctx.exit(exit_code)

    def execute(  # type: ignore[override]
        self,
        input_path: Path,
        recursive: bool = True,
        dry_run: bool = False,
        auto_confirm: bool = False,
    ) -> int:
        """
        Execute the clean plugin.

        Args:
            input_path: Root directory to search
            recursive: Whether to search recursively (default: True)
            dry_run: If True, only show what would be deleted
            auto_confirm: If True, skip confirmation prompt

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            logger.info(f"Searching for statistics directories in: {input_path}")

            # Find all statistics directories
            statistics_dirs = _find_statistics_dirs(input_path, recursive)

            if not statistics_dirs:
                logger.info("No statistics directories found")
                return 0

            logger.info(f"Found {len(statistics_dirs)} statistics director{'y' if len(statistics_dirs) == 1 else 'ies'}")

            # Calculate total size
            total_size = 0
            dir_info = []
            for stats_dir in statistics_dirs:
                size = _get_dir_size(stats_dir)
                total_size += size
                dir_info.append((stats_dir, size))

            # Display what will be deleted
            logger.info("\nDirectories to be deleted:")
            for stats_dir, size in dir_info:
                logger.info(f"  - {stats_dir} ({_format_size(size)})")

            logger.info(f"\nTotal size: {_format_size(total_size)}")

            if dry_run:
                logger.info("\n[DRY RUN] No files were deleted")
                return 0

            # Confirmation prompt (unless auto_confirm is True)
            if not auto_confirm:
                from rich.prompt import Confirm

                if not Confirm.ask(
                    f"\n[yellow]Delete {len(statistics_dirs)} statistics director{'y' if len(statistics_dirs) == 1 else 'ies'}?[/yellow]",
                    default=False,
                ):
                    logger.info("Operation cancelled")
                    return 0

            # Delete directories with progress bar
            deleted_count = 0
            deleted_size = 0

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
            ) as progress:
                task = progress.add_task(
                    f"[red]Deleting {len(statistics_dirs)} director{'y' if len(statistics_dirs) == 1 else 'ies'}...",
                    total=len(statistics_dirs),
                )

                for stats_dir, size in dir_info:
                    try:
                        logger.debug(f"Deleting: {stats_dir}")
                        shutil.rmtree(stats_dir)
                        deleted_count += 1
                        deleted_size += size
                        logger.info(f"Deleted: {stats_dir}")
                    except (OSError, PermissionError) as e:
                        logger.error(f"Failed to delete {stats_dir}: {e}")

                    progress.update(task, advance=1)

            # Summary
            logger.info(
                f"\nSuccessfully deleted {deleted_count}/{len(statistics_dirs)} "
                f"director{'y' if deleted_count == 1 else 'ies'} "
                f"({_format_size(deleted_size)} freed)"
            )

            if deleted_count < len(statistics_dirs):
                logger.warning(
                    f"Failed to delete {len(statistics_dirs) - deleted_count} "
                    f"director{'y' if (len(statistics_dirs) - deleted_count) == 1 else 'ies'}"
                )
                return 1

            return 0

        except Exception as e:
            return handle_error(e, show_traceback=logger.level <= 10)  # DEBUG level

