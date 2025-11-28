from __future__ import annotations

"""CLI tests for the preprocess plugin.

These tests focus on Click wiring and argument handling for the
``capmaster preprocess`` command, without re-testing the full
pipeline behaviour (which is covered by other tests).
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from capmaster.cli import cli
from capmaster.plugins.preprocess.plugin import PreprocessPlugin


@pytest.mark.integration
class TestPreprocessPluginCLI:
    """High-level CLI tests for the preprocess command."""

    def test_plugin_name(self) -> None:
        """Plugin name should match the CLI subcommand."""

        plugin = PreprocessPlugin()
        assert plugin.name == "preprocess"

    def test_cli_registration_and_help(self, runner) -> None:
        """The preprocess command should be registered and show key options."""

        result = runner.invoke(cli, ["preprocess", "--help"])

        assert result.exit_code == 0
        # Basic command description
        assert "Input PCAP file" in result.output
        # A few representative options
        assert "--enable-dedup" in result.output
        assert "--enable-oneway" in result.output
        assert "--enable-time-align" in result.output
        assert "--archive-original-files" in result.output
        assert "--quiet" in result.output

    def test_missing_input_is_error(self, runner) -> None:
        """Running without -i/--input should be rejected by Click."""

        result = runner.invoke(cli, ["preprocess"])

        assert result.exit_code != 0
        assert (
            "Input file count mismatch" in result.output
            or "No valid input files found" in result.output
        )

    def test_conflicting_enable_disable_flags_error(self, runner) -> None:
        """Conflicting enable/disable flags should result in a user-friendly error."""

        with runner.isolated_filesystem():
            with open("dummy.pcap", "wb") as f:
                f.write(b"dummy")

            result = runner.invoke(
                cli,
                [
                    "preprocess",
                    "-i",
                    "dummy.pcap",
                    "--enable-dedup",
                    "--disable-dedup",
                ],
            )

        assert result.exit_code != 0
        assert "Cannot use both --enable-dedup and --disable-dedup" in result.output

    def test_step_and_flags_cannot_be_mixed(self, runner) -> None:
        """Using --step together with enable/disable flags is not allowed."""

        with runner.isolated_filesystem():
            with open("dummy.pcap", "wb") as f:
                f.write(b"dummy")

            result = runner.invoke(
                cli,
                [
                    "preprocess",
                    "-i",
                    "dummy.pcap",
                    "--step",
                    "dedup",
                    "--enable-dedup",
                ],
            )

        assert result.exit_code != 0
        assert "Cannot mix --step with enable/disable flags" in result.output

    def test_cli_passes_flags_through_to_execute(self, runner) -> None:
        """CLI options should be forwarded to PreprocessPlugin.execute()."""

        called_kwargs: dict[str, object] = {}

        def fake_execute(self, **kwargs):  # type: ignore[override]
            nonlocal called_kwargs
            called_kwargs = kwargs
            return 0

        with patch.object(PreprocessPlugin, "execute", fake_execute):
            result = runner.invoke(
                cli,
                [
                    "preprocess",
                    "-i",
                    "a.pcap,b.pcap",
                    "--enable-dedup",
                    "--archive-original-files",
                    "--no-report",
                    "--report-path",
                    "report.md",
                    "--workers",
                    "4",
                    "--quiet",
                ],
            )

        assert result.exit_code == 0
        # Basic argument forwarding
        assert called_kwargs["input_path"] == "a.pcap,b.pcap"
        assert called_kwargs["enable_dedup"] is True
        assert called_kwargs["archive_original_files"] is True
        assert called_kwargs["no_report"] is True
        # report_path is created by Click as a Path object
        assert str(called_kwargs["report_path"]).endswith("report.md")
        assert called_kwargs["workers"] == 4
        assert called_kwargs["quiet"] is True



    def test_default_output_dir_for_directory_input(self, tmp_path, monkeypatch) -> None:
        """When -o/--output is omitted and input is a directory, outputs go into that directory."""

        input_dir = tmp_path / "pcaps"
        input_dir.mkdir()
        pcap_path = input_dir / "sample.pcap"
        pcap_path.write_bytes(b"dummy")

        captured_output_dir: Path | None = None

        def fake_run_preprocess(runtime, input_files, output_dir, *, steps=None, tmp_dir=None):  # type: ignore[unused-argument]
            nonlocal captured_output_dir
            captured_output_dir = output_dir
            return []

        monkeypatch.setattr(
            "capmaster.plugins.preprocess.plugin.run_preprocess",
            fake_run_preprocess,
        )

        plugin = PreprocessPlugin()
        exit_code = plugin.execute(input_path=str(input_dir))

        assert exit_code == 0
        assert captured_output_dir == input_dir

    def test_default_output_dir_for_file_input(self, tmp_path, monkeypatch) -> None:
        """When -o/--output is omitted and input is a file, outputs go to its parent directory."""

        input_dir = tmp_path / "pcaps"
        input_dir.mkdir()
        pcap_path = input_dir / "sample.pcap"
        pcap_path.write_bytes(b"dummy")

        captured_output_dir: Path | None = None

        def fake_run_preprocess(runtime, input_files, output_dir, *, steps=None, tmp_dir=None):  # type: ignore[unused-argument]
            nonlocal captured_output_dir
            captured_output_dir = output_dir
            return []

        monkeypatch.setattr(
            "capmaster.plugins.preprocess.plugin.run_preprocess",
            fake_run_preprocess,
        )

        plugin = PreprocessPlugin()
        exit_code = plugin.execute(input_path=str(pcap_path))

        assert exit_code == 0
        assert captured_output_dir == pcap_path.parent

