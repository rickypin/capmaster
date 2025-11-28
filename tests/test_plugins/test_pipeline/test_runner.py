from __future__ import annotations

from pathlib import Path

import pytest

from capmaster.core.input_manager import InputFile
from capmaster.plugins.base import PluginBase
from capmaster.plugins.pipeline.runner import PipelineRunner


class DummyPipelinePlugin(PluginBase):
    """Test double for verifying PipelineRunner interactions."""

    calls: list[dict[str, object]] = []

    @property
    def name(self) -> str:  # pragma: no cover - trivial property
        return "dummy"

    def setup_cli(self, cli_group):  # pragma: no cover - not used in tests
        return None

    def execute(
        self,
        marker: str,
        quiet: bool = False,
        strict: bool = False,
        allow_no_input: bool = False,
        **kwargs,
    ) -> int:
        record = {
            "marker": marker,
            "quiet": quiet,
            "strict": strict,
            "allow_no_input": allow_no_input,
        }
        record.update(kwargs)
        type(self).calls.append(record)

        if marker == "system-exit" and allow_no_input:
            raise SystemExit(0)

        return 0

    def get_command_map(self) -> dict[str, str]:  # pragma: no cover - trivial mapping
        return {"dummy": "execute"}


@pytest.fixture(autouse=True)
def _patch_plugins(monkeypatch):
    """Ensure PipelineRunner discovers the dummy plugin during tests."""

    DummyPipelinePlugin.calls = []
    monkeypatch.setattr(
        "capmaster.plugins.pipeline.runner.get_all_plugins",
        lambda: [DummyPipelinePlugin],
    )
    yield


def _make_input_files(tmp_path: Path, names: list[str]) -> list[InputFile]:
    files: list[InputFile] = []
    for idx, name in enumerate(names):
        path = tmp_path / name
        path.write_bytes(b"pcap")
        files.append(InputFile(path=path, pcapid=idx, capture_point=chr(ord("A") + idx)))
    return files


def _run_pipeline(
    tmp_path: Path,
    config: dict,
    *,
    quiet: bool = False,
    strict: bool = False,
    allow_no_input: bool = False,
    original_input: str | None = None,
    input_file_names: list[str] | None = None,
) -> int:
    config_path = tmp_path / "pipeline.yaml"
    output_dir = tmp_path / "output"

    import yaml  # Local import to keep dependency scoped to test runtime

    config_path.write_text(yaml.safe_dump(config))

    if input_file_names is None:
        input_file_names = ["input-a.pcap"]

    input_files = _make_input_files(tmp_path, input_file_names)

    runner = PipelineRunner(
        config_path=config_path,
        original_input=original_input,
        input_files=input_files,
        output_dir=output_dir,
        dry_run=False,
        quiet=quiet,
        allow_no_input=allow_no_input,
        strict=strict,
    )
    return runner.run()


def test_global_flags_are_injected(tmp_path):
    config = {
        "steps": [
            {"id": "first", "command": "dummy", "args": {"marker": "first"}},
            {"id": "second", "command": "dummy", "args": {"marker": "second"}},
        ]
    }

    exit_code = _run_pipeline(
        tmp_path,
        config,
        quiet=True,
        strict=True,
        allow_no_input=True,
    )

    assert exit_code == 0
    assert [call["marker"] for call in DummyPipelinePlugin.calls] == ["first", "second"]
    for call in DummyPipelinePlugin.calls:
        assert call["quiet"] is True
        assert call["strict"] is True
        assert call["allow_no_input"] is True


def test_shared_inputs_auto_injection(tmp_path):
    config = {
        "steps": [
            {"id": "first", "command": "dummy", "args": {"marker": "first"}},
        ]
    }

    exit_code = _run_pipeline(
        tmp_path,
        config,
        input_file_names=["alpha.pcap", "beta.pcap"],
        original_input="alpha.pcap,beta.pcap",
    )

    assert exit_code == 0
    call = DummyPipelinePlugin.calls[0]
    assert call.get("input_path") == "alpha.pcap,beta.pcap"
    assert "file1" not in call
    assert "file2" not in call


def test_shared_inputs_file_mode_injection(tmp_path):
    config = {
        "steps": [
            {"id": "first", "command": "dummy", "args": {"marker": "first"}},
        ]
    }

    exit_code = _run_pipeline(
        tmp_path,
        config,
        input_file_names=["alpha.pcap", "beta.pcap"],
        original_input=None,
    )

    assert exit_code == 0
    call = DummyPipelinePlugin.calls[0]
    assert call["file1"].endswith("alpha.pcap")
    assert call["file2"].endswith("beta.pcap")
    assert "input_path" not in call


def test_unresolved_placeholders_are_removed(tmp_path):
    config = {
        "steps": [
            {
                "id": "only",
                "command": "dummy",
                "args": {
                    "marker": "single",
                    "file1": "${FILE1}",
                    "file2": "${FILE2}",
                },
            }
        ]
    }

    exit_code = _run_pipeline(
        tmp_path,
        config,
        input_file_names=["alpha.pcap"],
    )

    assert exit_code == 0
    call = DummyPipelinePlugin.calls[0]
    assert call["file1"].endswith("alpha.pcap")
    assert "file2" not in call


def test_file_overrides_win_even_with_input_defaults(tmp_path):
    config = {
        "steps": [
            {
                "id": "only",
                "command": "dummy",
                "args": {
                    "marker": "files",
                    "file1": "${FILE1}",
                },
            }
        ]
    }

    exit_code = _run_pipeline(
        tmp_path,
        config,
        input_file_names=["alpha.pcap", "beta.pcap"],
        original_input="alpha.pcap,beta.pcap",
    )

    assert exit_code == 0
    call = DummyPipelinePlugin.calls[0]
    assert call["file1"].endswith("alpha.pcap")
    assert call["file2"].endswith("beta.pcap")
    assert "input_path" not in call


def test_when_clause_skips_on_min_input(tmp_path):
    config = {
        "steps": [
            {
                "id": "first",
                "command": "dummy",
                "when": {"min_input_files": 2},
                "args": {"marker": "first"},
            }
        ]
    }

    exit_code = _run_pipeline(
        tmp_path,
        config,
        input_file_names=["alpha.pcap"],
    )

    assert exit_code == 0
    assert DummyPipelinePlugin.calls == []


def test_when_clause_requires_previous_step(tmp_path):
    config = {
        "steps": [
            {
                "id": "match",
                "command": "dummy",
                "when": {"min_input_files": 2},
                "args": {"marker": "match"},
            },
            {
                "id": "topo",
                "command": "dummy",
                "when": {"require_steps": ["match"]},
                "args": {"marker": "topo"},
            },
        ]
    }

    exit_code = _run_pipeline(
        tmp_path,
        config,
        input_file_names=["alpha.pcap"],
    )

    assert exit_code == 0
    # match skipped due to min_input_files, so topo is also skipped
    assert DummyPipelinePlugin.calls == []


def test_step_level_override_wins_over_global_flags(tmp_path):
    config = {
        "steps": [
            {"id": "first", "command": "dummy", "args": {"marker": "first"}},
            {
                "id": "second",
                "command": "dummy",
                "args": {
                    "marker": "second",
                    "quiet": False,
                    "allow-no-input": False,
                },
            },
        ]
    }

    exit_code = _run_pipeline(
        tmp_path,
        config,
        quiet=True,
        strict=True,
        allow_no_input=True,
    )

    assert exit_code == 0
    first_call, second_call = DummyPipelinePlugin.calls
    assert first_call["quiet"] is True
    assert first_call["strict"] is True
    assert first_call["allow_no_input"] is True

    # Second step keeps its explicit overrides
    assert second_call["quiet"] is False
    assert second_call["strict"] is True  # not overridden in YAML
    assert second_call["allow_no_input"] is False


def test_system_exit_zero_is_treated_as_skip(tmp_path):
    config = {
        "steps": [
            {"id": "skip", "command": "dummy", "args": {"marker": "system-exit"}},
            {"id": "run", "command": "dummy", "args": {"marker": "after"}},
        ]
    }

    exit_code = _run_pipeline(
        tmp_path,
        config,
        allow_no_input=True,
    )

    assert exit_code == 0
    assert [call["marker"] for call in DummyPipelinePlugin.calls] == [
        "system-exit",
        "after",
    ]