#!/usr/bin/env python3
"""
Utility to run repeatable performance benchmarks for CapMaster CLI commands.

The script consumes ``benchmarks.yaml`` which enumerates suites and cases.
Each case defines the command to execute, optional setup steps, warmups, and
number of measured runs. Results are written to a JSON file that subsequent
tools (e.g., compare_benchmarks.py) can diff against previous baselines.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "scripts" / "benchmarks" / "benchmarks.yaml"
TMP_ROOT = REPO_ROOT / "artifacts" / "tmp" / "benchmarks"
LOG_ROOT = REPO_ROOT / "artifacts" / "benchmarks" / "logs"
TIME_BINARY = Path("/usr/bin/time")


class BenchmarkError(RuntimeError):
    """Raised when a benchmark case fails."""


@dataclass
class CaseResult:
    suite: str
    case_id: str
    runs: list[dict[str, Any]] = field(default_factory=list)
    setup_logs: list[str] = field(default_factory=list)
    status: str = "success"
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "case_id": self.case_id,
            "status": self.status,
            "error_message": self.error_message,
            "runs": self.runs,
            "setup_logs": self.setup_logs,
            "aggregates": self._compute_aggregates(),
        }

    def _compute_aggregates(self) -> dict[str, Any]:
        if not self.runs:
            return {}

        aggregates: dict[str, Any] = {}

        numeric_keys = [
            "wall_time_sec",
            "user_time_sec",
            "system_time_sec",
            "max_rss_kb",
        ]

        for key in numeric_keys:
            values = [run[key] for run in self.runs if key in run]
            if not values:
                continue
            aggregates[key] = {
                "min": min(values),
                "max": max(values),
                "avg": sum(values) / len(values),
            }

        return aggregates


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CapMaster benchmark runner")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="Path to benchmarks.yaml (default: %(default)s)",
    )
    parser.add_argument(
        "--suite",
        action="append",
        dest="suites",
        help="Name of suite to run (can be specified multiple times). "
        "Defaults to all suites in the configuration.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT
        / "artifacts"
        / "benchmarks"
        / f"benchmarks-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json",
        help="Path to write benchmark results JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop executing cases after the first failure.",
    )
    parser.add_argument(
        "--python-bin",
        type=Path,
        help="Python interpreter used inside benchmark commands "
        "(default: .venv/bin/python3 if present, otherwise current interpreter).",
    )
    return parser.parse_args()


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def ensure_prerequisites() -> None:
    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    if not TIME_BINARY.exists():
        raise BenchmarkError(f"Required binary not found: {TIME_BINARY}")


def expand_command(tokenized: list[str] | str, context: dict[str, str]) -> list[str]:
    if isinstance(tokenized, str):
        tokens = shlex.split(tokenized)
    else:
        tokens = tokenized
    return [token.format(**context) for token in tokens]


def execute_setup_commands(
    setup_commands: Iterable[list[str] | str],
    workdir: Path,
    env: dict[str, str],
    log_dir: Path,
    context: dict[str, str],
) -> list[str]:
    logs: list[str] = []
    for idx, raw_cmd in enumerate(setup_commands, start=1):
        cmd = expand_command(raw_cmd, context)
        log_path = log_dir / f"setup_{idx}.log"
        log_dir.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            cmd,
            cwd=workdir,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        log_path.write_text(result.stdout, encoding="utf-8")
        logs.append(str(log_path.relative_to(REPO_ROOT)))
        if result.returncode != 0:
            raise BenchmarkError(
                f"Setup command failed (exit {result.returncode}): {' '.join(cmd)}"
            )
    return logs


def parse_time_metrics(path: Path) -> dict[str, float]:
    metrics: dict[str, float] = {}
    if not path.exists():
        return metrics
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) == 2 and parts[1] == "real":
                metrics["real_time_sec"] = float(parts[0])
            elif len(parts) == 2 and parts[1] == "user":
                metrics["user_time_sec"] = float(parts[0])
            elif len(parts) == 2 and parts[1] == "sys":
                metrics["system_time_sec"] = float(parts[0])
            elif stripped.endswith("maximum resident set size"):
                value = float(parts[0])
                metrics["max_rss_kb"] = value
    return metrics


def run_single_command(
    command: list[str],
    workdir: Path,
    env: dict[str, str],
    log_dir: Path,
    run_label: str,
) -> dict[str, Any]:
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_log = log_dir / f"{run_label}_stdout.log"
    stderr_log = log_dir / f"{run_label}_stderr.log"
    metrics_file = log_dir / f"{run_label}_metrics.txt"

    time_cmd = (
        [str(TIME_BINARY), "-l", "-o", str(metrics_file)]
        + command
    )

    started_at = datetime.now(timezone.utc)
    wall_start = time.perf_counter()

    proc = subprocess.run(
        time_cmd,
        cwd=workdir,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    wall_end = time.perf_counter()
    finished_at = datetime.now(timezone.utc)

    stdout_log.write_text(proc.stdout, encoding="utf-8")
    stderr_log.write_text(proc.stderr, encoding="utf-8")

    metrics = parse_time_metrics(metrics_file)
    if "real_time_sec" in metrics:
        metrics["wall_time_sec"] = metrics.pop("real_time_sec")
    else:
        metrics["wall_time_sec"] = wall_end - wall_start

    record = {
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "wall_clock_sec": wall_end - wall_start,
        "return_code": proc.returncode,
        "stdout_log": str(stdout_log.relative_to(REPO_ROOT)),
        "stderr_log": str(stderr_log.relative_to(REPO_ROOT)),
    }

    if metrics:
        record.update(metrics)

    if proc.returncode != 0:
        raise BenchmarkError(
            f"Command failed (exit {proc.returncode}): {' '.join(command)}"
        )

    return record


def run_case(
    suite_name: str,
    case: dict[str, Any],
    env_base: dict[str, str],
) -> CaseResult:
    case_id = case["id"]
    description = case.get("description", "")
    print(f"[{suite_name}] -> {case_id}: {description}")

    workdir = REPO_ROOT
    command = case["command"]
    warmup = int(case.get("warmup", 0))
    runs = int(case.get("runs", 1))
    setup = case.get("setup", [])

    env = env_base.copy()
    env.update({k: str(v) for k, v in case.get("env", {}).items()})

    context = {
        "REPO_ROOT": str(REPO_ROOT),
        "TMP_DIR": str(TMP_ROOT),
        "PYTHON_BIN": env_base.get("CAPMASTER_BENCH_PYTHON", sys.executable),
    }

    expanded_command = expand_command(command, context)
    log_dir = LOG_ROOT / suite_name / case_id
    case_result = CaseResult(suite=suite_name, case_id=case_id)

    if setup:
        try:
            case_result.setup_logs = execute_setup_commands(
                setup, workdir, env, log_dir, context
            )
        except BenchmarkError as exc:
            case_result.status = "failed"
            case_result.error_message = str(exc)
            return case_result

    # Warmup runs (not recorded)
    for idx in range(1, warmup + 1):
        label = f"warmup_{idx}"
        try:
            run_single_command(expanded_command, workdir, env, log_dir, label)
        except BenchmarkError as exc:
            case_result.status = "failed"
            case_result.error_message = f"Warmup failed: {exc}"
            return case_result

    for run_idx in range(1, runs + 1):
        label = f"run_{run_idx}"
        try:
            record = run_single_command(
                expanded_command, workdir, env, log_dir, label
            )
            case_result.runs.append(record)
        except BenchmarkError as exc:
            case_result.status = "failed"
            case_result.error_message = str(exc)
            return case_result

    return case_result


def main() -> None:
    args = parse_args()
    ensure_prerequisites()

    config = load_config(args.config)
    config_suites: dict[str, Any] = config.get("suites", {})
    if not config_suites:
        raise BenchmarkError("No suites defined in configuration")

    requested = set(args.suites) if args.suites else set(config_suites.keys())

    env_base = os.environ.copy()
    env_base.setdefault("PYTHONUNBUFFERED", "1")
    env_base.setdefault("CAPMASTER_BENCH_ROOT", str(REPO_ROOT))
    env_base.setdefault("CAPMASTER_BENCH_TMP", str(TMP_ROOT))
    default_python = REPO_ROOT / ".venv" / "bin" / "python3"
    if args.python_bin:
        python_bin = Path(args.python_bin)
    elif default_python.exists():
        python_bin = default_python
    else:
        python_bin = Path(sys.executable)
    env_base["CAPMASTER_BENCH_PYTHON"] = str(python_bin)

    results: list[dict[str, Any]] = []
    for suite_name in sorted(requested):
        suite = config_suites.get(suite_name)
        if not suite:
            print(f"[WARN] Suite '{suite_name}' not found in configuration", file=sys.stderr)
            continue
        suite_cases = suite.get("cases", [])
        if not suite_cases:
            print(f"[WARN] Suite '{suite_name}' has no cases", file=sys.stderr)
            continue
        for case in suite_cases:
            case_result = run_case(suite_name, case, env_base)
            results.append(case_result.to_dict())
            if case_result.status != "success" and args.fail_fast:
                break
        else:
            continue  # only executed if inner loop didn't break
        break

    output_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": str(args.config.relative_to(REPO_ROOT)),
        "suites": sorted(requested),
        "results": results,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=2)

    print(f"Benchmark results saved to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except BenchmarkError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

