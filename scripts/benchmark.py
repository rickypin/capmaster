#!/usr/bin/env python3
"""
Performance Benchmark Script for CapMaster

This script runs performance benchmarks for the main commands:
- analyze
- match

It compares the performance against the original shell scripts and generates
a comprehensive performance report.
"""

import subprocess
import time
from pathlib import Path
from typing import Dict, List, Tuple
import json
import sys


class PerformanceBenchmark:
    """Performance benchmark runner for CapMaster."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root
        self.cases_dir = workspace_root / "cases"
        self.results: Dict[str, List[Dict]] = {
            "analyze": [],
            "match": [],
        }

    def run_command(self, cmd: List[str], timeout: int = 300) -> Tuple[float, int]:
        """
        Run a command and measure execution time.

        Args:
            cmd: Command to run as list of strings
            timeout: Maximum execution time in seconds

        Returns:
            Tuple of (execution_time, return_code)
        """
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.workspace_root,
            )
            execution_time = time.time() - start_time
            return execution_time, result.returncode
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return execution_time, -1

    def benchmark_analyze(self) -> None:
        """Benchmark the analyze command."""
        print("\n=== Benchmarking Analyze Command ===\n")

        test_cases = [
            ("V-001/VOIP.pcap", "Small PCAP (VOIP)"),
            ("TC-001-1-20160407/TC-001-1-20160407-O.pcap", "Medium PCAP"),
        ]

        for pcap_path, description in test_cases:
            full_path = self.cases_dir / pcap_path
            if not full_path.exists():
                print(f"⚠️  Skipping {description}: File not found")
                continue

            print(f"Testing: {description}")
            print(f"  File: {pcap_path}")

            # Get file size
            file_size_mb = full_path.stat().st_size / (1024 * 1024)
            print(f"  Size: {file_size_mb:.2f} MB")

            # Run CapMaster analyze
            cmd = ["python", "-m", "capmaster", "analyze", "-i", str(full_path)]
            exec_time, return_code = self.run_command(cmd)

            if return_code == 0:
                print(f"  ✅ CapMaster: {exec_time:.2f}s")
            else:
                print(f"  ❌ CapMaster: Failed (code {return_code})")

            # Store results
            self.results["analyze"].append(
                {
                    "description": description,
                    "file": pcap_path,
                    "size_mb": file_size_mb,
                    "capmaster_time": exec_time,
                    "capmaster_status": "success" if return_code == 0 else "failed",
                }
            )

            print()

    def benchmark_match(self) -> None:
        """Benchmark the match command."""
        print("\n=== Benchmarking Match Command ===\n")

        test_cases = [
            ("TC-001-1-20160407", "Small dataset (63 connections)"),
            ("TC-002-5-20220215-O", "Small dataset (few connections)"),
        ]

        for dir_path, description in test_cases:
            full_path = self.cases_dir / dir_path
            if not full_path.exists():
                print(f"⚠️  Skipping {description}: Directory not found")
                continue

            # Count PCAP files
            pcap_files = list(full_path.glob("*.pcap")) + list(full_path.glob("*.pcapng"))
            if len(pcap_files) != 2:
                print(f"⚠️  Skipping {description}: Expected 2 PCAP files, found {len(pcap_files)}")
                continue

            print(f"Testing: {description}")
            print(f"  Directory: {dir_path}")
            print(f"  Files: {len(pcap_files)}")

            # Calculate total size
            total_size_mb = sum(f.stat().st_size for f in pcap_files) / (1024 * 1024)
            print(f"  Total Size: {total_size_mb:.2f} MB")

            # Run CapMaster match
            cmd = ["python", "-m", "capmaster", "match", "-i", str(full_path)]
            exec_time, return_code = self.run_command(cmd)

            if return_code == 0:
                print(f"  ✅ CapMaster: {exec_time:.2f}s")
            else:
                print(f"  ❌ CapMaster: Failed (code {return_code})")

            # Store results
            self.results["match"].append(
                {
                    "description": description,
                    "directory": dir_path,
                    "file_count": len(pcap_files),
                    "total_size_mb": total_size_mb,
                    "capmaster_time": exec_time,
                    "capmaster_status": "success" if return_code == 0 else "failed",
                }
            )

            print()


    def generate_report(self) -> None:
        """Generate a comprehensive performance report."""
        print("\n" + "=" * 80)
        print("PERFORMANCE BENCHMARK REPORT")
        print("=" * 80)

        # Analyze results
        if self.results["analyze"]:
            print("\n--- Analyze Command ---")
            for result in self.results["analyze"]:
                print(f"\n{result['description']}:")
                print(f"  File Size: {result['size_mb']:.2f} MB")
                print(f"  Execution Time: {result['capmaster_time']:.2f}s")
                print(f"  Status: {result['capmaster_status']}")

        # Match results
        if self.results["match"]:
            print("\n--- Match Command ---")
            for result in self.results["match"]:
                print(f"\n{result['description']}:")
                print(f"  Total Size: {result['total_size_mb']:.2f} MB")
                print(f"  Execution Time: {result['capmaster_time']:.2f}s")
                print(f"  Status: {result['capmaster_status']}")


        # Summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)

        total_tests = sum(len(v) for v in self.results.values())
        successful_tests = sum(
            sum(1 for r in v if r.get("capmaster_status") == "success")
            for v in self.results.values()
        )

        print(f"\nTotal Tests: {total_tests}")
        print(f"Successful: {successful_tests}")
        print(f"Failed: {total_tests - successful_tests}")
        print(f"Success Rate: {successful_tests / total_tests * 100:.1f}%")

        # Save results to JSON
        output_file = self.workspace_root / "benchmark_results.json"
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\nDetailed results saved to: {output_file}")

    def run_all_benchmarks(self) -> None:
        """Run all benchmarks."""
        print("=" * 80)
        print("CapMaster Performance Benchmark")
        print("=" * 80)

        self.benchmark_analyze()
        self.benchmark_match()
        self.generate_report()


def main() -> int:
    """Main entry point."""
    # Get workspace root
    workspace_root = Path(__file__).parent.parent

    # Create benchmark runner
    benchmark = PerformanceBenchmark(workspace_root)

    # Run all benchmarks
    benchmark.run_all_benchmarks()

    return 0


if __name__ == "__main__":
    sys.exit(main())

