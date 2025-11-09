"""
Comparison tests between original scripts and new implementation.

This module tests that the new Python implementation produces the same
output as the original shell scripts.
"""

from __future__ import annotations
import difflib
import random
import subprocess
import tempfile
from pathlib import Path

import pytest


class TestAnalyzeComparison:
    """Compare analyze plugin output with original script."""

    @pytest.fixture
    def test_cases(self):
        """Test case PCAP files - ALL cases from cases/ directory (79 files)."""
        return [
            "cases/dbs_20251028-DNS/NXDOmain-response-from-GTM.pcap",
            "cases/dbs_20251028-Masked/A_processed.pcap",
            "cases/dbs_20251028-Masked/B_processed.pcap",
            "cases/TC-001-1-20160407/TC-001-1-20160407-A.pcap",
            "cases/TC-001-1-20160407/TC-001-1-20160407-B.pcap",
            "cases/TC-001-5-20190905/TC-001-5-20190905-Dev.pcapng",
            "cases/TC-002-1-20211208/TC-002-1-20211208-O.pcapng",
            "cases/TC-002-5-20220215-O/TC-002-5-20220215-O-FW-in.pcap",
            "cases/TC-002-5-20220215-O/TC-002-5-20220215-O-FW-out.pcap",
            "cases/TC-002-5-20220215/TC-002-5-20220215-O-A-FW-in.pcap",
            "cases/TC-002-5-20220215/TC-002-5-20220215-O-B-FW-out.pcap",
            "cases/TC-002-5-20220215/TC-002-5-20220215-O-FW-in.pcap",
            "cases/TC-002-5-20220215/TC-002-5-20220215-O-FW-out.pcap",
            "cases/TC-002-5-20220215/TC-002-5-20220215-S-FW-in.pcap",
            "cases/TC-002-5-20220215/TC-002-5-20220215-S-FW-out.pcap",
            "cases/TC-002-8-20210817-O/TC-002-8-20210817-O.pcap",
            "cases/TC-002-8-20210817-S/TC-002-8-20210817-S.pcapng",
            "cases/TC-004-01-20221108/TC-004-01-20221104-BLtoServer.pcap",
            "cases/TC-006-02-20180518-1/TC-006-02-20180518-O-61.148.244.65.pcap",
            "cases/TC-006-02-20180518/TC-006-02-20180518-O-114.242.248.232.pcap",
            "cases/TC-006-02-20180518/TC-006-02-20180518-O-61.148.244.65.pcap",
            "cases/TC-007-1-20220827/TC-007-1-20220827-F5-VS-F5SSL.pcap",
            "cases/TC-007-1-20220827/TC-007-1-20220827-F5-VS-XINANSSL.pcap",
            "cases/TC-020-4-20220425/TC-020-4-20220425-O-Service1.pcap",
            "cases/TC-020-4-20220425/TC-020-4-20220425-O-Service2.pcap",
            "cases/TC-032-3-20230329/TC-032-3-20230329-O-core-switch-abnormal-flow.pcapng",
            "cases/TC-032-3-20230329/TC-032-3-20230329-O-edge-router-abnormal-flow.pcapng",
            "cases/TC-032-3-20230329/TC-032-3-20230329-O-recovered-core-switch-normal-flow.pcapng",
            "cases/TC-032-3-20230329/TC-032-3-20230329-O-recovered-edge-router-normal-flow.pcapng",
            "cases/TC-032-8-20240603-O/TC-032-8-20240603-O.pcap",
            "cases/TC-032-8-20240603-S/TC-032-8-20240603-S.pcap",
            "cases/TC-034-3-20210604-O/TC-034-3-20210604-O-A-Front-of-F5-OWTR.pcap",
            "cases/TC-034-3-20210604-O/TC-034-3-20210604-O-B-Front-of-APP.pcap",
            "cases/TC-034-3-20210604-S/TC-034-3-20210604-S-A-Front-of-F5.pcapng",
            "cases/TC-034-3-20210604-S/TC-034-3-20210604-S-B-Front-of-APP.pcapng",
            "cases/TC-034-5-20211105/TC-034-5-20211105-O-APP.pcap",
            "cases/TC-034-5-20211105/TC-034-5-20211105-O-LoadBalancer.pcap",
            "cases/TC-034-9-20230222-O-1/TC-034-9-20230222-O-A-nginx.pcap",
            "cases/TC-034-9-20230222-O-2/TC-034-9-20230222-O-A-nginx.pcap",
            "cases/TC-034-9-20230222-O-2/TC-034-9-20230222-O-B-server.pcap",
            "cases/TC-034-9-20230222-O/TC-034-9-20230222-O-互联网运营商.pcap",
            "cases/TC-034-9-20230222-O/TC-034-9-20230222-O-应用服务器.pcap",
            "cases/TC-034-9-20230222-O/TC-034-9-20230222-O-nginx服务器前端.pcap",
            "cases/TC-034-9-20230222-S-1/TC-034-9-20230222-S-A-nginx.pcap",
            "cases/TC-034-9-20230222-S-2/TC-034-9-20230222-S-A-nginx.pcap",
            "cases/TC-034-9-20230222-S-2/TC-034-9-20230222-S-B-server.pcap",
            "cases/TC-034-9-20230222-S/TC-034-9-20230222-S-互联网运营商-异常flow.pcap",
            "cases/TC-034-9-20230222-S/TC-034-9-20230222-S-应用服务器-异常flow.pcap",
            "cases/TC-034-9-20230222-S/TC-034-9-20230222-S-nginx服务器前端-异常flow.pcap",
            "cases/TC-039-5-20211222/TC-039-5-20220107-O.pcap",
            "cases/TC-044-1-20240227-O/TC-044-1-20240227-O.pcap",
            "cases/TC-044-1-20240227-S/TC-044-1-20240227-S.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-O-信安世纪盒子处01.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-O-行内接入交换机01.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-O-信安世纪盒子处02.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-O-行内接入交换机02.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-O-A-信安世纪盒子处01-fltbyPORT.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-O-A-信安世纪盒子处01.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-O-A-信安世纪盒子处02.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-O-B-行内接入交换机01.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-O-B-行内接入交换机02.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-S-信安世纪盒子处03-异常flow.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-S-行内接入交换机03-异常flow.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-S-信安世纪盒子处04-异常flow.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-S-行内接入交换机04-异常flow.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-S-A-信安世纪盒子处03-异常flow.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-S-A-信安世纪盒子处04-异常flow.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-S-B-行内接入交换机03-异常flow.pcap",
            "cases/TC-044-2-20230920/TC-044-2-20231106-S-B-行内接入交换机04-异常flow.pcap",
            "cases/TC-045-1-20240219/TC-045-1-20240219-abnormal-sessions.pcap",
            "cases/TC-045-1-20240219/TC-045-1-20240219-all.pcap",
            "cases/TC-045-1-20240219/TC-045-1-20240219-normal-control-session.pcap",
            "cases/TC-045-1-20240219/TC-045-1-20240219-normal-data-session.pcap",
            "cases/TC-056-1-20190614-O/TC-056-1-20190614-O.pcap",
            "cases/TC-056-1-20190614/TC-056-1-20190614-Dev.pcap",
            "cases/TC-056-1-20190614/TC-056-1-20190614-O.pcap",
            "cases/TC-056-1-20190614/TC-056-1-20190614-S.pcap",
            "cases/V-001/VOIP_filtered.pcap",
            "cases/V-001/VOIP.pcap",
        ]

    @pytest.fixture
    def original_script(self):
        """Path to original analyze script."""
        return Path("analyze_pcap.sh")

    def run_original_script(self, script: Path, input_file: str, output_dir: Path) -> dict:
        """Run original shell script and return output files."""
        # Get absolute path to script
        script_abs = Path.cwd() / script
        cmd = [str(script_abs), "-i", input_file, "-o", str(output_dir)]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(Path.cwd()))
        assert result.returncode == 0, f"Original script failed: {result.stderr}"

        # Collect output files
        output_files = {}
        for f in output_dir.glob("*.txt"):
            output_files[f.name] = f.read_text()
        return output_files

    def run_new_implementation(self, input_file: str, output_dir: Path) -> dict:
        """Run new Python implementation and return output files."""
        cmd = ["python", "-m", "capmaster", "analyze", "-i", input_file, "-o", str(output_dir)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, f"New implementation failed: {result.stderr}"

        # Collect output files
        output_files = {}
        for f in output_dir.glob("*.txt"):
            output_files[f.name] = f.read_text()
        return output_files

    def normalize_filename(self, filename: str) -> str:
        """
        Normalize filename for comparison.

        Original: VOIP-5-tcp-conversations.txt
        New:      VOIP-1-tcp-conversations.txt

        Extract the suffix part for comparison.
        """
        parts = filename.split("-", 2)
        if len(parts) >= 3:
            return parts[2]  # Return the suffix part
        return filename

    def compare_outputs(self, orig_content: str, new_content: str, file_type: str,
                       ignore_trailing_whitespace: bool = True) -> tuple[bool, str]:
        """
        Compare two output files and return whether they match.

        Args:
            orig_content: Content from original script
            new_content: Content from new implementation
            file_type: Type of file being compared (for error messages)
            ignore_trailing_whitespace: If True, strip trailing whitespace before comparison

        Returns:
            Tuple of (matches: bool, diff_message: str)
        """
        # Optionally normalize trailing whitespace
        if ignore_trailing_whitespace:
            orig_normalized = orig_content.rstrip()
            new_normalized = new_content.rstrip()
        else:
            orig_normalized = orig_content
            new_normalized = new_content

        if orig_normalized == new_normalized:
            return True, ""

        # Generate diff for debugging
        diff = difflib.unified_diff(
            orig_content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile=f"original_{file_type}",
            tofile=f"new_{file_type}",
            lineterm=""
        )
        diff_text = "".join(diff)
        return False, diff_text

    def find_matching_files(self, orig_outputs: dict, new_outputs: dict, pattern: str) -> tuple[str | None, str | None]:
        """
        Find matching files in original and new outputs by pattern.

        Args:
            orig_outputs: Dictionary of original output files
            new_outputs: Dictionary of new output files
            pattern: Pattern to search for in filename

        Returns:
            Tuple of (original_content, new_content) or (None, None) if not found
        """
        orig_content = None
        new_content = None

        for name, content in orig_outputs.items():
            if pattern in name:
                orig_content = content
                break

        for name, content in new_outputs.items():
            if pattern in name:
                new_content = content
                break

        return orig_content, new_content

    @pytest.mark.parametrize("test_file", [
        "cases/V-001/VOIP.pcap",
        "cases/TC-001-5-20190905/TC-001-5-20190905-Dev.pcapng",
        "cases/TC-002-8-20210817-O/TC-002-8-20210817-O.pcap",
        "cases/TC-004-01-20221108/TC-004-01-20221104-BLtoServer.pcap",
        "cases/TC-056-1-20190614-O/TC-056-1-20190614-O.pcap",
    ])
    def test_protocol_hierarchy(self, test_file, original_script):
        """Test protocol hierarchy output matches across multiple test cases."""
        with tempfile.TemporaryDirectory() as orig_dir, \
             tempfile.TemporaryDirectory() as new_dir:

            orig_outputs = self.run_original_script(original_script, test_file, Path(orig_dir))
            new_outputs = self.run_new_implementation(test_file, Path(new_dir))

            # Find protocol hierarchy files
            orig_content, new_content = self.find_matching_files(
                orig_outputs, new_outputs, "protocol-hierarchy"
            )

            assert orig_content is not None, f"Original protocol hierarchy file not found for {test_file}"
            assert new_content is not None, f"New protocol hierarchy file not found for {test_file}"

            matches, diff = self.compare_outputs(orig_content, new_content, "protocol-hierarchy")
            assert matches, f"Protocol hierarchy outputs differ for {test_file}:\n{diff}"

    @pytest.mark.parametrize("test_file", [
        "cases/V-001/VOIP.pcap",
        "cases/TC-001-5-20190905/TC-001-5-20190905-Dev.pcapng",
        "cases/TC-002-8-20210817-O/TC-002-8-20210817-O.pcap",
        "cases/TC-004-01-20221108/TC-004-01-20221104-BLtoServer.pcap",
        "cases/TC-056-1-20190614-O/TC-056-1-20190614-O.pcap",
    ])
    def test_tcp_conversations(self, test_file, original_script):
        """Test TCP conversations output matches across multiple test cases."""
        with tempfile.TemporaryDirectory() as orig_dir, \
             tempfile.TemporaryDirectory() as new_dir:

            orig_outputs = self.run_original_script(original_script, test_file, Path(orig_dir))
            new_outputs = self.run_new_implementation(test_file, Path(new_dir))

            # Find TCP conversations files
            orig_content, new_content = self.find_matching_files(
                orig_outputs, new_outputs, "tcp-conversations"
            )

            assert orig_content is not None, f"Original TCP conversations file not found for {test_file}"
            assert new_content is not None, f"New TCP conversations file not found for {test_file}"

            matches, diff = self.compare_outputs(orig_content, new_content, "tcp-conversations")
            assert matches, f"TCP conversations outputs differ for {test_file}:\n{diff}"

    @pytest.mark.parametrize("test_file", [
        "cases/V-001/VOIP.pcap",
    ])
    def test_udp_conversations(self, test_file, original_script):
        """Test UDP conversations output matches for files with UDP traffic."""
        with tempfile.TemporaryDirectory() as orig_dir, \
             tempfile.TemporaryDirectory() as new_dir:

            orig_outputs = self.run_original_script(original_script, test_file, Path(orig_dir))
            new_outputs = self.run_new_implementation(test_file, Path(new_dir))

            # Find UDP conversations files
            orig_content, new_content = self.find_matching_files(
                orig_outputs, new_outputs, "udp-conversations"
            )

            # Both should either exist or not exist (protocol detection should match)
            if orig_content is None and new_content is None:
                pytest.skip(f"No UDP traffic in {test_file}")

            assert orig_content is not None, f"Original UDP conversations file not found for {test_file}"
            assert new_content is not None, f"New UDP conversations file not found for {test_file}"

            matches, diff = self.compare_outputs(orig_content, new_content, "udp-conversations")
            assert matches, f"UDP conversations outputs differ for {test_file}:\n{diff}"

    @pytest.mark.parametrize("test_file", [
        "cases/dbs_20251028-DNS/NXDOmain-response-from-GTM.pcap",
    ])
    def test_dns_general(self, test_file, original_script):
        """Test DNS general statistics output matches for DNS-specific test cases."""
        with tempfile.TemporaryDirectory() as orig_dir, \
             tempfile.TemporaryDirectory() as new_dir:

            orig_outputs = self.run_original_script(original_script, test_file, Path(orig_dir))
            new_outputs = self.run_new_implementation(test_file, Path(new_dir))

            # Find DNS general files
            orig_content, new_content = self.find_matching_files(
                orig_outputs, new_outputs, "dns-general"
            )

            assert orig_content is not None, f"Original DNS general file not found for {test_file}"
            assert new_content is not None, f"New DNS general file not found for {test_file}"

            matches, diff = self.compare_outputs(orig_content, new_content, "dns-general")
            assert matches, f"DNS general outputs differ for {test_file}:\n{diff}"

    @pytest.mark.parametrize("test_file", [
        "cases/dbs_20251028-DNS/NXDOmain-response-from-GTM.pcap",
    ])
    def test_dns_query_response(self, test_file, original_script):
        """Test DNS query-response statistics output matches for DNS-specific test cases."""
        with tempfile.TemporaryDirectory() as orig_dir, \
             tempfile.TemporaryDirectory() as new_dir:

            orig_outputs = self.run_original_script(original_script, test_file, Path(orig_dir))
            new_outputs = self.run_new_implementation(test_file, Path(new_dir))

            # Find DNS query-response files
            orig_content, new_content = self.find_matching_files(
                orig_outputs, new_outputs, "dns-query-response"
            )

            assert orig_content is not None, f"Original DNS query-response file not found for {test_file}"
            assert new_content is not None, f"New DNS query-response file not found for {test_file}"

            matches, diff = self.compare_outputs(orig_content, new_content, "dns-query-response")
            assert matches, f"DNS query-response outputs differ for {test_file}:\n{diff}"

    @pytest.mark.parametrize("test_file", [
        "cases/V-001/VOIP.pcap",
        "cases/TC-001-5-20190905/TC-001-5-20190905-Dev.pcapng",
        "cases/TC-002-8-20210817-O/TC-002-8-20210817-O.pcap",
        "cases/TC-004-01-20221108/TC-004-01-20221104-BLtoServer.pcap",
        "cases/TC-056-1-20190614-O/TC-056-1-20190614-O.pcap",
    ])
    def test_ipv4_conversations(self, test_file, original_script):
        """Test IPv4 conversations output matches across multiple test cases."""
        with tempfile.TemporaryDirectory() as orig_dir, \
             tempfile.TemporaryDirectory() as new_dir:

            orig_outputs = self.run_original_script(original_script, test_file, Path(orig_dir))
            new_outputs = self.run_new_implementation(test_file, Path(new_dir))

            # Find IPv4 conversations files
            orig_content, new_content = self.find_matching_files(
                orig_outputs, new_outputs, "ipv4-conversations"
            )

            assert orig_content is not None, f"Original IPv4 conversations file not found for {test_file}"
            assert new_content is not None, f"New IPv4 conversations file not found for {test_file}"

            matches, diff = self.compare_outputs(orig_content, new_content, "ipv4-conversations")
            assert matches, f"IPv4 conversations outputs differ for {test_file}:\n{diff}"

    def _test_all_cases_for_output_type(self, test_cases, original_script, output_pattern, output_name):
        """
        Helper method to test a specific output type across all test cases.

        Args:
            test_cases: List of test case files
            original_script: Path to original script
            output_pattern: Pattern to match in output filenames (e.g., "protocol-hierarchy")
            output_name: Human-readable name for the output type

        Returns:
            Tuple of (passed_count, failed_count, failures_list)
        """
        passed = 0
        failed = 0
        skipped = 0
        failures = []

        for test_file in test_cases:
            try:
                with tempfile.TemporaryDirectory() as orig_dir, \
                     tempfile.TemporaryDirectory() as new_dir:

                    # Run both implementations
                    orig_outputs = self.run_original_script(original_script, test_file, Path(orig_dir))
                    new_outputs = self.run_new_implementation(test_file, Path(new_dir))

                    # Find matching files
                    orig_content, new_content = self.find_matching_files(
                        orig_outputs, new_outputs, output_pattern
                    )

                    if orig_content is None and new_content is None:
                        # Both don't have this output - skip
                        skipped += 1
                        continue

                    if orig_content is None or new_content is None:
                        failed += 1
                        failures.append(f"{test_file}: {output_name} file not found in one implementation")
                        continue

                    # Compare outputs
                    matches, diff = self.compare_outputs(orig_content, new_content, output_pattern)

                    if matches:
                        passed += 1
                    else:
                        failed += 1
                        failures.append(f"{test_file}:\n{diff[:500]}")  # Limit diff output

            except Exception as e:
                failed += 1
                failures.append(f"{test_file}: Exception - {str(e)}")

        return passed, failed, skipped, failures

    def test_random_sample_protocol_hierarchy(self, test_cases, original_script):
        """
        Test protocol hierarchy output for a RANDOM SAMPLE of test cases.

        Samples 20 random test cases (or all if less than 20 available).
        Uses a fixed seed for reproducibility.
        """
        # Set seed for reproducibility
        random.seed(42)

        # Sample test cases
        sample_size = min(20, len(test_cases))
        sampled_cases = random.sample(test_cases, sample_size)

        passed, failed, skipped, failures = self._test_all_cases_for_output_type(
            sampled_cases, original_script, "protocol-hierarchy", "Protocol Hierarchy"
        )

        # Generate summary
        total = len(sampled_cases)
        summary = f"\n{'='*70}\n"
        summary += f"Protocol Hierarchy Test Summary (Random Sample)\n"
        summary += f"{'='*70}\n"
        summary += f"Total available cases: {len(test_cases)}\n"
        summary += f"Sample size: {total}\n"
        summary += f"Passed: {passed} ({passed/total*100:.1f}%)\n"
        summary += f"Failed: {failed} ({failed/total*100:.1f}%)\n"
        summary += f"Skipped: {skipped} ({skipped/total*100:.1f}%)\n"
        summary += f"{'='*70}\n"

        if failures:
            summary += "\nFailures:\n"
            for i, failure in enumerate(failures[:10], 1):
                summary += f"\n{i}. {failure}\n"
            if len(failures) > 10:
                summary += f"\n... and {len(failures) - 10} more failures\n"

        print(summary)

        # Assert with detailed summary
        assert failed == 0, summary

    def test_random_sample_tcp_conversations(self, test_cases, original_script):
        """Test TCP conversations output for a random sample of test cases."""
        random.seed(42)
        sample_size = min(20, len(test_cases))
        sampled_cases = random.sample(test_cases, sample_size)

        passed, failed, skipped, failures = self._test_all_cases_for_output_type(
            sampled_cases, original_script, "tcp-conversations", "TCP Conversations"
        )

        total = len(sampled_cases)
        summary = f"\n{'='*70}\n"
        summary += f"TCP Conversations Test Summary (Random Sample)\n"
        summary += f"{'='*70}\n"
        summary += f"Total available cases: {len(test_cases)}\n"
        summary += f"Sample size: {total}\n"
        summary += f"Passed: {passed} ({passed/total*100:.1f}%)\n"
        summary += f"Failed: {failed} ({failed/total*100:.1f}%)\n"
        summary += f"Skipped: {skipped} ({skipped/total*100:.1f}%)\n"
        summary += f"{'='*70}\n"

        if failures:
            summary += "\nFailures:\n"
            for i, failure in enumerate(failures[:10], 1):
                summary += f"\n{i}. {failure}\n"
            if len(failures) > 10:
                summary += f"\n... and {len(failures) - 10} more failures\n"

        print(summary)
        assert failed == 0, summary

    def test_random_sample_ipv4_conversations(self, test_cases, original_script):
        """Test IPv4 conversations output for a random sample of test cases."""
        random.seed(42)
        sample_size = min(20, len(test_cases))
        sampled_cases = random.sample(test_cases, sample_size)

        passed, failed, skipped, failures = self._test_all_cases_for_output_type(
            sampled_cases, original_script, "ipv4-conversations", "IPv4 Conversations"
        )

        total = len(sampled_cases)
        summary = f"\n{'='*70}\n"
        summary += f"IPv4 Conversations Test Summary (Random Sample)\n"
        summary += f"{'='*70}\n"
        summary += f"Total available cases: {len(test_cases)}\n"
        summary += f"Sample size: {total}\n"
        summary += f"Passed: {passed} ({passed/total*100:.1f}%)\n"
        summary += f"Failed: {failed} ({failed/total*100:.1f}%)\n"
        summary += f"Skipped: {skipped} ({skipped/total*100:.1f}%)\n"
        summary += f"{'='*70}\n"

        if failures:
            summary += "\nFailures:\n"
            for i, failure in enumerate(failures[:10], 1):
                summary += f"\n{i}. {failure}\n"
            if len(failures) > 10:
                summary += f"\n... and {len(failures) - 10} more failures\n"

        print(summary)
        assert failed == 0, summary

    def test_random_sample_udp_conversations(self, test_cases, original_script):
        """Test UDP conversations output for a random sample of test cases."""
        random.seed(42)
        sample_size = min(20, len(test_cases))
        sampled_cases = random.sample(test_cases, sample_size)

        passed, failed, skipped, failures = self._test_all_cases_for_output_type(
            sampled_cases, original_script, "udp-conversations", "UDP Conversations"
        )

        total = len(sampled_cases)
        summary = f"\n{'='*70}\n"
        summary += f"UDP Conversations Test Summary (Random Sample)\n"
        summary += f"{'='*70}\n"
        summary += f"Total available cases: {len(test_cases)}\n"
        summary += f"Sample size: {total}\n"
        summary += f"Passed: {passed} ({passed/total*100:.1f}%)\n"
        summary += f"Failed: {failed} ({failed/total*100:.1f}%)\n"
        summary += f"Skipped: {skipped} ({skipped/total*100:.1f}%)\n"
        summary += f"{'='*70}\n"

        if failures:
            summary += "\nFailures:\n"
            for i, failure in enumerate(failures[:10], 1):
                summary += f"\n{i}. {failure}\n"
            if len(failures) > 10:
                summary += f"\n... and {len(failures) - 10} more failures\n"

        print(summary)
        assert failed == 0, summary

    def test_random_sample_comprehensive(self, test_cases, original_script):
        """
        Comprehensive test of multiple output types on a random sample.

        Tests multiple output types on the same random sample to get
        a comprehensive view of compatibility.
        """
        random.seed(42)
        sample_size = min(20, len(test_cases))
        sampled_cases = random.sample(test_cases, sample_size)

        output_types = [
            ("protocol-hierarchy", "Protocol Hierarchy"),
            ("tcp-conversations", "TCP Conversations"),
            ("ipv4-conversations", "IPv4 Conversations"),
            ("udp-conversations", "UDP Conversations"),
            ("tcp-completeness", "TCP Completeness"),
            ("tcp-zero-window", "TCP Zero Window"),
            ("tcp-connection-duration", "TCP Connection Duration"),
            ("ipv4-source-ttls", "IPv4 Source TTLs"),
            ("ipv4-destinations-and-ports", "IPv4 Destinations and Ports"),
        ]

        results = {}
        for pattern, name in output_types:
            passed, failed, skipped, failures = self._test_all_cases_for_output_type(
                sampled_cases, original_script, pattern, name
            )
            results[name] = {
                "passed": passed,
                "failed": failed,
                "skipped": skipped,
                "failures": failures
            }

        # Generate comprehensive summary
        total = len(sampled_cases)
        summary = f"\n{'='*70}\n"
        summary += f"Comprehensive Test Summary (Random Sample)\n"
        summary += f"{'='*70}\n"
        summary += f"Total available cases: {len(test_cases)}\n"
        summary += f"Sample size: {total}\n"
        summary += f"Output types tested: {len(output_types)}\n"
        summary += f"{'='*70}\n\n"

        total_passed = 0
        total_failed = 0
        total_skipped = 0

        for name, result in results.items():
            summary += f"{name}:\n"
            summary += f"  Passed: {result['passed']} ({result['passed']/total*100:.1f}%)\n"
            summary += f"  Failed: {result['failed']} ({result['failed']/total*100:.1f}%)\n"
            summary += f"  Skipped: {result['skipped']} ({result['skipped']/total*100:.1f}%)\n"

            total_passed += result['passed']
            total_failed += result['failed']
            total_skipped += result['skipped']

            if result['failures']:
                summary += f"  First failure: {result['failures'][0][:100]}...\n"
            summary += "\n"

        summary += f"{'='*70}\n"
        summary += f"Overall Statistics:\n"
        summary += f"  Total tests run: {total_passed + total_failed}\n"
        summary += f"  Total passed: {total_passed}\n"
        summary += f"  Total failed: {total_failed}\n"
        summary += f"  Total skipped: {total_skipped}\n"
        if total_passed + total_failed > 0:
            summary += f"  Success rate: {total_passed/(total_passed+total_failed)*100:.1f}%\n"
        summary += f"{'='*70}\n"

        print(summary)

        # Assert no failures
        assert total_failed == 0, summary

    def test_comprehensive_comparison(self, test_cases, original_script):
        """
        Comprehensive test comparing all outputs for all test cases.

        This test runs both implementations on all test cases and compares
        all generated output files to ensure complete compatibility.
        """
        results = []

        for test_file in test_cases:
            with tempfile.TemporaryDirectory() as orig_dir, \
                 tempfile.TemporaryDirectory() as new_dir:

                # Run both implementations
                orig_outputs = self.run_original_script(original_script, test_file, Path(orig_dir))
                new_outputs = self.run_new_implementation(test_file, Path(new_dir))

                # Compare file counts
                file_count_match = len(orig_outputs) == len(new_outputs)

                # Compare each file type
                file_comparisons = {}
                for orig_name, orig_content in orig_outputs.items():
                    # Extract file type from name
                    file_type = self.normalize_filename(orig_name)

                    # Find matching new file
                    new_content = None
                    for new_name, content in new_outputs.items():
                        if self.normalize_filename(new_name) == file_type:
                            new_content = content
                            break

                    if new_content is not None:
                        matches, diff = self.compare_outputs(orig_content, new_content, file_type)
                        file_comparisons[file_type] = {
                            "matches": matches,
                            "diff": diff if not matches else None
                        }
                    else:
                        file_comparisons[file_type] = {
                            "matches": False,
                            "diff": f"File {file_type} not found in new implementation"
                        }

                results.append({
                    "test_file": test_file,
                    "file_count_match": file_count_match,
                    "orig_count": len(orig_outputs),
                    "new_count": len(new_outputs),
                    "file_comparisons": file_comparisons
                })

        # Generate summary report
        total_tests = len(results)
        passed_tests = sum(1 for r in results if all(
            fc["matches"] for fc in r["file_comparisons"].values()
        ))

        # Assert all tests passed
        failures = []
        for result in results:
            for file_type, comparison in result["file_comparisons"].items():
                if not comparison["matches"]:
                    failures.append(
                        f"\n{result['test_file']} - {file_type}:\n{comparison['diff']}"
                    )

        assert not failures, f"Comparison failures ({len(failures)} files):\n" + "\n".join(failures)
        assert passed_tests == total_tests, f"Only {passed_tests}/{total_tests} test cases passed completely"

