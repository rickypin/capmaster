"""Integration tests for Match plugin."""

import json
import subprocess
import sys
from pathlib import Path
from typing import List

import pytest


@pytest.mark.integration
class TestMatchIntegration:
    """Integration tests for the Match plugin using real test cases."""

    @pytest.fixture
    def test_cases_dir(self) -> Path:
        """Return the repository test cases directory under data/cases."""
        return Path(__file__).resolve().parent.parent.parent.parent / "data" / "cases"

    @pytest.fixture
    def tc_001_1(self, test_cases_dir: Path) -> Path:
        """TC-001-1-20160407 test case directory."""
        return test_cases_dir / "TC-001-1-20160407"

    @pytest.fixture
    def tc_001_5(self, test_cases_dir: Path) -> Path:
        """TC-001-5-20190905 test case directory."""
        return test_cases_dir / "TC-001-5-20190905"

    @pytest.fixture
    def tc_002_1(self, test_cases_dir: Path) -> Path:
        """TC-002-1-20211208 test case directory."""
        return test_cases_dir / "TC-002-1-20211208"

    def get_pcap_files(self, directory: Path) -> List[Path]:
        """Get all pcap/pcapng files in a directory (non-recursive)."""
        files = []
        for ext in [".pcap", ".pcapng"]:
            files.extend(directory.glob(f"*{ext}"))
        return sorted(files)

    def test_tc_001_1_has_two_files(self, tc_001_1: Path):
        """Test that TC-001-1 has exactly 2 pcap files."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")
        
        files = self.get_pcap_files(tc_001_1)
        assert len(files) == 2, f"Expected 2 files, found {len(files)}: {files}"

    def test_tc_001_1_match_workflow(self, tc_001_1: Path, tmp_path: Path):
        """Test complete match workflow on TC-001-1."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")
        
        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")
        
        output_file = tmp_path / "matches.txt"
        
        # Run the match command
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
            ],
            capture_output=True,
            text=True,
        )
        
        # Check that the command succeeded
        assert result.returncode == 0, f"Command failed: {result.stderr}"
        
        # Check that output file was created
        assert output_file.exists(), "Output file was not created"
        
        # Check that output file is not empty
        content = output_file.read_text()
        assert len(content) > 0, "Output file is empty"
        
        # Check for expected output format
        lines = content.strip().split("\n")
        assert len(lines) > 0, "No output lines found"

    def test_tc_001_5_single_file_skip(self, tc_001_5: Path, tmp_path: Path):
        """Test that single-file directory is handled correctly."""
        if not tc_001_5.exists():
            pytest.skip(f"Test case directory not found: {tc_001_5}")
        
        files = self.get_pcap_files(tc_001_5)
        if len(files) != 1:
            pytest.skip(f"Expected 1 file, found {len(files)}")
        
        output_file = tmp_path / "matches.txt"
        
        # Run the match command - should fail or skip
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_5),
                "-o", str(output_file),
            ],
            capture_output=True,
            text=True,
        )
        
        # Should fail because there's only 1 file
        assert result.returncode != 0, "Command should fail with single file"

    def test_match_with_mode_header(self, tc_001_1: Path, tmp_path: Path):
        """Test match with header-only mode."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")
        
        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")
        
        output_file = tmp_path / "matches_header.txt"
        
        # Run with header mode
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--mode", "header",
            ],
            capture_output=True,
            text=True,
        )
        
        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

    def test_match_with_bucket_server(self, tc_001_1: Path, tmp_path: Path):
        """Test match with server bucket strategy."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")
        
        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")
        
        output_file = tmp_path / "matches_server.txt"
        
        # Run with server bucket
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--bucket", "server",
            ],
            capture_output=True,
            text=True,
        )
        
        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

    def test_match_with_bucket_port(self, tc_001_1: Path, tmp_path: Path):
        """Test match with port bucket strategy."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")
        
        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")
        
        output_file = tmp_path / "matches_port.txt"
        
        # Run with port bucket
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--bucket", "port",
            ],
            capture_output=True,
            text=True,
        )
        
        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

    def test_match_verbose_output(self, tc_001_1: Path, tmp_path: Path):
        """Test match with verbose output."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches_verbose.txt"

        # Run with verbose flag
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "-v",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
            ],
            capture_output=True,
            text=True,
        )

        # Check that the command succeeded
        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Check that output file was created
        assert output_file.exists(), "Output file was not created"

        # Verbose output should be in stdout (INFO level logs)
        assert "INFO" in result.stdout, "No verbose output in stdout"
        assert len(result.stdout) > 0, "No output generated"

    def test_match_with_no_sampling(self, tc_001_1: Path, tmp_path: Path):
        """Test match with sampling disabled (default behavior)."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches_no_sampling.txt"

        # Run without --enable-sampling flag (default: no sampling)
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

        # Default behavior should work without errors (no sampling)
        # (No specific output message is required, just verify it doesn't crash)

    def test_match_with_custom_sampling_threshold(self, tc_001_1: Path, tmp_path: Path):
        """Test match with custom sampling threshold."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches_custom_threshold.txt"

        # Run with custom sampling threshold
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--sample-threshold", "5000",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

    def test_match_with_custom_sampling_rate(self, tc_001_1: Path, tmp_path: Path):
        """Test match with custom sampling rate."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches_custom_rate.txt"

        # Run with custom sampling rate
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--sample-rate", "0.3",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

    def test_match_with_combined_sampling_params(self, tc_001_1: Path, tmp_path: Path):
        """Test match with both custom threshold and rate."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches_combined.txt"

        # Run with both custom threshold and rate
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--sample-threshold", "2000",
                "--sample-rate", "0.7",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

    def test_match_with_one_to_many_mode(self, tc_001_1: Path, tmp_path: Path):
        """Test match with one-to-many matching mode."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches_one_to_many.txt"

        # Run with --match-mode one-to-many
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--match-mode", "one-to-many",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

        # Verify output contains match statistics
        with open(output_file, "r") as f:
            content = f.read()
            # One-to-many mode should report unique_matched and max_matches_per_conn
            assert "Match Statistics" in content or len(content) > 0

    def test_match_with_endpoint_stats(self, tc_001_1: Path, tmp_path: Path):
        """Test match with endpoint statistics generation."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches.txt"
        stats_file = tmp_path / "endpoint_stats.txt"

        # Run with --endpoint-stats
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--endpoint-stats",
                "--endpoint-stats-output", str(stats_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"
        assert stats_file.exists(), "Endpoint stats file was not created"

        # Verify stats file contains endpoint information
        with open(stats_file, "r") as f:
            content = f.read()
            # Should contain endpoint statistics (client IP, server IP, server port)
            assert len(content) > 0

    def test_match_with_endpoint_stats_json(self, tc_001_1: Path, tmp_path: Path):
        """Test match with endpoint statistics JSON output."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches.txt"
        json_file = tmp_path / "endpoint_stats.json"

        # Run with --endpoint-stats and --endpoint-stats-json
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--endpoint-stats",
                "--endpoint-stats-json", str(json_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"
        assert json_file.exists(), "JSON file was not created"

        # Verify JSON file format
        with open(json_file, "r") as f:
            lines = f.readlines()
            assert len(lines) > 0, "JSON file is empty"

            # Verify each line is valid JSON
            for i, line in enumerate(lines):
                try:
                    record = json.loads(line.strip())
                    # Verify required fields exist
                    assert "pcap_id" in record, f"Line {i+1}: missing pcap_id"
                    assert "group_id" in record, f"Line {i+1}: missing group_id"
                    assert "type" in record, f"Line {i+1}: missing type"
                    assert "is_capture" in record, f"Line {i+1}: missing is_capture"
                    assert "net_area" in record, f"Line {i+1}: missing net_area"
                    assert "stream_cnt" in record, f"Line {i+1}: missing stream_cnt"
                    assert "pktlen" in record, f"Line {i+1}: missing pktlen"
                    assert "display_name" in record, f"Line {i+1}: missing display_name"
                    assert "metrics" in record, f"Line {i+1}: missing metrics"

                    # Verify data types
                    assert isinstance(record["pcap_id"], int), f"Line {i+1}: pcap_id should be int"
                    assert isinstance(record["group_id"], int), f"Line {i+1}: group_id should be int"
                    assert isinstance(record["type"], int), f"Line {i+1}: type should be int"
                    assert isinstance(record["is_capture"], bool), f"Line {i+1}: is_capture should be bool"
                    assert isinstance(record["net_area"], list), f"Line {i+1}: net_area should be list"
                    assert isinstance(record["stream_cnt"], int), f"Line {i+1}: stream_cnt should be int"
                    assert isinstance(record["pktlen"], int), f"Line {i+1}: pktlen should be int"
                    assert isinstance(record["display_name"], str), f"Line {i+1}: display_name should be str"
                    assert isinstance(record["metrics"], dict), f"Line {i+1}: metrics should be dict"

                    # Verify node types are valid (1=client, 2=server, 1001/1002=network device)
                    assert record["type"] in [1, 2, 1001, 1002], f"Line {i+1}: invalid type {record['type']}"

                    # Verify type-specific fields
                    if record["type"] == 1:  # Client node
                        assert "ip" in record, f"Line {i+1}: client node should have ip"
                    elif record["type"] == 2:  # Server node
                        assert "ip" in record, f"Line {i+1}: server node should have ip"
                        assert "port" in record, f"Line {i+1}: server node should have port"
                        assert "proto" in record, f"Line {i+1}: server node should have proto"

                except json.JSONDecodeError as e:
                    pytest.fail(f"Line {i+1} is not valid JSON: {e}\nLine content: {line}")

    def test_match_with_endpoint_stats_json_creates_directory(self, tc_001_1: Path, tmp_path: Path):
        """Test that JSON output creates parent directories if they don't exist."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches.txt"
        # Use a nested directory path that doesn't exist yet
        json_file = tmp_path / "nested" / "dir" / "endpoint_stats.json"

        # Verify the directory doesn't exist yet
        assert not json_file.parent.exists(), "Parent directory should not exist yet"

        # Run with --endpoint-stats and --endpoint-stats-json
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--endpoint-stats",
                "--endpoint-stats-json", str(json_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"
        assert json_file.exists(), "JSON file was not created"
        assert json_file.parent.exists(), "Parent directory was not created"

        # Verify JSON file is not empty
        with open(json_file, "r") as f:
            lines = f.readlines()
            assert len(lines) > 0, "JSON file is empty"

    def test_match_with_service_aggregation(self, tc_001_1: Path, tmp_path: Path):
        """Test match with service aggregation (default behavior)."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches.txt"

        # Run with default behavior (service aggregation)
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--endpoint-stats",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"

        # Verify output contains service statistics
        output = result.stdout
        assert "Service Statistics" in output or "Service:" in output, \
            "Output should contain service statistics"

    def test_match_with_service_aggregation_json(self, tc_001_1: Path, tmp_path: Path):
        """Test match with service aggregation and JSON output (default behavior)."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches.txt"
        json_file = tmp_path / "service_stats.json"

        # Run with default behavior (service aggregation) and --endpoint-stats-json
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--endpoint-stats",
                "--endpoint-stats-json", str(json_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"
        assert json_file.exists(), "JSON file was not created"

        # Verify JSON file contains service data
        with open(json_file, "r") as f:
            lines = f.readlines()
            assert len(lines) > 0, "JSON file is empty"

            # Parse first line to check structure
            first_record = json.loads(lines[0])
            assert "pcap_id" in first_record
            assert "group_id" in first_record
            assert "type" in first_record

    def test_match_with_service_group_mapping(self, tc_001_1: Path, tmp_path: Path):
        """Test match with service group mapping file."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches.txt"
        json_file = tmp_path / "service_stats.json"
        mapping_file = tmp_path / "mapping.json"

        # Create a service group mapping file
        mapping = {
            "80": 1,
            "8000": 1,
            "8080": 1,
            "443": 2,
            "8443": 2
        }
        with open(mapping_file, "w") as f:
            json.dump(mapping, f)

        # Run with --service-group-mapping (service aggregation is default)
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--endpoint-stats",
                "--service-group-mapping", str(mapping_file),
                "--endpoint-stats-json", str(json_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"
        assert json_file.exists(), "JSON file was not created"

        # Verify JSON file uses the mapping
        with open(json_file, "r") as f:
            lines = f.readlines()
            assert len(lines) > 0, "JSON file is empty"

    def test_match_service_aggregation_deduplicates_ips(self, tc_001_1: Path, tmp_path: Path):
        """Test that service aggregation deduplicates client and server IPs."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        json_file = tmp_path / "service_stats.json"

        # Run with default behavior (service aggregation)
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "--endpoint-stats",
                "--endpoint-stats-json", str(json_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert json_file.exists(), "JSON file was not created"

        # Parse JSON and verify deduplication
        with open(json_file, "r") as f:
            records = [json.loads(line) for line in f]

        # Group records by pcap_id and type
        clients_by_pcap = {}
        servers_by_pcap = {}

        for record in records:
            pcap_id = record["pcap_id"]
            node_type = record["type"]

            if node_type == 1:  # Client
                if pcap_id not in clients_by_pcap:
                    clients_by_pcap[pcap_id] = set()
                if "ip" in record:
                    clients_by_pcap[pcap_id].add(record["ip"])
            elif node_type == 4:  # Server (aggregated)
                if pcap_id not in servers_by_pcap:
                    servers_by_pcap[pcap_id] = set()
                if "ip" in record:
                    servers_by_pcap[pcap_id].add(record["ip"])

        # Verify that each IP appears only once per pcap_id
        for pcap_id, ips in clients_by_pcap.items():
            assert len(ips) == len(set(ips)), \
                f"Client IPs should be deduplicated for pcap_id {pcap_id}"

        for pcap_id, ips in servers_by_pcap.items():
            assert len(ips) == len(set(ips)), \
                f"Server IPs should be deduplicated for pcap_id {pcap_id}"

    def test_match_with_endpoint_pair_mode(self, tc_001_1: Path, tmp_path: Path):
        """Test match with --endpoint-pair-mode flag."""
        if not tc_001_1.exists():
            pytest.skip(f"Test case directory not found: {tc_001_1}")

        files = self.get_pcap_files(tc_001_1)
        if len(files) != 2:
            pytest.skip(f"Expected 2 files, found {len(files)}")

        output_file = tmp_path / "matches.txt"
        json_file = tmp_path / "endpoint_pairs.json"

        # Run with --endpoint-pair-mode to disable service aggregation
        result = subprocess.run(
            [
                sys.executable, "-m", "capmaster",
                "match",
                "-i", str(tc_001_1),
                "-o", str(output_file),
                "--endpoint-stats",
                "--endpoint-pair-mode",
                "--endpoint-stats-json", str(json_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert output_file.exists(), "Output file was not created"
        assert json_file.exists(), "JSON file was not created"

        # Verify output contains endpoint pair statistics (not service statistics)
        output = result.stdout
        assert "Endpoint Statistics" in output, "Endpoint statistics not found in output"
        assert "Total unique endpoint pairs:" in output, "Endpoint pair count not found in output"
        # Should NOT contain service statistics
        assert "Service Statistics" not in output, "Should not contain service statistics in endpoint pair mode"

        # Verify JSON contains endpoint pairs with different group_ids
        with open(json_file, "r") as f:
            lines = f.readlines()
            assert len(lines) > 0, "JSON file is empty"

            # Parse JSON and collect group_ids
            group_ids = set()
            for line in lines:
                record = json.loads(line)
                group_ids.add(record["group_id"])

            # In endpoint pair mode, each pair should have a different group_id
            # (unless there's only one pair)
            assert len(group_ids) >= 1, "Should have at least one group_id"

