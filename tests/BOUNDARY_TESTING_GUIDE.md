# Boundary Testing Guide

This guide provides examples and best practices for writing boundary condition and negative tests for CapMaster.

## What are Boundary Tests?

Boundary tests verify that the system handles edge cases and error conditions correctly:

- **Empty inputs** - Empty files, empty directories, empty strings
- **Invalid inputs** - Malformed data, wrong file types, invalid arguments
- **Extreme values** - Very large files, very long strings, maximum/minimum values
- **Missing resources** - Non-existent files, missing permissions, unavailable tools
- **Error conditions** - Network errors, disk full, process failures

## Why Boundary Tests Matter

1. **Robustness** - Ensure the system doesn't crash on unexpected input
2. **User Experience** - Provide helpful error messages instead of stack traces
3. **Security** - Prevent exploitation through malformed input
4. **Reliability** - Handle real-world scenarios gracefully

---

## Examples by Category

### 1. Empty Input Tests

```python
def test_analyze_empty_pcap(tmp_path: Path):
    """Test analyzing an empty PCAP file."""
    # Create empty PCAP (header only)
    empty_pcap = tmp_path / "empty.pcap"
    empty_pcap.write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
    
    plugin = AnalyzePlugin()
    exit_code = plugin.execute(
        input_path=empty_pcap,
        output_dir=tmp_path / "output",
    )
    
    # Should handle gracefully
    assert exit_code == 0

def test_scan_empty_directory(tmp_path: Path):
    """Test scanning an empty directory."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    
    scanner = PcapScanner()
    files = list(scanner.scan(empty_dir))
    
    # Should return empty list, not crash
    assert len(files) == 0
```

### 2. Invalid Input Tests

```python
def test_analyze_invalid_pcap(tmp_path: Path):
    """Test analyzing a file with invalid PCAP header."""
    invalid_pcap = tmp_path / "invalid.pcap"
    invalid_pcap.write_bytes(b"NOT A PCAP FILE")
    
    plugin = AnalyzePlugin()
    exit_code = plugin.execute(
        input_path=invalid_pcap,
        output_dir=tmp_path / "output",
    )
    
    # Should fail gracefully with non-zero exit code
    assert exit_code != 0

def test_match_with_wrong_file_type(tmp_path: Path):
    """Test match plugin with non-PCAP file."""
    text_file = tmp_path / "test.txt"
    text_file.write_text("This is not a PCAP file")
    
    plugin = MatchPlugin()
    exit_code = plugin.execute(
        input_path=text_file,
        output_path=tmp_path / "output.txt",
    )
    
    # Should reject invalid file type
    assert exit_code != 0
```

### 3. Missing Resource Tests

```python
def test_analyze_nonexistent_file():
    """Test analyzing a file that doesn't exist."""
    plugin = AnalyzePlugin()
    exit_code = plugin.execute(
        input_path=Path("/nonexistent/file.pcap"),
        output_dir=Path("/tmp/output"),
    )
    
    # Should fail with clear error
    assert exit_code != 0

def test_filter_with_missing_tshark(tmp_path: Path, monkeypatch):
    """Test filter plugin when tshark is not available."""
    # Mock subprocess to simulate missing tshark
    def mock_run(*args, **kwargs):
        raise FileNotFoundError("tshark not found")
    
    monkeypatch.setattr("subprocess.run", mock_run)
    
    pcap_file = tmp_path / "test.pcap"
    pcap_file.touch()
    
    plugin = FilterPlugin()
    exit_code = plugin.execute(
        input_path=pcap_file,
        output_path=tmp_path / "output.pcap",
    )
    
    # Should handle missing dependency gracefully
    assert exit_code != 0
```

### 4. Extreme Value Tests

```python
def test_analyze_very_large_pcap(tmp_path: Path):
    """Test analyzing a very large PCAP file."""
    # Create a PCAP with many packets
    builder = PcapBuilder()
    for i in range(10000):
        builder.add_tcp_packet(
            f"192.168.{i // 256}.{i % 256}",
            "10.0.0.1",
            50000 + i,
            80,
        )
    
    large_pcap = builder.build(tmp_path / "large.pcap")
    
    plugin = AnalyzePlugin()
    exit_code = plugin.execute(
        input_path=large_pcap,
        output_dir=tmp_path / "output",
    )
    
    # Should handle large files
    assert exit_code == 0

def test_match_with_very_long_path(tmp_path: Path):
    """Test match with very long file path."""
    # Create deeply nested directory
    deep_dir = tmp_path
    for i in range(50):
        deep_dir = deep_dir / f"level{i}"
    deep_dir.mkdir(parents=True)
    
    pcap_file = deep_dir / "test.pcap"
    pcap_file.touch()
    
    plugin = MatchPlugin()
    # Should handle long paths
    # (May fail on some systems, but shouldn't crash)
    try:
        exit_code = plugin.execute(
            input_path=pcap_file,
            output_path=tmp_path / "output.txt",
        )
        assert exit_code is not None
    except OSError:
        # Path too long is acceptable failure
        pass
```

### 5. Permission Error Tests

```python
@pytest.mark.skipif(os.name == "nt", reason="Unix-only test")
def test_analyze_unreadable_file(tmp_path: Path):
    """Test analyzing a file without read permission."""
    pcap_file = tmp_path / "unreadable.pcap"
    pcap_file.touch()
    pcap_file.chmod(0o000)  # Remove all permissions
    
    try:
        plugin = AnalyzePlugin()
        exit_code = plugin.execute(
            input_path=pcap_file,
            output_dir=tmp_path / "output",
        )
        
        # Should fail gracefully
        assert exit_code != 0
    finally:
        # Restore permissions for cleanup
        pcap_file.chmod(0o644)

@pytest.mark.skipif(os.name == "nt", reason="Unix-only test")
def test_filter_unwritable_output(tmp_path: Path):
    """Test filter with unwritable output directory."""
    pcap_file = tmp_path / "input.pcap"
    pcap_file.touch()
    
    output_dir = tmp_path / "readonly"
    output_dir.mkdir()
    output_dir.chmod(0o444)  # Read-only
    
    try:
        plugin = FilterPlugin()
        exit_code = plugin.execute(
            input_path=pcap_file,
            output_path=output_dir / "output.pcap",
        )
        
        # Should fail gracefully
        assert exit_code != 0
    finally:
        # Restore permissions for cleanup
        output_dir.chmod(0o755)
```

### 6. Malformed Data Tests

```python
def test_flow_hash_with_malformed_packet():
    """Test flow hash with malformed packet data."""
    # Create packet with invalid IP addresses
    malformed_packet = {
        "src_ip": "not.an.ip.address",
        "dst_ip": "256.256.256.256",
        "src_port": 99999,  # Invalid port
        "dst_port": -1,  # Invalid port
        "protocol": "INVALID",
    }
    
    # Should handle gracefully
    try:
        hash_value = calculate_flow_hash(malformed_packet)
        # If it succeeds, hash should be valid
        assert isinstance(hash_value, str)
    except ValueError:
        # Raising ValueError is also acceptable
        pass

def test_detector_with_corrupted_pcap(tmp_path: Path):
    """Test detector with corrupted PCAP file."""
    corrupted_pcap = tmp_path / "corrupted.pcap"
    
    # Create PCAP with valid header but corrupted packet data
    header = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
    corrupted_data = b"\xFF" * 100  # Random garbage
    corrupted_pcap.write_bytes(header + corrupted_data)
    
    detector = OneWayDetector()
    
    # Should handle corrupted data gracefully
    try:
        result = detector.analyze(corrupted_pcap)
        assert result is not None
    except Exception as e:
        # Should raise a specific exception, not crash
        assert "corrupt" in str(e).lower() or "invalid" in str(e).lower()
```

---

## Best Practices

### 1. Test Error Messages

```python
def test_error_message_is_helpful(tmp_path: Path):
    """Test that error messages are helpful to users."""
    plugin = AnalyzePlugin()
    
    # Capture stderr
    import io
    import sys
    captured = io.StringIO()
    sys.stderr = captured
    
    try:
        plugin.execute(
            input_path=Path("/nonexistent.pcap"),
            output_dir=tmp_path,
        )
    finally:
        sys.stderr = sys.__stderr__
    
    error_output = captured.getvalue()
    
    # Error message should be informative
    assert "not found" in error_output.lower() or "does not exist" in error_output.lower()
    # Should not contain stack traces in production mode
    assert "Traceback" not in error_output
```

### 2. Test Cleanup on Failure

```python
def test_cleanup_on_failure(tmp_path: Path):
    """Test that temporary files are cleaned up on failure."""
    plugin = AnalyzePlugin()
    
    # Force a failure
    exit_code = plugin.execute(
        input_path=Path("/nonexistent.pcap"),
        output_dir=tmp_path / "output",
    )
    
    assert exit_code != 0
    
    # Check that no partial output was left behind
    output_dir = tmp_path / "output"
    if output_dir.exists():
        # If directory was created, it should be empty or cleaned up
        assert len(list(output_dir.iterdir())) == 0
```

### 3. Test Concurrent Access

```python
def test_concurrent_file_access(tmp_path: Path):
    """Test handling of concurrent file access."""
    import threading
    
    pcap_file = tmp_path / "test.pcap"
    pcap_file.touch()
    
    results = []
    
    def analyze():
        plugin = AnalyzePlugin()
        exit_code = plugin.execute(
            input_path=pcap_file,
            output_dir=tmp_path / f"output_{threading.current_thread().name}",
        )
        results.append(exit_code)
    
    # Run multiple threads
    threads = [threading.Thread(target=analyze) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    # All should complete (may succeed or fail, but shouldn't crash)
    assert len(results) == 5
```

---

## Checklist for New Features

When adding a new feature, ensure you have tests for:

- [ ] Empty input
- [ ] Invalid input format
- [ ] Missing required files/resources
- [ ] Permission errors
- [ ] Very large inputs
- [ ] Malformed data
- [ ] Concurrent access (if applicable)
- [ ] Helpful error messages
- [ ] Proper cleanup on failure

---

## Running Boundary Tests

```bash
# Run all tests including boundary tests
pytest

# Run only tests with "invalid" or "error" in the name
pytest -k "invalid or error"

# Run with verbose output to see error messages
pytest -v --tb=short

# Run with coverage to ensure error paths are tested
pytest --cov=capmaster --cov-report=html
```

---

## Additional Resources

- [pytest documentation](https://docs.pytest.org/)
- [Python unittest.mock](https://docs.python.org/3/library/unittest.mock.html)
- [Testing Best Practices](https://docs.python-guide.org/writing/tests/)

