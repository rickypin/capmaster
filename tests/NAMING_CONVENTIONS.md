# Test Naming Conventions

This document defines the naming conventions for tests in the CapMaster project.

## File Naming

### Test Files

```
test_<component>.py          # Unit tests for a component
test_<component>_unit.py     # Explicit unit tests (when both unit and integration exist)
test_integration.py          # Integration tests for a module
```

**Examples:**
- `test_file_scanner.py` - Unit tests for file scanner
- `test_tshark_wrapper.py` - Unit tests for tshark wrapper
- `test_plugin_unit.py` - Unit tests for plugin (when integration tests also exist)
- `test_integration.py` - Integration tests for the module

### Test Directories

```
tests/
├── test_core/              # Core functionality tests
├── test_plugins/           # Plugin tests
│   ├── test_analyze/       # Analyze plugin tests
│   ├── test_match/         # Match plugin tests
│   ├── test_preprocess/    # Preprocess plugin tests
│   ├── test_topology/      # Topology plugin tests
│   ├── test_streamdiff/    # StreamDiff plugin tests
│   ├── test_pipeline/      # Pipeline plugin tests
│   └── test_compare/       # Compare plugin tests
├── fixtures/               # Test fixtures and builders
└── legacy/                 # Deprecated tests (ignored by default)
```

---

## Class Naming

### Unit Test Classes

```python
class TestComponentName:
    """Unit tests for ComponentName."""
```

**Examples:**
```python
class TestFileScanner:
    """Unit tests for FileScanner."""

class TestTsharkWrapper:
    """Unit tests for TsharkWrapper."""

class TestFlowHash:
    """Unit tests for flow hash calculation."""
```

### Integration Test Classes

```python
@pytest.mark.integration
class TestComponentNameIntegration:
    """Integration tests for ComponentName."""
```

**Examples:**
```python
@pytest.mark.integration
class TestAnalyzePluginIntegration:
    """Integration tests for AnalyzePlugin."""

@pytest.mark.integration
class TestMatchWorkflow:
    """Integration tests for match workflow."""
```

### Feature-Specific Test Classes

```python
class TestComponentFeature:
    """Tests for specific feature of Component."""
```

**Examples:**
```python
class TestFileScannerRecursive:
    """Tests for recursive scanning feature."""

class TestFlowHashRustCompatibility:
    """Tests for Rust compatibility of flow hash."""
```

---

## Method Naming

### Basic Pattern

```python
def test_<action>_<expected_result>():
    """Test that <action> <expected_result>."""
```

**Examples:**
```python
def test_scan_returns_pcap_files():
    """Test that scan returns PCAP files."""

def test_execute_creates_output_directory():
    """Test that execute creates output directory."""

def test_calculate_hash_returns_string():
    """Test that calculate_hash returns a string."""
```

### With Conditions

```python
def test_<action>_<condition>_<expected_result>():
    """Test that <action> <expected_result> when <condition>."""
```

**Examples:**
```python
def test_scan_empty_directory_returns_empty_list():
    """Test that scanning empty directory returns empty list."""

def test_execute_invalid_input_returns_error():
    """Test that execute returns error with invalid input."""

def test_match_single_file_skips_processing():
    """Test that match skips processing with single file."""
```

### Error/Edge Cases

```python
def test_<action>_with_<error_condition>():
    """Test <action> with <error_condition>."""

def test_<action>_handles_<error_condition>():
    """Test that <action> handles <error_condition>."""
```

**Examples:**
```python
def test_scan_with_missing_directory():
    """Test scan with missing directory."""

def test_execute_handles_permission_error():
    """Test that execute handles permission error."""

def test_parse_handles_malformed_data():
    """Test that parse handles malformed data."""
```

### Parametrized Tests

```python
@pytest.mark.parametrize("input,expected", [...])
def test_<action>_with_various_inputs(input, expected):
    """Test <action> with various inputs."""
```

**Examples:**
```python
@pytest.mark.parametrize("extension", [".pcap", ".pcapng"])
def test_scan_finds_files_with_extension(extension):
    """Test that scan finds files with given extension."""

@pytest.mark.parametrize("threshold,expected", [(5, 2), (10, 1)])
def test_detect_with_threshold(threshold, expected):
    """Test detection with different thresholds."""
```

---

## Docstring Conventions

### Basic Format

```python
def test_something():
    """Test that something works correctly.
    
    This test verifies that the component behaves as expected
    when given valid input.
    """
```

### With Setup/Teardown

```python
def test_something_complex():
    """Test complex scenario.
    
    Setup:
        - Create test PCAP file
        - Initialize plugin
    
    Test:
        - Execute plugin
        - Verify output
    
    Expected:
        - Exit code is 0
        - Output file exists
    """
```

### Integration Tests

```python
@pytest.mark.integration
def test_end_to_end_workflow():
    """Test complete end-to-end workflow.
    
    This integration test verifies the entire workflow from
    input to output, including all intermediate steps.
    
    Requirements:
        - tshark must be installed
        - Test PCAP files must be available
    """
```

---

## Marker Conventions

### Integration Tests

```python
@pytest.mark.integration
class TestSomethingIntegration:
    """Integration tests."""
```

### Slow Tests

```python
@pytest.mark.slow
def test_large_file_processing():
    """Test processing of large files (slow)."""
```

### Skip Conditions

```python
@pytest.mark.skipif(not TSHARK_AVAILABLE, reason="tshark not installed")
def test_requires_tshark():
    """Test that requires tshark."""
```

### Platform-Specific

```python
@pytest.mark.skipif(os.name == "nt", reason="Unix-only test")
def test_unix_permissions():
    """Test Unix file permissions."""
```

---

## Examples by Category

### 1. Unit Tests

```python
class TestFlowHash:
    """Unit tests for flow hash calculation."""
    
    def test_calculate_hash_returns_string(self):
        """Test that calculate_hash returns a string."""
    
    def test_calculate_hash_same_input_same_output(self):
        """Test that same input produces same hash."""
    
    def test_calculate_hash_bidirectional_same_result(self):
        """Test that bidirectional flows produce same hash."""
    
    def test_calculate_hash_with_invalid_input_raises_error(self):
        """Test that invalid input raises ValueError."""
```

### 2. Integration Tests

```python
@pytest.mark.integration
class TestAnalyzePluginIntegration:
    """Integration tests for AnalyzePlugin."""
    
    def test_execute_creates_all_output_files(self):
        """Test that execute creates all expected output files."""
    
    def test_execute_with_real_pcap_succeeds(self):
        """Test that execute succeeds with real PCAP file."""
    
    def test_execute_with_voip_pcap_includes_sip_stats(self):
        """Test that VoIP PCAP includes SIP statistics."""
```

### 3. Error Handling Tests

```python
class TestErrorHandling:
    """Tests for error handling."""
    
    def test_execute_with_missing_file_returns_error(self):
        """Test that missing file returns error code."""
    
    def test_execute_with_invalid_pcap_shows_error_message(self):
        """Test that invalid PCAP shows helpful error message."""
    
    def test_execute_handles_permission_error_gracefully(self):
        """Test that permission errors are handled gracefully."""
```

### 4. Boundary Tests

```python
class TestBoundaryConditions:
    """Tests for boundary conditions."""
    
    def test_scan_empty_directory_returns_empty_list(self):
        """Test that empty directory returns empty list."""
    
    def test_execute_with_empty_pcap_succeeds(self):
        """Test that empty PCAP file is handled correctly."""
    
    def test_match_with_very_large_file_completes(self):
        """Test that very large files can be processed."""
```

---

## Anti-Patterns to Avoid

### ❌ Bad Names

```python
def test1():  # Not descriptive
def test_stuff():  # Too vague
def test_it_works():  # What works?
def test_bug_fix():  # Which bug?
def test_issue_123():  # Not self-documenting
```

### ✅ Good Names

```python
def test_scan_returns_only_pcap_files():
def test_execute_creates_statistics_directory():
def test_calculate_hash_handles_ipv6_addresses():
def test_filter_removes_one_way_streams():
def test_match_finds_corresponding_packets():
```

### ❌ Bad Class Names

```python
class Tests:  # Too generic
class TestStuff:  # Not specific
class MyTests:  # Not descriptive
```

### ✅ Good Class Names

```python
class TestFileScanner:
class TestAnalyzePlugin:
class TestFlowHashCalculation:
class TestOneWayDetector:
```

---

## Checklist for New Tests

When writing a new test, ensure:

- [ ] File name follows `test_<component>.py` pattern
- [ ] Class name follows `TestComponentName` pattern
- [ ] Method name follows `test_<action>_<expected_result>` pattern
- [ ] Docstring clearly describes what is being tested
- [ ] Integration tests are marked with `@pytest.mark.integration`
- [ ] Slow tests are marked with `@pytest.mark.slow`
- [ ] Skip conditions are documented with clear reasons
- [ ] Test is in the appropriate directory

---

## Migration Guide

If you have existing tests that don't follow these conventions:

1. **Don't rename everything at once** - Focus on new tests
2. **Rename when refactoring** - Update names when modifying tests
3. **Document exceptions** - If a test can't follow conventions, document why
4. **Use automation** - Consider scripts to detect naming violations

---

## Tools

### Check Naming Violations

```bash
# Find tests without proper naming
grep -r "def test_test" tests/

# Find classes without Test prefix
grep -r "^class [^T].*:" tests/

# Find integration tests without marker
grep -l "Integration" tests/ | xargs grep -L "@pytest.mark.integration"
```

### Rename Tests

```bash
# Use your IDE's refactoring tools
# Most IDEs support "Rename" with automatic reference updates
```

---

## References

- [pytest naming conventions](https://docs.pytest.org/en/stable/goodpractices.html#test-discovery)
- [PEP 8 - Style Guide for Python Code](https://peps.python.org/pep-0008/)
- [Google Python Style Guide - Testing](https://google.github.io/styleguide/pyguide.html#s3.8-comments-and-docstrings)

