# CapMaster Test Suite

This directory contains the test suite for CapMaster, a unified Python CLI tool for PCAP analysis.

## Test Organization

```
tests/
├── test_core/              # Core functionality tests
│   ├── test_file_scanner.py
│   ├── test_output_manager.py
│   ├── test_protocol_detector.py
│   └── test_tshark_wrapper.py
├── test_plugins/           # Plugin tests
│   ├── test_analyze/       # Analyze plugin tests
│   ├── test_compare/       # Compare plugin tests
│   ├── test_match/         # Match plugin tests
│   ├── test_pipeline/      # Pipeline plugin tests
│   ├── test_preprocess/    # Preprocess plugin tests
│   ├── test_streamdiff/    # StreamDiff plugin tests
│   └── test_topology/      # Topology plugin tests
├── test_flow_hash.py       # Flow hash unit tests
├── test_flow_hash_rust_compatibility.py  # Rust compatibility tests
└── conftest.py             # Shared fixtures
```

## Test Categories

### Unit Tests (79 tests)
Fast, isolated tests that mock external dependencies.

**Examples:**
- `test_core/test_file_scanner.py` - File scanning logic
- `test_plugins/test_preprocess/test_pcap_tools_unit.py` - Preprocess helpers and one-way detection
- `test_flow_hash.py` - Flow hash calculation

**Run unit tests only:**
```bash
pytest -m "not integration" -v
```

### Integration Tests (204 tests)
Tests that use real components and may require external dependencies.

**Examples:**
- `test_plugins/test_analyze/test_integration.py` - Full analyze workflow
- `test_plugins/test_preprocess/test_integration.py` - Preprocess workflow with real PCAP files
- `test_plugins/test_match/test_integration.py` - Match workflow

**Run integration tests only:**
```bash
pytest -m integration -v
```

## Running Tests

### Quick Start

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=capmaster --cov-report=term

# Run specific test file
pytest tests/test_core/test_file_scanner.py -v

# Run specific test class
pytest tests/test_core/test_file_scanner.py::TestPcapScanner -v

# Run specific test method
pytest tests/test_core/test_file_scanner.py::TestPcapScanner::test_scan_single_file -v
```

### By Category

```bash
# Core functionality
pytest tests/test_core/ -v

# Analyze plugin
pytest tests/test_plugins/test_analyze/ -v

# Compare plugin
pytest tests/test_plugins/test_compare/ -v

# Match plugin
pytest tests/test_plugins/test_match/ -v

# Preprocess plugin
pytest tests/test_plugins/test_preprocess/ -v

# All plugins
pytest tests/test_plugins/ -v
```

### By Marker

```bash
# Integration tests only
pytest -m integration -v

# Unit tests only (fast)
pytest -m "not integration" -v

# Slow tests only
pytest -m slow -v

# Skip slow tests
pytest -m "not slow" -v
```

### With Filters

```bash
# Run tests matching pattern
pytest -k "test_scan" -v

# Run tests NOT matching pattern
pytest -k "not integration" -v

# Multiple patterns
pytest -k "test_scan or test_parse" -v
```

## External Dependencies

### Required

- **Python 3.10+** - Required for type annotations
- **tshark 4.0+** - Required for PCAP processing
  ```bash
  # macOS
  brew install wireshark
  
  # Ubuntu/Debian
  sudo apt-get install tshark
  
  # Verify installation
  tshark --version
  ```

### Optional Test Data

Some integration tests require PCAP files in the `data/cases/` directory:

```
data/cases/
├── V-001/VOIP.pcap              # VoIP test case
├── TC-001-1-20160407/           # TCP connection matching
├── TC-001-5-20190905/           # Single file test
└── ... (more test cases)
```

**Note:** These files are in `.gitignore` and not included in the repository.

Tests will automatically skip if required files are not found:
```python
@pytest.fixture
def test_pcap(self) -> Path:
    pcap_path = Path("data/cases/V-001/VOIP.pcap")
    if not pcap_path.exists():
        pytest.skip(f"Test PCAP file not found: {pcap_path}")
    return pcap_path
```

## Test Fixtures

Common fixtures are defined in `conftest.py`:

### Basic Fixtures

```python
@pytest.fixture
def runner() -> CliRunner:
    """Click CLI test runner."""

@pytest.fixture
def tmp_path(tmp_path_factory) -> Path:
    """Temporary directory path."""

@pytest.fixture
def temp_output(tmp_path: Path) -> Iterator[Path]:
    """Temporary output directory."""
```

### PCAP File Fixtures

**Simple PCAP Files:**

```python
@pytest.fixture
def test_pcap(tmp_path: Path) -> Path:
    """Create a minimal test PCAP file (header only)."""

@pytest.fixture
def test_pcap_with_packets(tmp_path: Path) -> Path:
    """Create a PCAP file with 3 TCP SYN packets."""

@pytest.fixture
def test_dir(tmp_path: Path) -> Path:
    """Create a directory with 3 PCAP files."""
```

**Advanced PCAP Fixtures:**

```python
@pytest.fixture
def tcp_connection_pcap(tmp_path: Path) -> Path:
    """Complete TCP connection (SYN, SYN-ACK, ACK, data, FIN)."""

@pytest.fixture
def multi_connection_pcap(tmp_path: Path) -> Path:
    """Multiple TCP connections to different servers."""

@pytest.fixture
def mixed_protocol_pcap(tmp_path: Path) -> Path:
    """Mixed protocols: TCP, UDP, and ICMP packets."""

@pytest.fixture
def pcap_builder() -> type[PcapBuilder]:
    """PcapBuilder class for custom PCAP creation."""
```

**Example Usage:**

```python
def test_with_tcp_connection(tcp_connection_pcap):
    """Test using pre-built TCP connection."""
    # tcp_connection_pcap is a Path to a valid PCAP file
    result = analyze_pcap(tcp_connection_pcap)
    assert result.connection_count == 1

def test_with_custom_pcap(pcap_builder, tmp_path):
    """Test with custom-built PCAP."""
    pcap = (pcap_builder()
        .add_tcp_packet("192.168.1.1", "10.0.0.1", 1234, 80)
        .add_tcp_packet("10.0.0.1", "192.168.1.1", 80, 1234)
        .build(tmp_path / "custom.pcap"))

    result = analyze_pcap(pcap)
    assert result.packet_count == 2
```

## Writing New Tests

### Test File Naming

- Unit tests: `test_<component>.py`
- Integration tests: `test_<component>_integration.py` or `test_integration.py`

### Test Class Naming

```python
# Unit test
class TestComponentName:
    """Test ComponentName functionality."""

# Integration test
@pytest.mark.integration
class TestComponentNameIntegration:
    """Integration tests for ComponentName."""
```

### Test Method Naming

```python
def test_<what_is_being_tested>_<expected_behavior>(self):
    """Test that <component> <does something> when <condition>."""
```

### Example Test

```python
"""Tests for MyComponent."""

import pytest
from capmaster.core.my_component import MyComponent


@pytest.mark.integration  # If integration test
class TestMyComponent:
    """Test MyComponent functionality."""
    
    @pytest.fixture
    def component(self):
        """Create a MyComponent instance."""
        return MyComponent()
    
    def test_process_returns_expected_result(self, component):
        """Test that process() returns expected result."""
        # Arrange
        input_data = "test"
        
        # Act
        result = component.process(input_data)
        
        # Assert
        assert result == "expected"
```

## Continuous Integration

Tests are run automatically on:
- Pull requests
- Commits to main branch

CI configuration runs:
```bash
# Fast tests first
pytest -m "not integration" --cov=capmaster

# Then integration tests
pytest -m integration

# Type checking
mypy capmaster/

# Linting
ruff check capmaster/

# Formatting check
black --check capmaster/
```

## Troubleshooting

### Tests fail with "tshark not found"

Install tshark (see External Dependencies above).

### Tests fail with "PCAP file not found"

Integration tests that require specific PCAP files will skip automatically.
This is expected behavior if you don't have the test data.

### Type annotation errors on Python 3.9

The project requires Python 3.10+ for modern type annotations.
Upgrade Python or use a virtual environment with Python 3.10+.

### Import errors

Make sure CapMaster is installed in development mode:
```bash
pip install -e ".[dev]"
```

## Test Coverage

Current coverage: **~80%+**

View detailed coverage report:
```bash
pytest --cov=capmaster --cov-report=html
open htmlcov/index.html
```

## Contributing

When adding new features:

1. Write tests first (TDD)
2. Ensure tests pass: `pytest`
3. Check coverage: `pytest --cov=capmaster`
4. Run type checking: `mypy capmaster/`
5. Run linting: `ruff check capmaster/`
6. Format code: `black capmaster/`

## Questions?

See the main project documentation:
- `README.md` - Project overview
- `docs/USER_GUIDE.md` - User guide
- `docs/QUICK_REFERENCE.md` - Quick reference

