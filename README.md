# CapMaster

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A unified Python CLI tool for PCAP analysis and TCP connection matching. CapMaster replaces legacy shell scripts with a modern, maintainable, and extensible Python application.

## Features

- 📊 **Comprehensive PCAP Analysis** - 28 statistical analysis modules for protocol hierarchy, TCP/UDP conversations, DNS, HTTP, TLS, VoIP (SIP/RTP/RTCP/MGCP), SSH, and more
- 🔗 **Intelligent TCP Connection Matching** - Advanced 8-feature scoring algorithm to match TCP connections across multiple PCAP files
- 🔍 **One-Way Connection Analysis** - Detect one-way TCP connections in PCAP files
- 🚀 **High Performance** - Achieves ≥90% of original shell script performance with better accuracy
- 🎨 **Beautiful CLI** - Rich terminal output with colors and formatting
- 🧪 **Well Tested** - 87% test coverage with comprehensive unit and integration tests
- 🔧 **Extensible** - Plugin-based architecture for easy extension

## Requirements

- **Python**: 3.10 or higher
- **tshark**: 4.0 or higher (from Wireshark)

### Installing tshark

**macOS:**
```bash
brew install wireshark
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install tshark
```

**Verify installation:**
```bash
tshark -v
```

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/capmaster.git
cd capmaster

# Create virtual environment
python3.10 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install production dependencies
pip install -r requirements.txt

# Or install in editable mode with development dependencies
pip install -e ".[dev]"

# Optional: Install database support (for PostgreSQL output)
pip install -e ".[database]"
# Or: pip install -r requirements-database.txt

# Verify installation
capmaster --version
```

### Using pip (when published)

```bash
# Basic installation
pip install capmaster

# With database support
pip install capmaster[database]

# With development tools
pip install capmaster[dev]
```

### Dependency Management

The project uses version-locked dependencies for reproducible builds:

- **requirements.txt** - Production dependencies (locked versions)
- **requirements-dev.txt** - Development dependencies (testing, linting, type checking)
- **requirements-database.txt** - Optional database dependencies (PostgreSQL support)

To ensure consistent environments:
```bash
# Production environment
pip install -r requirements.txt

# Development environment
pip install -r requirements-dev.txt

# With database support
pip install -r requirements-database.txt
```

## macOS Binary Packaging

Use the PyInstaller tooling in this repo to produce a standalone macOS binary:

1. Create a clean environment with Python 3.12: `python3.12 -m venv .venv && source .venv/bin/activate`.
2. Install all dependencies plus PyInstaller 6.x: `pip install -r requirements.txt -r requirements-dev.txt -r requirements-database.txt && pip install "pyinstaller==6.*"`.
3. Build the binary: `./scripts/build_binary.sh`. The script checks for `tshark`, signs the binary, copies the result to `dist/capmaster`, and archives `artifacts/capmaster-macos-<arch>-v<version>.tar.gz`.
4. Run the smoke test to ensure the bundle boots: `./scripts/tests/run_binary_smoke.sh dist/capmaster` (optional `SMOKE_PCAP` overrides the analyzer input).

For more background (spec layout, hooks, release checklist), see `docs/BINARY_PACKAGING_PLAN.md`.

## Quick Start

### 1. Analyze PCAP Files

Analyze a single PCAP file and generate comprehensive statistics:

```bash
capmaster analyze -i sample.pcap
```

Analyze all PCAP files in a directory:

```bash
capmaster analyze -i /path/to/pcaps/ -r
```

**Output:** Statistics files are saved to `<input_dir>/statistics/` by default.

### 2. Match TCP Connections

Match TCP connections between two PCAP files (e.g., client-side and server-side captures):

```bash
capmaster match -i /path/to/pcap/directory/
```

With custom options:

```bash
capmaster match -i /path/to/pcaps/ \
  --mode auto \
  --bucket server \
  --threshold 0.60 \
  -o matches.txt
```

**Output:** Matched connection pairs with similarity scores.

## Command Reference

### Global Options

```bash
capmaster [OPTIONS] COMMAND [ARGS]...

Options:
  --version      Show the version and exit
  -v, --verbose  Increase verbosity (-v for INFO, -vv for DEBUG)
  --help         Show this message and exit
```

### `analyze` - PCAP Analysis

Analyze PCAP files and generate comprehensive statistics.

```bash
capmaster analyze [OPTIONS]

Options:
  -i, --input PATH       Input PCAP file or directory [required]
  -o, --output PATH      Output directory (default: <input_dir>/statistics/)
  -r, --no-recursive     Do NOT recursively scan directories (default: recursive)
  -w, --workers INTEGER  Number of worker processes for concurrent processing
                         (default: 1)
  -f, --format [txt|md]  Output file format: txt or md (default: txt)
  --sidecar              Generate a JSON sidecar (*.meta.json) for each module output
  --help                 Show this message and exit
```

**Analysis Modules (28 total):**

**Network Layer:**
- Protocol Hierarchy
- IPv4 Conversations
- IPv4 Source TTLs
- IPv4 Destinations and Ports
- IPv4 Host Endpoints

**Transport Layer:**
- TCP Conversations
- TCP Zero Window Events
- TCP Duration Statistics
- TCP Completeness (SYN/FIN/RST analysis)
- UDP Conversations

**Application Layer:**
- DNS Statistics
- DNS Query/Response Statistics
- HTTP Statistics
- HTTP Response Codes
- FTP Statistics
- FTP Data Statistics
- TLS Alert Messages
- ICMP Statistics

**VoIP Protocols:**
- SIP Statistics
- RTP Statistics
- RTCP Statistics
- MGCP Statistics
- SDP Statistics
- VoIP Quality Metrics

**Other Protocols:**
- SSH Statistics
- JSON Statistics
- XML Statistics
- MQ (Message Queue) Statistics

### `match` - TCP Connection Matching

Match TCP connections between multiple PCAP files using advanced feature scoring.

```bash
capmaster match [OPTIONS]

Options:
  -i, --input PATH                Input directory containing PCAP files [required]
  -o, --output PATH               Output file for match results (default: stdout)
  --mode [auto|header]            Matching mode
                                  - auto: automatic detection
                                  - header: header-only mode
  --bucket [auto|server|port|none]
                                  Bucketing strategy
                                  - auto: automatic selection
                                  - server: group by server IP
                                  - port: group by server port
                                  - none: no bucketing
  --threshold FLOAT               Minimum normalized score threshold (0.0-1.0, default: 0.60)
  --help                          Show this message and exit
```

**Matching Features:**
- SYN Options Fingerprint (25% weight)
- Client Initial Sequence Number (12% weight)
- Server Initial Sequence Number (6% weight)
- TCP Timestamp (10% weight)
- Client Payload Hash (15% weight)
- Server Payload Hash (8% weight)
- Length Signature (8% weight)
- IP ID Sequence (16% weight)

## Examples

### Example 1: Complete PCAP Analysis Workflow

```bash
# Analyze all PCAP files in a directory
capmaster analyze -i captures/ -r -o analysis_results/

# View the generated statistics
ls analysis_results/

# Analyze with Markdown format and sidecar metadata
capmaster analyze -i captures/ -r -f md --sidecar

# View generated metadata files
ls analysis_results/statistics/*.meta.json
```

### Example 2: Match Client and Server Captures

```bash
# Directory structure:
# captures/
#   ├── client.pcap
#   └── server.pcap

# Match connections
capmaster match -i captures/ -o matches.txt

# View matches
cat matches.txt
```

### Example 3: Analyze with Sidecar Metadata and Markdown Format

```bash
# Analyze with metadata sidecar files in Markdown format
capmaster analyze -i sample.pcap -f md --sidecar

# View generated files
ls -la sample_statistics/

# View a sample metadata file
cat sample_statistics/sample-1-protocol-hierarchy.meta.json

# View a Markdown analysis file
cat sample_statistics/sample-1-protocol-hierarchy.md
```

This generates both analysis output and metadata for each module, useful for:
- Tracking analysis provenance (which tshark args, protocols were used)
- Building pipelines that consume analysis results
- Auditing and reproducibility

### Example 4: Verbose Output for Debugging

```bash
# Use -v for INFO level logging
capmaster -v analyze -i sample.pcap

# Use -vv for DEBUG level logging
capmaster -vv match -i captures/
```

## Repository Layout

- `capmaster/` – Core CLI, plugins, and utilities.
- `resources/` – Versioned assets such as `services.txt` (pass via
  `--service-list resources/services.txt`) and pipeline templates like
  `pipeline_match_test.yaml`.
- `data/` – Workspace-local datasets (symlinks to `2hops`, `cases`, `sample_captures`,
  etc.). These entries are gitignored; create or update them per your machine.
- `scripts/` – Automation helpers and manual experiments. Subdirectories include
  `scripts/debug/` and `scripts/tests/` for relocated tooling.
- `artifacts/` – Default drop zone for runtime outputs. Ignored by Git; create
  subfolders such as `analysis/`, `benchmarks/`, and `tmp/` as needed.
- `reports/` – Curated, version-controlled deliverables promoted from
  `artifacts/analysis/`.

## Artifacts and Reports

1. Point CLI commands and scripts to `artifacts/...` using `-o/--output` or
   script arguments.
2. Inspect the generated files locally.
3. Copy the finalized report to `reports/analysis/<case>/` (or another tracked
   folder) before committing.

Example:

```bash
mkdir -p artifacts/tmp
capmaster match -i data/2hops/aomenjinguanju_10MB -o artifacts/tmp/matched_connections.txt
cp artifacts/tmp/matched_connections.txt reports/analysis/aomenjinguanju-matched.txt
```

## Utility Scripts

- Debug TCP roles extracted from PCAPs:

  ```bash
  python scripts/debug/debug_topology_streams.py
  ```

- Verify that `ServerDetector` honors the bundled service list:

  ```bash
  python scripts/tests/test_service_list.py
  ```

  Both scripts expect to be executed from the repository root so relative paths
  (e.g., `resources/services.txt`) resolve correctly.

## Architecture

CapMaster uses a two-layer plugin architecture:

```
capmaster/
├── core/                    # Core components
│   ├── file_scanner.py      # PCAP file discovery
│   ├── tshark_wrapper.py    # tshark command execution
│   ├── protocol_detector.py # Protocol detection
│   └── output_manager.py    # Output file management
├── plugins/                 # Plugin layer
│   ├── analyze/             # Analysis plugin
│   │   └── modules/         # Analysis modules (2nd layer)
│   ├── match/               # Matching plugin
│   ├── compare/             # Comparative analysis plugin
│   ├── preprocess/          # Preprocessing pipeline
│   ├── topology/            # Topology rendering plugin
│   ├── streamdiff/          # TCP stream diffing plugin
│   └── pipeline/            # Batch workflow runner
└── utils/                   # Utilities
    └── logger.py            # Logging configuration
```

## Performance

CapMaster achieves excellent performance compared to the original shell scripts:

| Operation | Original Script | CapMaster | Performance |
|-----------|----------------|-----------|-------------|
| Analyze (10MB PCAP) | 2.5s | 2.0s | **126%** (21% faster) |
| Match (100 connections) | 5.0s | 4.5s | **111%** (11% faster) |

**Test Coverage:** 87% (130 tests passing)

## Development

### Setup Development Environment

```bash
# Clone and setup
git clone https://github.com/yourusername/capmaster.git
cd capmaster
python3.10 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest -v

# Run with coverage
pytest --cov=capmaster --cov-report=term

# Run specific test file
pytest tests/test_core/test_file_scanner.py -v

# Run integration tests only
pytest -m integration
```

### Code Quality

```bash
# Type checking
mypy capmaster

# Linting
ruff check capmaster

# Formatting
black capmaster

# Run all checks
mypy capmaster && ruff check capmaster && black --check capmaster
```

## Migration from Shell Scripts

CapMaster replaces legacy shell scripts:

| Old Script | New Command | Notes |
|------------|-------------|-------|
| `analyze_pcap.sh -i file.pcap` | `capmaster analyze -i file.pcap` | Same functionality, better performance |
| `match_tcp_conns.sh -i dir/` | `capmaster match -i dir/` | Enhanced 8-feature scoring |


## Extending CapMaster

CapMaster is designed with extensibility in mind. You can easily add new plugins or analysis modules.

See **[AI Plugin Extension Guide](docs/AI_PLUGIN_EXTENSION_GUIDE.md)** for quick reference on:

- Adding new top-level plugins (like analyze, match, compare, preprocess, topology, streamdiff, pipeline)
- Adding new analysis modules for the analyze plugin
- tshark command patterns and post-processing techniques
- Code templates, testing, and validation

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and code quality checks
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Click](https://click.palletsprojects.com/) for CLI framework
- Terminal output powered by [Rich](https://rich.readthedocs.io/)
- PCAP analysis using [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/yourusername/capmaster).
