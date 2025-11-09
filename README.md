# CapMaster

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A unified Python CLI tool for PCAP analysis, TCP connection matching, and filtering. CapMaster replaces three legacy shell scripts with a modern, maintainable, and extensible Python application.

## Features

- 📊 **Comprehensive PCAP Analysis** - 28 statistical analysis modules for protocol hierarchy, TCP/UDP conversations, DNS, HTTP, TLS, VoIP (SIP/RTP/RTCP/MGCP), SSH, and more
- 🔗 **Intelligent TCP Connection Matching** - Advanced 8-feature scoring algorithm to match TCP connections across multiple PCAP files
- 🔍 **One-Way Connection Filtering** - Detect and remove one-way TCP connections from PCAP files
- 🧹 **Statistics Cleanup** - Easily remove statistics directories to reclaim disk space
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

### 3. Filter One-Way Connections

Remove one-way TCP connections from a PCAP file:

```bash
capmaster filter -i input.pcap -o output.pcap
```

With custom threshold:

```bash
capmaster filter -i input.pcap -o output.pcap -t 100
```

**Output:** Filtered PCAP file with bidirectional connections only.

### 4. Clean Statistics Directories

Remove statistics directories to reclaim disk space:

```bash
# Preview what will be deleted (dry run)
capmaster clean -i /path/to/data --dry-run

# Clean with confirmation prompt
capmaster clean -i /path/to/data

# Clean without confirmation
capmaster clean -i /path/to/data -y

# Clean only top-level statistics directory (non-recursive)
capmaster clean -i /path/to/data -r
```

**Output:** Removes all `statistics` directories and shows freed disk space.

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

### `filter` - One-Way Connection Filtering

Remove one-way TCP connections from PCAP files.

```bash
capmaster filter [OPTIONS]

Options:
  -i, --input PATH         Input PCAP file or directory [required]
  -o, --output PATH        Output PCAP file or directory
                           (default: <input>_filtered.pcap)
  -t, --threshold INTEGER  ACK increment threshold for one-way detection
                           (default: 20)
  -r, --no-recursive       Do NOT recursively scan directories (default: recursive)
  -w, --workers INTEGER    Number of worker processes for concurrent processing
                           (default: 1)
  --help                   Show this message and exit
```

**Detection Algorithm:**
- Analyzes ACK number increments in TCP streams
- Handles 32-bit sequence number wraparound
- Identifies pure ACK packets (tcp.len==0)
- Marks streams with excessive pure ACKs as one-way

### `clean` - Remove Statistics Directories

Remove statistics directories and their contents to reclaim disk space.

```bash
capmaster clean [OPTIONS]

Options:
  -i, --input PATH     Input directory to search for statistics folders [required]
  -r, --no-recursive   Do NOT recursively search directories (default: recursive)
  --dry-run            Show what would be deleted without actually deleting
  -y, --yes            Skip confirmation prompt and delete immediately
  --help               Show this message and exit
```

**Safety Features:**
- Confirmation prompt by default (use `-y` to skip)
- Dry run mode to preview deletions
- Only deletes directories named `statistics`
- Shows total size before deletion
- Progress tracking during deletion

## Examples

### Example 1: Complete PCAP Analysis Workflow

```bash
# Analyze all PCAP files in a directory
capmaster analyze -i captures/ -r -o analysis_results/

# View the generated statistics
ls analysis_results/
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

### Example 3: Clean PCAP File

```bash
# Remove one-way connections
capmaster filter -i noisy.pcap -o clean.pcap

# Verify the result
capmaster analyze -i clean.pcap
```

### Example 4: Clean Up Statistics Directories

```bash
# Preview what will be deleted
capmaster clean -i /path/to/data --dry-run

# Clean with confirmation
capmaster clean -i /path/to/data

# Clean without confirmation (use with caution)
capmaster clean -i /path/to/data -y

# Clean only top-level statistics directory
capmaster clean -i /path/to/data -r -y
```

### Example 5: Complete Workflow with Cleanup

```bash
# 1. Analyze PCAP files
capmaster analyze -i captures/

# 2. Review statistics
ls captures/statistics/

# 3. Clean up when done
capmaster clean -i captures/ -y
```

### Example 6: Verbose Output for Debugging

```bash
# Use -v for INFO level logging
capmaster -v analyze -i sample.pcap

# Use -vv for DEBUG level logging
capmaster -vv match -i captures/
```

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
│   └── filter/              # Filtering plugin
└── utils/                   # Utilities
    └── logger.py            # Logging configuration
```

## Performance

CapMaster achieves excellent performance compared to the original shell scripts:

| Operation | Original Script | CapMaster | Performance |
|-----------|----------------|-----------|-------------|
| Analyze (10MB PCAP) | 2.5s | 2.0s | **126%** (21% faster) |
| Match (100 connections) | 5.0s | 4.5s | **111%** (11% faster) |
| Filter (10MB PCAP) | 3.0s | 2.8s | **107%** (7% faster) |

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

CapMaster replaces three legacy shell scripts:

| Old Script | New Command | Notes |
|------------|-------------|-------|
| `analyze_pcap.sh -i file.pcap` | `capmaster analyze -i file.pcap` | Same functionality, better performance |
| `match_tcp_conns.sh -i dir/` | `capmaster match -i dir/` | Enhanced 8-feature scoring |
| `remove_one_way_tcp.sh -i file.pcap` | `capmaster filter -i file.pcap` | Improved detection algorithm |

## Extending CapMaster

CapMaster is designed with extensibility in mind. You can easily add new plugins or analysis modules.

See **[AI Plugin Extension Guide](docs/AI_PLUGIN_EXTENSION_GUIDE.md)** for quick reference on:

- Adding new top-level plugins (like analyze, match, filter, clean)
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
