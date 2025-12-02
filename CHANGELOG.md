# Changelog

All notable changes to CapMaster will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- 新增 `topology` 插件，支持单点与双点拓扑分析，可通过 `--single-file` 直接分析单个 PCAP，或结合 `--matched-connections` 重建两点拓扑。

### Changed
- `match` 命令移除 `--topology` 选项，拓扑输出统一由 `capmaster topology` 负责，同时复用 `match` 的匹配结果。
- 文档、示例脚本与 meta 测试脚本更新，指导用户通过新插件生成 `topology.txt`。

## [1.0.0] - 2024-11-02

### Added

#### Core Features
- **Analyze Plugin**: Comprehensive PCAP analysis with 12 statistical modules
  - Protocol Hierarchy Statistics
  - TCP Conversations
  - TCP Zero Window Detection
  - TCP Duration Statistics
  - TCP Completeness Analysis
  - UDP Conversations
  - DNS Statistics
  - HTTP Statistics
  - TLS/SSL Statistics
  - FTP Statistics
  - ICMP Statistics
  - IPv4 Host Endpoints

- **Match Plugin**: Advanced TCP connection matching
  - 8-feature weighted scoring algorithm
  - SYN options fingerprinting (25% weight)
  - Client/Server ISN matching (12%/6% weight)
  - TCP timestamp analysis (10% weight)
  - Payload hash comparison (15%/8% weight)
  - Length signature similarity (8% weight)
  - IP ID sequence matching (16% weight)
  - Automatic bucketing strategies (auto/server/port/none)
  - Header-only mode support
  - Configurable score threshold (0.0-1.0)

- **Preprocess Plugin**: PCAP preprocessing pipeline
  - One-way TCP connection filtering
  - ACK increment analysis
  - 32-bit sequence number wraparound handling
  - Pure ACK packet detection (tcp.len==0)
  - Configurable threshold for one-way detection
  - Duplicate packet removal (dedup)
  - Time alignment across multiple PCAPs

#### Core Components
- **PcapScanner**: Intelligent PCAP file discovery
  - Support for .pcap and .pcapng formats
  - Recursive directory scanning
  - File validation

- **TsharkWrapper**: Robust tshark command execution
  - Automatic tshark detection
  - Version compatibility checking
  - Timeout handling
  - Error management

- **ProtocolDetector**: Protocol detection using tshark
  - Automatic protocol hierarchy analysis
  - Module execution optimization

- **OutputManager**: Flexible output file management
  - Automatic output directory creation
  - Configurable naming schemes
  - Sequence number handling

#### CLI Features
- Beautiful terminal output using Rich library
- Verbose logging modes (-v for INFO, -vv for DEBUG)
- Comprehensive help messages
- Version information display
- Progress indication for long operations

#### Testing
- 130 comprehensive tests (87% coverage)
- Unit tests for all core components
- Integration tests for all plugins
- Comparison tests against original shell scripts
- Performance benchmarks

#### Documentation
- Complete README.md with quick start guide
- Comprehensive USER_GUIDE.md
- API documentation
- Code examples and best practices
- Migration guide from shell scripts

### Changed

#### Performance Improvements
- **Analyze**: 126% of original script performance (21% faster)
- **Match**: 111% of original script performance (11% faster)
- Optimized tshark command generation
- Efficient memory usage for large files

#### Algorithm Enhancements
- **Match Plugin**: Enhanced from 4-feature to 8-feature scoring
  - Added TCP timestamp analysis
  - Added payload hash comparison (MD5)
  - Added length signature Jaccard similarity
  - Improved IPID matching logic
  - Fixed IPID=0 false rejection bug
  - Support for connections without SYN packets

### Fixed

#### Code Quality
- Fixed all mypy type errors (100% type coverage)
- Fixed all ruff linting issues
- Removed deprecated unit tests
- Fixed tshark_wrapper test compatibility

#### Bug Fixes
- **Match Plugin**:
  - Fixed IPID=0 being incorrectly rejected as invalid
  - Fixed TCP timestamp availability detection
  - Fixed payload hash calculation for empty payloads
  - Fixed length signature calculation edge cases
  - Corrected sequence number extraction (absolute vs relative)

- **Analyze Plugin**:
  - Fixed UTF-8 encoding issues in output files
  - Fixed module execution order
  - Fixed protocol detection for edge cases

### Deprecated

- Legacy shell scripts (replaced by Python CLI):
  - `analyze_pcap.sh` → `capmaster analyze`
  - `match_tcp_conns.sh` → `capmaster match`
  - `remove_one_way_tcp.sh` → `capmaster preprocess` (one-way filtering stage)

### Removed

- Obsolete unit test files:
  - `test_tcp_conversations.py`
  - `test_tcp_zero_window.py`
  - `test_tcp_duration.py`

### Security

- No known security vulnerabilities
- Safe handling of user input
- Proper file permission checks
- Secure temporary file handling

## [0.9.0] - 2024-10-30 (Beta)

### Added
- Initial beta release
- Basic analyze functionality
- Prototype match algorithm

### Known Issues
- Match algorithm used simplified 4-feature scoring
- IPID matching had false rejection issues
- Limited test coverage (43%)

## [0.5.0] - 2024-10-15 (Alpha)

### Added
- Project structure setup
- Core component implementation
- Basic CLI framework
- Initial test suite

## Migration Guide

### From Shell Scripts to CapMaster 1.0.0

#### Analyze Command

**Before:**
```bash
./analyze_pcap.sh -i test.pcap
./analyze_pcap.sh -i dir/ -c custom.conf
```

**After:**
```bash
capmaster analyze -i test.pcap
capmaster analyze -i dir/ -r
```

#### Match Command

**Before:**
```bash
./match_tcp_conns.sh -i dir/
./match_tcp_conns.sh -i dir/ --mode header
```

**After:**
```bash
capmaster match -i dir/
capmaster match -i dir/ --mode header --threshold 0.60
```

#### One-Way Filtering (Former `filter` Command)

**Before:**
```bash
./remove_one_way_tcp.sh -i test.pcap
./remove_one_way_tcp.sh -i test.pcap -t 100
```

**After (current releases):**
```bash
capmaster preprocess -i test.pcap
```

The preprocess pipeline automatically detects and removes one-way TCP streams.
The legacy `capmaster filter` subcommand has been retired and is no longer
distributed.

### Configuration Changes

- YAML configuration replaces shell script config files
- Module configuration is now in `config/default_commands.yaml`
- Custom configurations can be specified per command

### Output Format Changes

- Statistics files use consistent naming: `{base_name}-{sequence}-{suffix}`
- Match results include detailed feature scores
- Filter output includes summary statistics

## Upgrade Notes

### From 0.9.0 to 1.0.0

1. **Match Algorithm**: The scoring system has been completely rewritten
   - Old 4-feature scores are not comparable to new 8-feature scores
   - Default threshold changed from 0.30 to 0.60 (normalized scale)
   - Re-run match operations to get updated results

2. **Test Coverage**: Significantly improved from 43% to 87%
   - More reliable and well-tested codebase
   - Better error handling

3. **Performance**: All operations are now faster than original scripts
   - Analyze: +21% faster
   - Match: +11% faster

4. **Dependencies**: Updated minimum versions
   - Python 3.10+ (was 3.8+)
   - tshark 4.0+ (was 3.0+)

## Roadmap

### Version 1.1.0 (Planned)

- [ ] Parallel processing for multiple files
- [ ] Progress bars for long operations
- [ ] Enhanced error messages
- [ ] Configuration file support for match thresholds
- [ ] Export results to JSON/CSV formats

### Version 1.2.0 (Planned)

- [ ] Web UI for visualization
- [ ] Real-time capture analysis
- [ ] Custom plugin development guide
- [ ] Performance profiling tools

### Version 2.0.0 (Future)

- [ ] Distributed processing support
- [ ] Cloud storage integration
- [ ] Machine learning-based matching
- [ ] Advanced visualization tools

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/capmaster/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/capmaster/discussions)
- **Email**: support@capmaster.dev

---

**Note**: This project replaces three legacy shell scripts (analyze_pcap.sh, match_tcp_conns.sh, remove_one_way_tcp.sh) with a modern, maintainable Python CLI tool.
