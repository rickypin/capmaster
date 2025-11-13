# CapMaster Documentation

Welcome to the CapMaster documentation! This directory contains comprehensive guides, references, and technical documentation for using and developing CapMaster.

## 📚 Documentation Index

### Getting Started

- **[USER_GUIDE.md](USER_GUIDE.md)** - Complete user guide covering all features
  - Installation and setup
  - Command usage (analyze, match, compare, filter, clean)
  - Advanced features (F5 matching, sampling, module selection)
  - Troubleshooting and best practices

- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Quick reference card
  - Common commands and options
  - Match & Compare consistency workflow
  - Sampling control for large datasets
  - F5 load balancer support

### Technical Documentation

- **[MATCH_LOGIC_COMPLETE.md](MATCH_LOGIC_COMPLETE.md)** - Detailed matching algorithm
  - 8-feature scoring system
  - Server detection logic
  - Bucketing strategies
  - Match modes (one-to-one, one-to-many)

- **[PERFORMANCE_REPORT.md](PERFORMANCE_REPORT.md)** - Performance benchmarks
  - Benchmark results vs original shell scripts
  - Performance analysis by dataset size
  - Configuration recommendations
  - Optimization strategies

- **[MATCH_PLUGIN_PERFORMANCE_REVIEW.md](MATCH_PLUGIN_PERFORMANCE_REVIEW.md)** - In-depth performance review
  - Detailed performance analysis
  - Optimization opportunities
  - Implementation recommendations

### Protocol & Feature Coverage

- **[PROTOCOL_COVERAGE_REPORT.md](PROTOCOL_COVERAGE_REPORT.md)** - Protocol support
  - 28 analysis modules
  - Supported protocols (TCP, UDP, HTTP, DNS, VoIP, etc.)
  - Module descriptions and output formats

- **[COMPARATIVE_ANALYSIS_GUIDE.md](COMPARATIVE_ANALYSIS_GUIDE.md)** - Comparative analysis feature
  - Service-level comparison
  - Connection-pair comparison
  - Quality metrics (packet loss, retransmission, duplicate ACK)

### Development

- **[AI_PLUGIN_EXTENSION_GUIDE.md](AI_PLUGIN_EXTENSION_GUIDE.md)** - Plugin development guide
  - Plugin architecture
  - Creating new plugins
  - Code sharing patterns
  - Best practices

### Examples

- **[examples/](examples/)** - Code examples and demonstrations
  - `gil_demonstration.py` - Python GIL demonstration
  - `match_parallelization_analysis.py` - Parallelization analysis

### Historical Documentation

- **[archive/](archive/)** - Archived development documents
  - Project specifications
  - Task checklists (100% complete)
  - Refactoring summaries
  - Fix completion reports
  - Changelogs

## 🚀 Quick Start

### New Users

1. Start with **[USER_GUIDE.md](USER_GUIDE.md)** for comprehensive introduction
2. Use **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** for quick command lookup
3. Check **[PROTOCOL_COVERAGE_REPORT.md](PROTOCOL_COVERAGE_REPORT.md)** for supported protocols

### Advanced Users

1. Read **[MATCH_LOGIC_COMPLETE.md](MATCH_LOGIC_COMPLETE.md)** to understand matching algorithm
2. Review **[PERFORMANCE_REPORT.md](PERFORMANCE_REPORT.md)** for optimization tips
3. Explore **[COMPARATIVE_ANALYSIS_GUIDE.md](COMPARATIVE_ANALYSIS_GUIDE.md)** for advanced analysis

### Developers

1. Start with **[AI_PLUGIN_EXTENSION_GUIDE.md](AI_PLUGIN_EXTENSION_GUIDE.md)**
2. Review code in **[examples/](examples/)**
3. Check **[archive/](archive/)** for historical context

## 📖 Documentation Organization

```
docs/
├── README.md                              # This file - Documentation index
├── USER_GUIDE.md                          # Complete user guide (primary reference)
├── QUICK_REFERENCE.md                     # Quick reference card
├── MATCH_LOGIC_COMPLETE.md                # Matching algorithm details
├── PERFORMANCE_REPORT.md                  # Performance benchmarks
├── MATCH_PLUGIN_PERFORMANCE_REVIEW.md     # Detailed performance analysis
├── PROTOCOL_COVERAGE_REPORT.md            # Protocol support matrix
├── COMPARATIVE_ANALYSIS_GUIDE.md          # Comparative analysis feature
├── AI_PLUGIN_EXTENSION_GUIDE.md           # Plugin development guide
├── archive/                               # Historical documents
│   ├── README.md                          # Archive index
│   ├── TASK_CHECKLIST.md                  # Development tasks (100% complete)
│   ├── PROJECT_SPEC.md                    # Original project specification
│   ├── REFACTORING_SUMMARY.md             # Code refactoring summary
│   ├── *_FIX_SUMMARY.md                   # Various fix summaries
│   └── changelogs/                        # Feature changelogs
└── examples/                              # Code examples
    ├── README.md                          # Examples index
    ├── gil_demonstration.py               # GIL demonstration
    └── match_parallelization_analysis.py  # Parallelization analysis
```

## 🔍 Finding Information

### By Topic

- **Installation**: USER_GUIDE.md → Getting Started
- **Command Usage**: QUICK_REFERENCE.md or USER_GUIDE.md
- **Matching Algorithm**: MATCH_LOGIC_COMPLETE.md
- **Performance**: PERFORMANCE_REPORT.md
- **Protocols**: PROTOCOL_COVERAGE_REPORT.md
- **Development**: AI_PLUGIN_EXTENSION_GUIDE.md
- **History**: archive/README.md

### By Use Case

- **First-time user**: USER_GUIDE.md
- **Quick command lookup**: QUICK_REFERENCE.md
- **Understanding match results**: MATCH_LOGIC_COMPLETE.md
- **Optimizing performance**: PERFORMANCE_REPORT.md
- **Creating plugins**: AI_PLUGIN_EXTENSION_GUIDE.md
- **Troubleshooting**: USER_GUIDE.md → Troubleshooting

## 📝 Documentation Maintenance

This documentation was reorganized on 2025-11-13 to:
- Remove obsolete development documents (31 files)
- Consolidate feature documentation into core guides
- Improve navigation and discoverability
- Archive historical documents for reference

For the complete list of changes, see the git history.

## 🆘 Getting Help

1. Check **[USER_GUIDE.md](USER_GUIDE.md)** → Troubleshooting section
2. Review **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** for command syntax
3. Search documentation using your editor's search function
4. Check **[archive/](archive/)** for historical context

## 📄 License

See the main repository LICENSE file for licensing information.

