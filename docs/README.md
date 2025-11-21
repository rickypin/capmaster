# CapMaster Documentation

Welcome to the CapMaster documentation! This directory contains comprehensive guides, references, and technical documentation for using and developing CapMaster.

> **给 AI Agent 的约定**：请将 `capmaster/` 代码和 `tests/` 测试视为唯一真实来源，文档只提供导航、概念和不变量说明；当文档与代码冲突时，以代码和测试为准。

## 📚 Documentation Index

### Getting Started

- **[USER_GUIDE.md](USER_GUIDE.md)** - Complete user guide covering all features
  - Installation and setup
  - Command usage (analyze, match, compare, preprocess, clean)
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

- **Performance & implementation notes**
  - For up-to-date behavior and performance characteristics, inspect the code under `capmaster/core/` and `capmaster/plugins/` as well as relevant tests in `tests/`.
  - Historical performance and optimization reports are archived under **[archive/](archive/)** (e.g. `PERFORMANCE_REPORT.md`, `MATCH_PLUGIN_PERFORMANCE_REVIEW.md`).

- **[MATCH_PLUGIN_PERFORMANCE_REVIEW.md](MATCH_PLUGIN_PERFORMANCE_REVIEW.md)** - In-depth performance review
  - Detailed performance analysis
  - Optimization opportunities
  - Implementation recommendations

### Protocol & Feature Coverage

- **[COMPARATIVE_ANALYSIS_GUIDE.md](COMPARATIVE_ANALYSIS_GUIDE.md)** - Comparative analysis feature
  - Service-level and connection-pair level quality metrics
  - Integrates with `capmaster match` output

- **[ACK_LOST_SEGMENT_FEATURE.md](ACK_LOST_SEGMENT_FEATURE.md)** - ACK Lost Segment & Real Loss metrics
  - Clarifies difference between capture misses and real network loss
  - Defines derived fields and invariants for quality analysis

- **Historical protocol coverage snapshot**
  - See **[archive/PROTOCOL_COVERAGE_REPORT.md](archive/PROTOCOL_COVERAGE_REPORT.md)** for a past protocol coverage report; for current modules, inspect `capmaster/plugins/analyze/modules/` and corresponding tests.

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

### Analysis & Historical Reports

- **[archive/](archive/)** - Historical analysis and design reports
  - Matching strategy comparisons
  - Behavioral matching tuning & validation
  - Specific fix/design histories

## 🚀 Quick Start

### New Users

1. Start with **[USER_GUIDE.md](USER_GUIDE.md)** for comprehensive introduction
2. Use **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** for quick command lookup
3. For supported protocols and modules, prefer inspecting `capmaster/plugins/analyze/modules/` and running CLI `--help`; historical protocol coverage snapshot is available at **[archive/PROTOCOL_COVERAGE_REPORT.md](archive/PROTOCOL_COVERAGE_REPORT.md)**.

### Advanced Users

1. Read **[MATCH_LOGIC_COMPLETE.md](MATCH_LOGIC_COMPLETE.md)** to understand matching algorithm
2. Review **[PERFORMANCE_REPORT.md](PERFORMANCE_REPORT.md)** for optimization tips
3. Explore **[COMPARATIVE_ANALYSIS_GUIDE.md](COMPARATIVE_ANALYSIS_GUIDE.md)** for advanced analysis

### Developers

1. Start with **[AI_PLUGIN_EXTENSION_GUIDE.md](AI_PLUGIN_EXTENSION_GUIDE.md)**
2. Review code in **[examples/](examples/)**
3. Check git history for historical context

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
├── archive/                               # Historical analysis & design reports
│   ├── README.md                          # Archive index
│   ├── BEHAVIORAL_MATCHING_TUNING.md      # Behavioral tuning report
│   ├── BEHAVIORAL_PRECISION_ANALYSIS.md   # Behavioral precision analysis
│   ├── BEHAVIORAL_VALIDATION_REPORT.md    # Behavioral validation report
│   ├── MATCHING_STRATEGIES_COMPARISON.md  # Matching strategies comparison
│   ├── MERGE_BY_5TUPLE_FIX.md             # --merge-by-5tuple fix notes
│   └── STRATEGY_COMPARISON_SUMMARY.md     # Strategy comparison summary
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
- **Performance**: runtime behavior from code (`capmaster/core/`, `capmaster/plugins/`) and tests; historical benchmarks in **[archive/PERFORMANCE_REPORT.md](archive/PERFORMANCE_REPORT.md)**
- **Protocols**: current modules under `capmaster/plugins/analyze/modules/`; historical coverage snapshot in **[archive/PROTOCOL_COVERAGE_REPORT.md](archive/PROTOCOL_COVERAGE_REPORT.md)**
- **Development**: AI_PLUGIN_EXTENSION_GUIDE.md
- **History**: git history (git log)

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
4. Check git history (git log) for historical context

## 📄 License

See the main repository LICENSE file for licensing information.

