# CapMaster Documentation

Welcome to the CapMaster documentation! This directory contains comprehensive guides, references, and technical documentation for using and developing CapMaster.

> **给 AI Agent 的约定**：请将 `capmaster/` 代码和 `tests/` 测试视为唯一真实来源，文档只提供导航、概念和不变量说明；当文档与代码冲突时，以代码和测试为准。

## 📚 Documentation Index

### Getting Started

- **[USER_GUIDE.md](USER_GUIDE.md)** - Complete user guide covering all features
  - Installation and setup
  - Command usage (analyze, match, compare, preprocess)
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

- **Implementation & performance notes**
  - For up-to-date behavior and performance characteristics, inspect the code under `capmaster/core/` and `capmaster/plugins/` as well as relevant tests in `tests/`.
  - For historical changes or past experiments, prefer `git log` and pull request discussions instead of separate archived reports.

### Protocol & Feature Coverage

- **[COMPARATIVE_ANALYSIS_GUIDE.md](COMPARATIVE_ANALYSIS_GUIDE.md)** - Comparative analysis feature
  - Service-level and connection-pair level quality metrics
  - Integrates with `capmaster match` output

- **[ACK_LOST_SEGMENT_FEATURE.md](ACK_LOST_SEGMENT_FEATURE.md)** - ACK Lost Segment & Real Loss metrics
  - Clarifies difference between capture misses and real network loss
  - Defines derived fields and invariants for quality analysis

### Development

- **[AI_PLUGIN_EXTENSION_GUIDE.md](AI_PLUGIN_EXTENSION_GUIDE.md)** - Plugin development guide
  - Plugin architecture
  - Creating new plugins
  - Code sharing patterns
  - Best practices
- **[BINARY_PACKAGING_PLAN.md](BINARY_PACKAGING_PLAN.md)** - macOS PyInstaller packaging workflow
  - Spec file layout & hooks
  - Build and smoke-test automation
  - Release checklist and artifacts

## 🚀 Quick Start

### New Users

1. Start with **[USER_GUIDE.md](USER_GUIDE.md)** for comprehensive introduction
2. Use **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** for quick command lookup
3. For supported protocols and modules, inspect `capmaster/plugins/analyze/modules/` and run `capmaster analyze --help`

### Advanced Users

1. Read **[MATCH_LOGIC_COMPLETE.md](MATCH_LOGIC_COMPLETE.md)** to understand matching algorithm
2. Check runtime behavior from code (`capmaster/core/`, `capmaster/plugins/`) and tests for performance characteristics
3. Explore **[COMPARATIVE_ANALYSIS_GUIDE.md](COMPARATIVE_ANALYSIS_GUIDE.md)** for advanced analysis

### Developers

1. Start with **[AI_PLUGIN_EXTENSION_GUIDE.md](AI_PLUGIN_EXTENSION_GUIDE.md)**
2. Review code in **[examples/](examples/)**
3. Check git history for historical context

## 📖 Documentation Organization

```text
docs/
├── README.md                              # This file - Documentation index
├── USER_GUIDE.md                          # Complete user guide (primary reference)
├── QUICK_REFERENCE.md                     # Quick reference card
├── MATCH_LOGIC_COMPLETE.md                # Matching algorithm details
├── ACK_LOST_SEGMENT_FEATURE.md            # ACK Lost Segment & Real Loss metrics
├── COMPARATIVE_ANALYSIS_GUIDE.md          # Comparative analysis feature
├── AI_PLUGIN_EXTENSION_GUIDE.md           # Plugin development guide
├── DESIGN_preprocess_and_config.md        # Preprocess plugin & config design (internal)
└── TOPOLOGY_UDP_AND_ICMP_DESIGN.md        # Topology UDP & ICMP design (internal)
```

## 🔍 Finding Information

### By Topic

- **Installation**: USER_GUIDE.md → Getting Started
- **Command Usage**: QUICK_REFERENCE.md or USER_GUIDE.md
- **Matching Algorithm**: MATCH_LOGIC_COMPLETE.md
- **Performance**: runtime behavior from code (`capmaster/core/`, `capmaster/plugins/`) and tests
- **Protocols**: current modules under `capmaster/plugins/analyze/modules/`
- **Development**: AI_PLUGIN_EXTENSION_GUIDE.md
- **History**: git history (git log)

### By Use Case

- **First-time user**: USER_GUIDE.md
- **Quick command lookup**: QUICK_REFERENCE.md
- **Understanding match results**: MATCH_LOGIC_COMPLETE.md
- **Optimizing performance**: Check code and tests for runtime behavior
- **Creating plugins**: AI_PLUGIN_EXTENSION_GUIDE.md
- **Troubleshooting**: USER_GUIDE.md → Troubleshooting

## 🆘 Getting Help

1. Check **[USER_GUIDE.md](USER_GUIDE.md)** → Troubleshooting section
2. Review **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** for command syntax
3. Search documentation using your editor's search function
4. Check git history (git log) for historical context

## 📄 License

See the main repository LICENSE file for licensing information.
