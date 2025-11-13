# Archived Scripts

This directory contains one-time debugging and testing scripts that are no longer actively used but kept for historical reference.

## Contents

### Debug Scripts
- `debug_ttl_position.py` - TTL position debugging script
- `analyze_ipid.py` - IPID overlap analysis script (hardcoded paths)

### Test Scripts
- `test_compare_consistency.py` - Compare plugin consistency testing
- `test_match_compare_consistency.sh` - Match/Compare consistency testing
- `run_comprehensive_test.py` - Comprehensive 2hops test suite (hardcoded paths)
- `test_2hops_comprehensive.py` - 2hops comprehensive testing
- `test_all_2hops.sh` - Shell script for 2hops testing

## Why Archived?

These scripts were created for specific debugging or testing purposes and contain:
- Hardcoded file paths specific to development environment
- One-time analysis tasks that have been completed
- Functionality that has been integrated into the main test suite

## Usage

These scripts are **not maintained** and may not work without modification. They are kept for:
- Historical reference
- Understanding past debugging approaches
- Potential adaptation for future similar tasks

## Active Testing

For current testing, use:
```bash
# Run main test suite
pytest tests/

# Run specific plugin tests
pytest tests/test_plugins/test_match/ -v
pytest tests/test_plugins/test_compare/ -v

# Run benchmarks
python scripts/benchmark.py
python scripts/benchmark_2hops.py
```

## Last Updated
- Date: 2025-11-13
- Reason: Project cleanup - moved one-time scripts to archive

