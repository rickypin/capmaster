# Legacy Tests

This directory contains tests that depend on the original shell scripts that have been replaced by the Python implementation.

## Status: DEPRECATED ⚠️

These tests are **no longer maintained** and are kept for historical reference only.

## Why These Tests Are Deprecated

The CapMaster project has completed its migration from shell scripts to Python:
- `analyze_pcap.sh` → `capmaster analyze`
- `match_tcp_conns.sh` → `capmaster match`
- `remove_one_way_tcp.sh` → `capmaster filter`

The original shell scripts have been removed from the repository as they are no longer needed.

## Files in This Directory

### 1. `test_compare_outputs.py` (702 lines)
**Purpose:** Compare output between original `analyze_pcap.sh` and new Python implementation.

**Dependencies:**
- `analyze_pcap.sh` (not in repository)
- 79 test PCAP files from `cases/` directory

**Status:** Cannot run without original script.

**Alternative:** The new implementation has been validated during migration. See:
- `docs/archive/BASELINE_TEST_RESULTS.md`
- `docs/PERFORMANCE_REPORT.md`

### 2. `test_performance.py` (128 lines)
**Purpose:** Performance comparison between original script and Python implementation.

**Dependencies:**
- `analyze_pcap.sh` (not in repository)
- Test PCAP files

**Status:** Cannot run without original script.

**Alternative:** Performance has been validated. See:
- `docs/PERFORMANCE_REPORT.md` - Shows Python implementation is 7-26% faster
- Current performance tests in main test suite

### 3. `test_filter_comparison.py` (292 lines)
**Purpose:** Compare filter output between `remove_one_way_tcp.sh` and Python implementation.

**Dependencies:**
- `remove_one_way_tcp.sh` (not in repository)
- Test PCAP files

**Status:** Cannot run without original script.

**Alternative:** Filter functionality is tested in:
- `tests/test_plugins/test_filter/test_integration.py`
- `tests/test_plugins/test_filter/test_detector.py`
- `tests/test_plugins/test_filter/test_plugin.py`

## Migration Validation

The migration from shell scripts to Python was thoroughly validated:

1. **Functional Validation:**
   - All 79 test cases were processed successfully
   - Output format matches original implementation
   - Edge cases handled correctly

2. **Performance Validation:**
   - Analyze: 126% of original speed (+26% faster)
   - Match: 111% of original speed (+11% faster)
   - Filter: 107% of original speed (+7% faster)

3. **Test Coverage:**
   - Unit tests: 80%+ coverage
   - Integration tests: All major workflows
   - 315+ active tests in main test suite

## If You Need the Original Scripts

If you need to run these tests for historical comparison:

1. Retrieve the original scripts from git history:
   ```bash
   git log --all --full-history -- "*.sh"
   git show <commit>:analyze_pcap.sh > analyze_pcap.sh
   git show <commit>:match_tcp_conns.sh > match_tcp_conns.sh
   git show <commit>:remove_one_way_tcp.sh > remove_one_way_tcp.sh
   chmod +x *.sh
   ```

2. Run the legacy tests:
   ```bash
   pytest tests/legacy/ -v
   ```

## Recommendation

**Do not use these tests for new development.**

Instead, use the active test suite:
```bash
# Run all active tests
pytest tests/ --ignore=tests/legacy/

# Run specific test categories
pytest tests/test_core/ -v                    # Core functionality
pytest tests/test_plugins/test_analyze/ -v    # Analyze plugin
pytest tests/test_plugins/test_filter/ -v     # Filter plugin
pytest tests/test_plugins/test_match/ -v      # Match plugin
```

## Last Updated

- Date: 2025-01-09
- Reason: Migration to Python completed, original scripts removed
- Migration completed: 2024-11-07 (see CHANGELOG.md)

