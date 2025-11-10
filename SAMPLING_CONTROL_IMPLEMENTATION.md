# Match Plugin - Sampling Control Implementation

## Summary

Successfully implemented fine-grained control over connection sampling in the `match` plugin. Users can now disable sampling or customize sampling parameters to balance performance and accuracy.

## Changes Made

### 1. Plugin Code (`capmaster/plugins/match/plugin.py`)

#### Added CLI Options

Three new command-line options were added:

1. **`--no-sampling`** (flag)
   - Completely disables sampling
   - Processes all connections regardless of dataset size
   - Default: `False`

2. **`--sampling-threshold`** (integer)
   - Sets the connection count threshold for triggering sampling
   - Default: `1000`
   - Minimum: `1`

3. **`--sampling-rate`** (float)
   - Sets the fraction of connections to keep when sampling
   - Range: `0.0 < rate <= 1.0`
   - Default: `0.5` (50%)

#### Updated Function Signatures

- `match_command()`: Added three new parameters
- `execute()`: Added three new parameters with defaults

#### Enhanced Sampling Logic

- Added parameter validation with warnings for invalid values
- Added detailed logging showing sampling parameters and results
- Added conditional logic to skip sampling when `--no-sampling` is set
- Improved logging to show retention percentage

### 2. Tests

#### Integration Tests (`tests/test_plugins/test_match/test_integration.py`)

Added 5 new test cases:

1. `test_match_with_no_sampling`: Verifies `--no-sampling` flag works
2. `test_match_with_custom_sampling_threshold`: Tests custom threshold
3. `test_match_with_custom_sampling_rate`: Tests custom rate
4. `test_match_with_combined_sampling_params`: Tests both threshold and rate together
5. Validates output files are created and commands succeed

#### Unit Tests (`tests/test_plugins/test_match/test_units.py`)

Added 2 new test cases:

1. `test_execute_with_no_sampling`: Tests programmatic API with `no_sampling=True`
2. `test_execute_with_custom_sampling_params`: Tests custom threshold and rate via API

### 3. Documentation (`docs/match_sampling_control.md`)

Created comprehensive documentation covering:

- Overview of sampling behavior
- Detailed explanation of each new option
- Usage examples for different scenarios
- Performance considerations and recommendations
- Algorithm details
- Best practices

## Technical Details

### Sampling Algorithm

The match plugin uses **time-based stratified sampling**:

1. Connections are sorted by timestamp
2. Divided into up to 10 time strata
3. Each stratum contributes proportionally to target sample size
4. Protected connections are always preserved:
   - Header-only connections
   - Special ports (SSH, HTTP, HTTPS, databases, etc.)

### Default Behavior

- **Threshold**: 1000 connections
- **Rate**: 50% (keeps half)
- **Protected**: Header-only + special ports

### Parameter Validation

The implementation includes validation:

```python
if sampling_rate <= 0.0 or sampling_rate > 1.0:
    logger.warning(f"Invalid sampling rate {sampling_rate}, using default 0.5")
    sampling_rate = 0.5

if sampling_threshold < 1:
    logger.warning(f"Invalid sampling threshold {sampling_threshold}, using default 1000")
    sampling_threshold = 1000
```

### Logging Enhancements

Before:
```
INFO: Applying sampling to first file...
INFO: Sampled to 1250 connections
```

After:
```
INFO: Applying sampling to first file (threshold=1000, rate=0.5)...
INFO: Sampled from 2500 to 1250 connections (50.0% retained)
```

Or when disabled:
```
INFO: Sampling disabled by --no-sampling flag
```

## Usage Examples

### Disable Sampling
```bash
capmaster match -i captures/ --no-sampling
```

### Custom Threshold
```bash
capmaster match -i captures/ --sampling-threshold 5000
```

### Custom Rate
```bash
capmaster match -i captures/ --sampling-rate 0.3
```

### Combined
```bash
capmaster match -i captures/ --sampling-threshold 2000 --sampling-rate 0.7
```

### With Other Options
```bash
capmaster match -i captures/ \
  --no-sampling \
  --threshold 0.70 \
  --match-mode one-to-many \
  --endpoint-stats \
  -o results.txt
```

## Backward Compatibility

✅ **Fully backward compatible**

- All new parameters have default values
- Existing code and scripts continue to work unchanged
- Default behavior remains the same (threshold=1000, rate=0.5)

## Testing

### Manual Testing

Verified CLI help output shows new options:
```bash
python -m capmaster match --help
```

Output includes:
```
--no-sampling                   Disable connection sampling (process all
                                connections regardless of dataset size)
--sampling-threshold INTEGER    Number of connections above which sampling
                                is triggered (default: 1000)
--sampling-rate FLOAT           Fraction of connections to keep when
                                sampling (0.0-1.0, default: 0.5)
```

### Automated Testing

- 5 new integration tests
- 2 new unit tests
- All tests verify correct behavior and output

## Files Modified

1. `capmaster/plugins/match/plugin.py` - Main implementation
2. `tests/test_plugins/test_match/test_integration.py` - Integration tests
3. `tests/test_plugins/test_match/test_units.py` - Unit tests

## Files Created

1. `docs/match_sampling_control.md` - User documentation
2. `SAMPLING_CONTROL_IMPLEMENTATION.md` - This implementation summary

## Performance Impact

- **No impact** when using default settings
- **Improved flexibility** for users to optimize based on their needs
- **Better logging** helps users understand sampling behavior

## Future Enhancements

Potential improvements for future versions:

1. Add `--sampling-strategy` option to choose different sampling algorithms
2. Add statistics output showing sampling effectiveness
3. Add adaptive sampling based on available memory
4. Add per-file sampling control (different thresholds for file1 vs file2)

## Conclusion

The implementation successfully adds comprehensive sampling control to the match plugin while maintaining backward compatibility and following best practices for CLI design, testing, and documentation.

