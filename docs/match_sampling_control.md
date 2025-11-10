# Match Plugin - Sampling Control

## Overview

The `match` plugin now supports fine-grained control over connection sampling behavior. This allows you to optimize performance for large datasets or ensure complete accuracy by processing all connections.

## Background

When matching TCP connections between PCAP files, the match plugin uses **time-based stratified sampling** to handle large datasets efficiently. By default:

- **Sampling is triggered** when connection count exceeds **1000**
- **Sampling rate** is **50%** (keeps half of the connections)
- **Protected connections** are always preserved:
  - Header-only connections (SYN/SYN-ACK only)
  - Connections on special ports (SSH, HTTP, HTTPS, MySQL, PostgreSQL, etc.)

## New CLI Options

### `--no-sampling`

Completely disable sampling and process all connections regardless of dataset size.

**Use case**: When you need 100% accuracy and can afford the processing time.

```bash
capmaster match -i captures/ --no-sampling
```

### `--sampling-threshold <number>`

Set the connection count threshold above which sampling is triggered.

**Default**: 1000

**Use case**: Adjust when sampling should kick in based on your system's capabilities.

```bash
# Only sample when connections exceed 5000
capmaster match -i captures/ --sampling-threshold 5000
```

### `--sampling-rate <0.0-1.0>`

Set the fraction of connections to keep when sampling is applied.

**Default**: 0.5 (50%)

**Use case**: Control the trade-off between performance and accuracy.

```bash
# Keep 70% of connections when sampling
capmaster match -i captures/ --sampling-rate 0.7

# Keep only 30% of connections for faster processing
capmaster match -i captures/ --sampling-rate 0.3
```

## Usage Examples

### Example 1: Disable Sampling for Critical Analysis

```bash
capmaster match -i important_case/ --no-sampling -o results.txt
```

This ensures every single connection is analyzed, providing maximum accuracy.

### Example 2: Custom Threshold for Large Datasets

```bash
capmaster match -i large_dataset/ --sampling-threshold 10000 --sampling-rate 0.3
```

This configuration:
- Only triggers sampling when connections exceed 10,000
- Keeps 30% of connections when sampling is applied
- Useful for very large datasets where you want aggressive sampling

### Example 3: Conservative Sampling

```bash
capmaster match -i captures/ --sampling-threshold 2000 --sampling-rate 0.8
```

This configuration:
- Triggers sampling at 2,000 connections
- Keeps 80% of connections
- Good balance between performance and accuracy

### Example 4: Combined with Other Options

```bash
capmaster match \
  -i captures/ \
  --no-sampling \
  --threshold 0.70 \
  --match-mode one-to-many \
  --endpoint-stats \
  -o matches.txt
```

## Sampling Algorithm Details

The match plugin uses **time-based stratified sampling**:

1. **Time Division**: Connections are sorted by timestamp and divided into up to 10 time strata
2. **Proportional Sampling**: Each stratum contributes proportionally to the target sample size
3. **Protection**: Certain connections are always preserved:
   - Header-only connections (important for fingerprinting)
   - Connections on special ports (20, 21, 22, 23, 25, 53, 80, 443, 110, 143, 3306, 5432, 6379, 27017)

This approach ensures:
- **Temporal coverage**: Samples are distributed across the entire time range
- **Important connections preserved**: Critical connections are never dropped
- **Deterministic results**: Same input produces same output

## Performance Considerations

| Connections | Default Behavior | With --no-sampling | Recommended |
|-------------|------------------|-------------------|-------------|
| < 1,000 | No sampling | No sampling | Default is fine |
| 1,000 - 5,000 | 50% sampling | All processed | Consider --no-sampling |
| 5,000 - 10,000 | 50% sampling | All processed | Use --sampling-rate 0.7 |
| > 10,000 | 50% sampling | All processed | Use --sampling-rate 0.3-0.5 |

## Validation

The plugin validates sampling parameters:

- **sampling-rate**: Must be between 0.0 and 1.0 (exclusive of 0.0, inclusive of 1.0)
  - Invalid values default to 0.5
- **sampling-threshold**: Must be at least 1
  - Invalid values default to 1000

## Logging

When sampling is applied, the plugin logs detailed information:

```
INFO: Applying sampling to first file (threshold=1000, rate=0.5)...
INFO: Sampled from 2500 to 1250 connections (50.0% retained)
```

When sampling is disabled:

```
INFO: Sampling disabled by --no-sampling flag
```

## Best Practices

1. **For production analysis**: Use `--no-sampling` to ensure complete accuracy
2. **For exploratory analysis**: Use default settings or adjust threshold/rate as needed
3. **For very large datasets**: Start with aggressive sampling (e.g., `--sampling-rate 0.3`) and increase if needed
4. **Monitor logs**: Check the sampling statistics to understand how many connections were processed

## See Also

- [Match Plugin Documentation](match_plugin.md)
- [Connection Matching Algorithm](connection_matching.md)
- [Performance Tuning Guide](performance_tuning.md)

