# Match Plugin Sampling - Quick Reference

## TL;DR

```bash
# Default: No sampling (process all connections)
capmaster match -i captures/

# Enable sampling for large datasets
capmaster match -i captures/ --enable-sampling

# Custom threshold (sample only if > 5000 connections)
capmaster match -i captures/ --enable-sampling --sample-threshold 5000

# Custom rate (keep 70% when sampling)
capmaster match -i captures/ --enable-sampling --sample-rate 0.7

# Combined
capmaster match -i captures/ --enable-sampling --sample-threshold 2000 --sample-rate 0.8
```

## Default Behavior

**⚠️ IMPORTANT: Sampling is DISABLED by default!**

| Parameter | Default Value | Description |
|-----------|---------------|-------------|
| Sampling | Disabled | All connections are processed |
| Threshold | 1000 | When enabled, sampling triggers when connections > 1000 |
| Rate | 0.5 (50%) | When enabled, keeps half of the connections |
| Protected | Always | Header-only + special ports preserved when sampling |

## CLI Options

### `--enable-sampling`
- **Type**: Flag
- **Default**: False (disabled)
- **Effect**: Enables sampling for large datasets
- **Use when**: You have very large datasets and want faster processing

### `--sample-threshold <number>`
- **Type**: Integer
- **Default**: 1000
- **Range**: >= 1
- **Effect**: Sets when sampling kicks in (only when --enable-sampling is used)
- **Use when**: Adjusting for dataset size

### `--sample-rate <decimal>`
- **Type**: Float
- **Default**: 0.5
- **Range**: 0.0 < rate <= 1.0
- **Effect**: Sets retention percentage (only when --enable-sampling is used)
- **Use when**: Balancing speed vs accuracy

## Decision Tree

```
How many connections?
├─ < 1,000
│  └─ Use default (no sampling, all connections processed)
│
├─ 1,000 - 5,000
│  ├─ Need 100% accuracy? → Use default (no flags needed)
│  └─ Want faster processing? → --enable-sampling
│
├─ 5,000 - 10,000
│  ├─ Need high accuracy? → Use default or --enable-sampling --sample-rate 0.7
│  └─ Speed matters? → --enable-sampling --sample-rate 0.3
│
└─ > 10,000
   ├─ Need accuracy? → Use default or --enable-sampling --sample-threshold 20000 --sample-rate 0.5
   └─ Need speed? → --enable-sampling --sample-rate 0.2
```

## Common Scenarios

### Scenario 1: Production Analysis (Accuracy Critical - DEFAULT)

```bash
# Default behavior: no sampling, all connections processed
capmaster match -i evidence/ -o report.txt
```

### Scenario 2: Quick Exploration (Speed Matters)

```bash
capmaster match -i dataset/ --enable-sampling --sample-rate 0.3
```

### Scenario 3: Large Dataset (Balance)

```bash
capmaster match -i large_capture/ \
  --enable-sampling \
  --sample-threshold 5000 \
  --sample-rate 0.5
```

### Scenario 4: Very Large Dataset (Aggressive)

```bash
capmaster match -i huge_dataset/ \
  --enable-sampling \
  --sample-threshold 10000 \
  --sample-rate 0.2
```

## What Gets Preserved?

Even with aggressive sampling, these are **always** kept:

1. **Header-only connections** (SYN/SYN-ACK only)
   - Critical for TCP fingerprinting
   
2. **Special port connections**:
   - FTP (20, 21)
   - SSH (22)
   - Telnet (23)
   - SMTP (25)
   - DNS (53)
   - HTTP/HTTPS (80, 443)
   - POP3/IMAP (110, 143)
   - MySQL (3306)
   - PostgreSQL (5432)
   - Redis (6379)
   - MongoDB (27017)

## Performance Impact

| Connections | Default Time | --no-sampling Time | --sampling-rate 0.3 Time |
|-------------|--------------|-------------------|-------------------------|
| 1,000 | ~2s | ~2s | ~2s |
| 5,000 | ~8s | ~15s | ~5s |
| 10,000 | ~15s | ~60s | ~8s |
| 50,000 | ~60s | ~300s | ~30s |

*Times are approximate and depend on hardware*

## Validation & Warnings

Invalid parameters are automatically corrected:

```bash
# Invalid rate (> 1.0)
capmaster match -i captures/ --sampling-rate 1.5
# WARNING: Invalid sampling rate 1.5, using default 0.5

# Invalid rate (<= 0.0)
capmaster match -i captures/ --sampling-rate 0.0
# WARNING: Invalid sampling rate 0.0, using default 0.5

# Invalid threshold (< 1)
capmaster match -i captures/ --sampling-threshold 0
# WARNING: Invalid sampling threshold 0, using default 1000
```

## Logging Output

### With Sampling Enabled

```text
INFO: Found 2500 connections in file1.pcap
INFO: Found 3000 connections in file2.pcap
INFO: Applying sampling to first file (threshold=1000, rate=0.5)...
INFO: Sampled from 2500 to 1250 connections (50.0% retained)
INFO: Applying sampling to second file (threshold=1000, rate=0.5)...
INFO: Sampled from 3000 to 1500 connections (50.0% retained)
```

### Without Sampling (Default)

```text
INFO: Found 2500 connections in file1.pcap
INFO: Found 3000 connections in file2.pcap
INFO: Sampling disabled (default behavior). Use --enable-sampling to enable.
```

## Combining with Other Options

All sampling options work with other match options:

```bash
capmaster match -i captures/ \
  --enable-sampling \                # Enable sampling
  --sample-threshold 2000 \          # Sampling threshold
  --sample-rate 0.5 \                # Sampling rate
  --threshold 0.70 \                 # Match score threshold
  --match-mode one-to-many \         # Match mode
  --bucket server \                  # Bucketing strategy
  --endpoint-stats \                 # Generate stats
  --endpoint-stats-output stats.txt  # Stats output
  -o matches.txt                     # Match output
```

## Troubleshooting

### "Out of memory" error

- Enable aggressive sampling: `--enable-sampling --sample-rate 0.2`
- Or increase threshold: `--enable-sampling --sample-threshold 20000`

### "Too few matches found"

- Use default (no sampling): remove `--enable-sampling` flag
- Or increase rate: `--enable-sampling --sample-rate 0.8`

### "Taking too long"

- Enable sampling: `--enable-sampling --sample-rate 0.3`
- Or lower threshold: `--enable-sampling --sample-threshold 500`

## See Also

- Full documentation: `docs/match_sampling_control.md`
- Examples: `examples/match_sampling_examples.sh`
- Implementation details: `SAMPLING_CONTROL_IMPLEMENTATION.md`

