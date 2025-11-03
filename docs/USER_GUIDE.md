# CapMaster User Guide

This comprehensive guide covers all aspects of using CapMaster for PCAP analysis, TCP connection matching, and filtering.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Analyze Command](#analyze-command)
3. [Match Command](#match-command)
4. [Filter Command](#filter-command)
5. [Clean Command](#clean-command)
6. [Advanced Usage](#advanced-usage)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)

## Getting Started

### Prerequisites

Before using CapMaster, ensure you have:

- Python 3.10 or higher
- tshark 4.0 or higher
- Sufficient disk space for output files

### Verify Installation

```bash
# Check Python version
python3 --version

# Check tshark version
tshark -v

# Check CapMaster installation
capmaster --version
```

### Understanding PCAP Files

CapMaster works with PCAP (Packet Capture) files in two formats:
- `.pcap` - Standard PCAP format
- `.pcapng` - Next-generation PCAP format (recommended)

## Analyze Command

The `analyze` command generates comprehensive statistics from PCAP files.

### Basic Usage

```bash
# Analyze a single file
capmaster analyze -i capture.pcap

# Analyze all files in a directory
capmaster analyze -i /path/to/captures/

# Recursive analysis
capmaster analyze -i /path/to/captures/ -r
```

### Output Structure

By default, statistics are saved to `<input_dir>/statistics/`:

```
statistics/
├── capture-1-protocol-hierarchy.txt
├── capture-1-tcp-conversations.txt
├── capture-1-tcp-zero-window.txt
├── capture-1-tcp-duration.txt
├── capture-1-tcp-completeness.txt
├── capture-1-udp-conversations.txt
├── capture-1-dns-stats.txt
├── capture-1-http-stats.txt
├── capture-1-tls-stats.txt
├── capture-1-ftp-stats.txt
├── capture-1-icmp-stats.txt
└── capture-1-ipv4-hosts.txt
```

### Analysis Modules

#### 1. Protocol Hierarchy

Shows the distribution of protocols in the capture:

```
Protocol Hierarchy Statistics
Filter: frame

frame                                    frames:1000 bytes:1500000
  eth                                    frames:1000 bytes:1500000
    ip                                   frames:950 bytes:1425000
      tcp                                frames:800 bytes:1200000
        http                             frames:200 bytes:300000
        tls                              frames:400 bytes:600000
      udp                                frames:150 bytes:225000
        dns                              frames:100 bytes:150000
```

#### 2. TCP Conversations

Lists all TCP conversations with packet and byte counts:

```
TCP Conversations
Filter:<No Filter>

                                               |       <-      | |       ->      | |     Total     |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |
192.168.1.100:54321 <-> 93.184.216.34:443      |    150  45000 | |    120  36000 | |    270  81000 |
```

#### 3. TCP Zero Window

Identifies TCP zero window events (flow control issues):

```
Frame  Time                    Source          Destination     SrcPort DstPort
123    2024-01-15 10:30:45.123 192.168.1.100   93.184.216.34   54321   443
```

#### 4. TCP Duration

Statistical analysis of TCP packet timing:

```
| IO Statistics                                                |
|                                                              |
| Duration: 60.5 secs                                          |
| Interval: 60.5 secs                                          |
|                                                              |
| MIN(tcp.time_delta): 0.000001                               |
| MAX(tcp.time_delta): 5.234567                               |
| AVG(tcp.time_delta): 0.012345                               |
```

#### 5. TCP Completeness

Analyzes TCP connection completeness (SYN, FIN, RST):

```
Complete Connections (SYN + FIN/RST): 45
Incomplete Connections: 5
  - Missing SYN: 2
  - Missing FIN/RST: 3
```

### Custom Output Directory

```bash
capmaster analyze -i capture.pcap -o /custom/output/path/
```

### Verbose Output

```bash
# INFO level logging
capmaster -v analyze -i capture.pcap

# DEBUG level logging
capmaster -vv analyze -i capture.pcap
```

## Match Command

The `match` command identifies matching TCP connections across multiple PCAP files using an advanced 8-feature scoring algorithm.

### Use Cases

- Matching client-side and server-side captures
- Correlating captures from different network segments
- Identifying the same connection in multiple traces

### Basic Usage

```bash
# Match connections in a directory
capmaster match -i /path/to/captures/

# Save results to file
capmaster match -i /path/to/captures/ -o matches.txt
```

### Input Requirements

The input directory must contain **exactly 2 PCAP files**:

```
captures/
├── client.pcap
└── server.pcap
```

### Matching Algorithm

CapMaster uses an 8-feature weighted scoring system:

| Feature | Weight | Description |
|---------|--------|-------------|
| SYN Options | 25% | TCP SYN packet options fingerprint |
| Client ISN | 12% | Client initial sequence number |
| Server ISN | 6% | Server initial sequence number |
| TCP Timestamp | 10% | TCP timestamp option |
| Client Payload | 15% | MD5 hash of first N bytes from client |
| Server Payload | 8% | MD5 hash of first N bytes from server |
| Length Signature | 8% | Jaccard similarity of packet lengths |
| IP ID | 16% | IP identification field sequence |

**Total Score:** 0.0 to 1.0 (normalized)

### Matching Modes

#### Auto Mode (Default)

Automatically detects the best matching strategy:

```bash
capmaster match -i captures/ --mode auto
```

#### Header-Only Mode

For captures with only TCP headers (no payload):

```bash
capmaster match -i captures/ --mode header
```

### Bucketing Strategies

Bucketing groups connections before matching to improve performance:

#### Auto (Default)

Automatically selects the best strategy:

```bash
capmaster match -i captures/ --bucket auto
```

#### Server IP Bucketing

Groups connections by server IP address:

```bash
capmaster match -i captures/ --bucket server
```

Best for: Multiple servers, few connections per server

#### Port Bucketing

Groups connections by server port:

```bash
capmaster match -i captures/ --bucket port
```

Best for: Single server, multiple services

#### No Bucketing

Compares all connections (slower but most thorough):

```bash
capmaster match -i captures/ --bucket none
```

### Score Threshold

Adjust the minimum score for a match:

```bash
# Default threshold (0.60)
capmaster match -i captures/

# Stricter matching (higher threshold)
capmaster match -i captures/ --threshold 0.80

# More lenient matching (lower threshold)
capmaster match -i captures/ --threshold 0.40
```

**Recommendations:**
- **0.60-0.70**: Balanced (default)
- **0.70-0.85**: High confidence matches only
- **0.40-0.60**: Include more potential matches

### Output Format

```
=== TCP Connection Matching Results ===

File 1: client.pcap
File 2: server.pcap

Bucketing Strategy: PORT
Matching Mode: AUTO

Total Connections:
  File 1: 150 connections
  File 2: 145 connections

Matched Pairs: 63

--- Match Details ---

Match #1 (Score: 0.95)
  File 1: Stream 5 | 192.168.1.100:54321 -> 93.184.216.34:443
  File 2: Stream 12 | 10.0.0.50:54321 -> 93.184.216.34:443
  Features:
    - SYN Options: MATCH (0.25)
    - Client ISN: MATCH (0.12)
    - Server ISN: MATCH (0.06)
    - TCP Timestamp: MATCH (0.10)
    - Client Payload: MATCH (0.15)
    - Server Payload: MATCH (0.08)
    - Length Signature: 0.95 (0.076)
    - IP ID: MATCH (0.16)

Match #2 (Score: 0.82)
  ...
```

## Filter Command

The `filter` command removes one-way TCP connections from PCAP files.

### What are One-Way Connections?

One-way connections occur when:
- Only one side of the communication is captured
- Network issues prevent bidirectional traffic
- Asymmetric routing causes incomplete captures

### Basic Usage

```bash
# Filter a single file
capmaster filter -i noisy.pcap -o clean.pcap

# Use default output name
capmaster filter -i noisy.pcap
# Output: noisy_filtered.pcap
```

### Detection Algorithm

The filter identifies one-way connections by:

1. Analyzing ACK number increments in each TCP stream
2. Counting pure ACK packets (tcp.len==0)
3. Marking streams exceeding the threshold as one-way

### Threshold Adjustment

The threshold determines how many pure ACK packets indicate a one-way connection:

```bash
# Default threshold (20)
capmaster filter -i capture.pcap

# More aggressive filtering
capmaster filter -i capture.pcap -t 10

# More conservative filtering
capmaster filter -i capture.pcap -t 100
```

**Recommendations:**
- **10-20**: Aggressive (removes more connections)
- **20-50**: Balanced (default range)
- **50-100**: Conservative (keeps more connections)

### Handling Sequence Number Wraparound

CapMaster correctly handles 32-bit TCP sequence number wraparound:

```python
# Example: ACK numbers near wraparound
ACK1: 4294967290 (near max)
ACK2: 10 (wrapped around)
Delta: 16 (correctly calculated)
```

## Clean Command

The `clean` command removes statistics directories and their contents, helping you manage disk space and clean up analysis outputs.

### Basic Usage

```bash
# Clean statistics directories recursively (with confirmation)
capmaster clean -i /path/to/data

# Clean only top-level statistics directory
capmaster clean -i /path/to/data -r

# Dry run to see what would be deleted
capmaster clean -i /path/to/data --dry-run

# Clean without confirmation prompt
capmaster clean -i /path/to/data -y
```

### How It Works

The clean command:

1. Searches for all directories named `statistics` under the specified path
2. Calculates the total size of files to be deleted
3. Shows a preview of what will be deleted
4. Asks for confirmation (unless `-y` flag is used)
5. Deletes the directories and shows progress

### Options

#### Recursive vs Non-Recursive

```bash
# Recursive (default): Find all statistics directories in subdirectories
capmaster clean -i /path/to/data

# Non-recursive: Only clean top-level statistics directory
capmaster clean -i /path/to/data -r
```

**Example directory structure:**
```
/path/to/data/
├── statistics/           ← Deleted in both modes
├── dir1/
│   └── statistics/       ← Deleted only in recursive mode
└── dir2/
    └── statistics/       ← Deleted only in recursive mode
```

#### Dry Run Mode

Preview what will be deleted without actually deleting:

```bash
capmaster clean -i /path/to/data --dry-run
```

**Output:**
```
INFO     Found 3 statistics directories

         Directories to be deleted:
INFO       - /path/to/data/dir1/statistics (1.25 MB)
INFO       - /path/to/data/dir2/statistics (856.00 KB)
INFO       - /path/to/data/statistics (2.10 MB)

         Total size: 4.21 MB

INFO     [DRY RUN] No files were deleted
```

#### Auto-Confirm Mode

Skip the confirmation prompt (use with caution):

```bash
# Dangerous: Deletes immediately without asking
capmaster clean -i /path/to/data -y
```

### Safety Features

The clean command includes several safety features:

1. **Confirmation Prompt**: By default, asks for confirmation before deleting
2. **Dry Run**: Preview deletions with `--dry-run`
3. **Specific Target**: Only deletes directories named `statistics`
4. **Size Display**: Shows total size before deletion
5. **Progress Tracking**: Shows deletion progress
6. **Error Handling**: Continues if some directories fail to delete

### Use Cases

#### 1. Clean Up After Analysis

```bash
# Analyze PCAP files
capmaster analyze -i captures/

# Review the statistics
ls captures/statistics/

# Clean up when done
capmaster clean -i captures/ -y
```

#### 2. Reclaim Disk Space

```bash
# Check what would be deleted
capmaster clean -i /large/dataset --dry-run

# Clean if satisfied
capmaster clean -i /large/dataset
```

#### 3. Batch Cleanup

```bash
# Clean multiple directories
for dir in project1 project2 project3; do
    capmaster clean -i "$dir" -y
done
```

#### 4. Selective Cleanup

```bash
# Clean only top-level statistics (keep nested ones)
capmaster clean -i /path/to/data -r -y
```

### Output Example

```bash
$ capmaster clean -i /tmp/test_data -y

INFO     Searching for statistics directories in: /tmp/test_data
INFO     Found 3 statistics directories

         Directories to be deleted:
INFO       - /tmp/test_data/dir1/statistics (12.00 B)
INFO       - /tmp/test_data/dir2/statistics (12.00 B)
INFO       - /tmp/test_data/dir1/subdir/statistics (12.00 B)

         Total size: 36.00 B

⠋ Deleting 3 directories... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0%
INFO     Deleted: /tmp/test_data/dir1/statistics
INFO     Deleted: /tmp/test_data/dir2/statistics
INFO     Deleted: /tmp/test_data/dir1/subdir/statistics
  Deleting 3 directories... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

INFO     Successfully deleted 3/3 directories (36.00 B freed)
```

### Best Practices

1. **Always use dry-run first** when cleaning important data:
   ```bash
   capmaster clean -i /important/data --dry-run
   ```

2. **Use verbose mode** to see detailed information:
   ```bash
   capmaster -v clean -i /path/to/data
   ```

3. **Backup important statistics** before cleaning:
   ```bash
   tar -czf statistics_backup.tar.gz */statistics/
   capmaster clean -i . -y
   ```

4. **Be careful with auto-confirm** in scripts:
   ```bash
   # Good: Check if directory exists first
   if [ -d "/path/to/data" ]; then
       capmaster clean -i /path/to/data -y
   fi
   ```

## Advanced Usage

### Batch Processing

Process multiple PCAP files efficiently:

```bash
#!/bin/bash
# analyze_all.sh

for pcap in *.pcap; do
    echo "Analyzing $pcap..."
    capmaster analyze -i "$pcap" -o "results/$pcap/"
done
```

### Pipeline Integration

Combine CapMaster commands:

```bash
# Filter then analyze
capmaster filter -i noisy.pcap -o clean.pcap
capmaster analyze -i clean.pcap

# Match then filter both files
capmaster match -i captures/ -o matches.txt
capmaster filter -i captures/client.pcap -o captures/client_clean.pcap
capmaster filter -i captures/server.pcap -o captures/server_clean.pcap
```

### Scripting with Python

```python
import subprocess
import json

def analyze_pcap(input_file, output_dir):
    """Analyze a PCAP file using CapMaster."""
    result = subprocess.run(
        ['capmaster', 'analyze', '-i', input_file, '-o', output_dir],
        capture_output=True,
        text=True
    )
    return result.returncode == 0

# Use in your script
if analyze_pcap('capture.pcap', 'results/'):
    print("Analysis complete!")
```

## Troubleshooting

### Common Issues

#### 1. tshark Not Found

**Error:** `tshark not found in PATH`

**Solution:**
```bash
# macOS
brew install wireshark

# Ubuntu
sudo apt install tshark

# Verify
which tshark
```

#### 2. Permission Denied

**Error:** `Permission denied: capture.pcap`

**Solution:**
```bash
# Check file permissions
ls -l capture.pcap

# Fix permissions
chmod 644 capture.pcap
```

#### 3. No Matches Found

**Issue:** Match command returns 0 matches

**Solutions:**
- Lower the threshold: `--threshold 0.40`
- Check if files contain the same connections
- Verify both files have TCP traffic
- Try different bucketing strategies

#### 4. Out of Memory

**Issue:** Large PCAP files cause memory errors

**Solutions:**
- Process files individually
- Use filtering to reduce file size first
- Increase system memory
- Split large files into smaller chunks

### Debug Mode

Enable debug logging for troubleshooting:

```bash
capmaster -vv analyze -i capture.pcap 2> debug.log
```

## Best Practices

### 1. File Organization

```
project/
├── raw/              # Original captures
├── filtered/         # Filtered captures
├── analysis/         # Analysis results
└── matches/          # Match results
```

### 2. Naming Conventions

Use descriptive names:
```
client_2024-01-15_10-30.pcap
server_2024-01-15_10-30.pcap
```

### 3. Regular Cleanup

Remove temporary files:
```bash
# Clean old statistics
find analysis/ -name "*.txt" -mtime +30 -delete
```

### 4. Version Control

Track analysis results:
```bash
git add matches.txt
git commit -m "Analysis results for 2024-01-15"
```

### 5. Documentation

Document your analysis:
```markdown
# Analysis Report - 2024-01-15

## Files Analyzed
- client.pcap (15 MB, 10,000 packets)
- server.pcap (18 MB, 12,000 packets)

## Findings
- 63 matched connections
- 5 one-way connections filtered
- Average match score: 0.85
```

## Performance Tips

1. **Use filtering first** for large files
2. **Enable bucketing** for match operations
3. **Process files in parallel** when possible
4. **Use SSD storage** for better I/O performance
5. **Adjust thresholds** based on your needs

## Next Steps

- Explore the [API Documentation](API.md) for programmatic usage
- Check the [CHANGELOG](../CHANGELOG.md) for version history
- Report issues on [GitHub](https://github.com/yourusername/capmaster/issues)

