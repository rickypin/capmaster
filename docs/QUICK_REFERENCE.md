# CapMaster Quick Reference Card

> **Scope（范围）**：为常见 CLI 用法提供示例级“速查卡”，方便人类和 AI 快速拼出常用命令。
> **Contract（契约）**：示例命令展示的是“推荐组合”和典型参数，不保证覆盖所有 flags；精确语义以 `capmaster --help` 输出和代码实现为准。
> **Implementation Pointers**：需要确认参数含义或默认值时，请查看 `capmaster/plugins/*` 中各插件的 CLI 定义（`setup_cli`）以及相关测试用例。
> **Maintenance**：仅在推荐命令模式发生明显变化时更新此文件，避免在此重复维护完整参数表。

---

## Installation

```bash
pip install -e .
capmaster --version
```

---

## Common Commands

### Preprocess PCAP Files (Cleaning / One-way / Time Align)

```bash
# Basic preprocessing for a single file
capmaster preprocess -i sample.pcap

# Preprocess a directory of PCAPs
capmaster preprocess -i /path/to/pcaps/ -o /path/to/pcaps-preprocessed/

# Run only time-align and dedup steps
capmaster preprocess -i sample.pcap --step time-align --step dedup
```

### Analyze PCAP Files

```bash
# Single file
capmaster analyze -i sample.pcap

# Directory (non-recursive)
capmaster analyze -i /path/to/pcaps/

# Specific files
capmaster analyze --file1 sample1.pcap --file2 sample2.pcap

# Custom output directory
capmaster analyze -i sample.pcap -o /custom/output/

# Verbose output
capmaster -v analyze -i sample.pcap
capmaster -vv analyze -i sample.pcap  # Debug mode
```

### Match TCP Connections

```bash
# Basic matching (directory with 2 files)
capmaster match -i /path/to/pcaps/

# Explicit file inputs
capmaster match --file1 client.pcap --file2 server.pcap

# Save to file
capmaster match -i /path/to/pcaps/ -o matches.txt

# Header-only mode
capmaster match -i /path/to/pcaps/ --mode header

# Custom bucketing
capmaster match -i /path/to/pcaps/ --bucket server
capmaster match -i /path/to/pcaps/ --bucket port
capmaster match -i /path/to/pcaps/ --bucket none

# Custom threshold
capmaster match -i /path/to/pcaps/ --threshold 0.70

# Combined options
capmaster match -i /path/to/pcaps/ \
  --mode auto \
  --bucket server \
  --threshold 0.60 \
  -o results.txt
```

---

## Command Options

### Global Options

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `-v, --verbose` | INFO level logging |
| `-vv` | DEBUG level logging |
| `--help` | Show help message |

### Analyze Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--input` | `-i` | Input file or directory | Required |
| `--output` | `-o` | Output directory | `<input_dir>/statistics/` |
| `--no-recursive` | `-r` | Do NOT recursively scan directories | Recursive by default |
| `--workers` | `-w` | Number of worker processes | 1 |
| `--format` | `-f` | Output file format (txt/md) | txt |

### Match Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--input` | `-i` | Input directory | Required |
| `--output` | `-o` | Output file | stdout |
| `--mode` | | Matching mode (auto/header) | auto |
| `--bucket` | | Bucketing strategy | auto |
| `--threshold` | | Score threshold (0.0-1.0) | 0.60 |

### Preprocess Options

> **Note**: The legacy `filter` subcommand has been replaced by the more general `preprocess` pipeline.
> 以下是常用 `preprocess` 选项的速查（完整参数以 `capmaster preprocess --help` 为准）。

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--input` | `-i` | Input PCAP file, directory, or comma-separated file list | Required |
| `--output` | `-o` | Output directory for preprocessed files | Auto-created under input when omitted |
| `--step` | | Explicit step list (time-align, dedup, oneway) | From config |
| `--enable-dedup` / `--disable-dedup` | | Enable/disable dedup step | From config |
| `--enable-oneway` / `--disable-oneway` | | Enable/disable one-way detection step | From config |
| `--enable-time-align` / `--disable-time-align` | | Enable/disable time-align step | From config |
| `--dedup-window-packets` | | Dedup window size in packets | From config |
| `--dedup-ignore-bytes` | | Ignore N bytes at packet end when deduplicating | From config |
| `--oneway-ack-threshold` | | ACK threshold for one-way detection | From config |
| `--workers` | `-w` | Number of worker processes | From config |

---

## Analysis Modules (28 total)

### Network Layer
| Module | Output Suffix | Description |
|--------|---------------|-------------|
| Protocol Hierarchy | `protocol-hierarchy.txt` | Protocol distribution |
| IPv4 Conversations | `ipv4-conversations.txt` | IPv4 conversation statistics |
| IPv4 Source TTLs | `ipv4-source-ttls.txt` | TTL distribution by source |
| IPv4 Destinations | `ipv4-destinations-and-ports.txt` | Destination IPs and ports |
| IPv4 Hosts | `ipv4-hosts.txt` | IP endpoint statistics |

### Transport Layer
| Module | Output Suffix | Description |
|--------|---------------|-------------|
| TCP Conversations | `tcp-conversations.txt` | TCP session statistics |
| TCP Zero Window | `tcp-zero-window.txt` | Flow control issues |
| TCP Duration | `tcp-connection-duration.txt` | Connection timing statistics |
| TCP Completeness | `tcp-completeness.txt` | SYN/FIN/RST analysis |
| UDP Conversations | `udp-conversations.txt` | UDP session statistics |

### Application Layer
| Module | Output Suffix | Description |
|--------|---------------|-------------|
| DNS Statistics | `dns-stats.txt` | DNS query/response stats |
| DNS Query/Response | `dns-query-response.txt` | DNS QR statistics |
| HTTP Statistics | `http-stats.txt` | HTTP request/response stats |
| HTTP Response | `http-response-code.txt` | HTTP response codes |
| FTP Statistics | `ftp-response-code.txt` | FTP response codes |
| FTP Data | `ftp-data-stats.txt` | FTP data transfer stats |
| TLS Alert | `tls-alert-message.txt` | TLS alert messages |
| ICMP Statistics | `icmp-messages.txt` | ICMP message stats |

### VoIP Protocols
| Module | Output Suffix | Description |
|--------|---------------|-------------|
| SIP Statistics | `sip-stats.txt` | SIP protocol statistics |
| RTP Statistics | `rtp-stats.txt` | RTP stream statistics |
| RTCP Statistics | `rtcp-stats.txt` | RTCP statistics |
| MGCP Statistics | `mgcp-stats.txt` | MGCP protocol statistics |
| SDP Statistics | `sdp-stats.txt` | SDP session statistics |
| VoIP Quality | `voip-quality.txt` | VoIP quality metrics |

### Other Protocols
| Module | Output Suffix | Description |
|--------|---------------|-------------|
| SSH Statistics | `ssh-stats.txt` | SSH protocol statistics |
| JSON Statistics | `json-stats.txt` | JSON data statistics |
| XML Statistics | `xml-stats.txt` | XML data statistics |
| MQ Statistics | `mq-stats.txt` | Message Queue statistics |

---

## Match Features & Weights

| Feature | Weight | Description |
|---------|--------|-------------|
| SYN Options | 25% | TCP SYN packet options |
| Client ISN | 12% | Client initial sequence number |
| Server ISN | 6% | Server initial sequence number |
| TCP Timestamp | 10% | TCP timestamp option |
| Client Payload | 15% | MD5 hash of client data |
| Server Payload | 8% | MD5 hash of server data |
| Length Signature | 8% | Packet length similarity |
| IP ID | 16% | IP identification sequence |

---

## Bucketing Strategies

| Strategy | Best For | Description |
|----------|----------|-------------|
| `auto` | General use | Automatic selection |
| `server` | Multiple servers | Group by server IP |
| `port` | Single server | Group by server port |
| `none` | Small datasets | No grouping (exhaustive) |

---

## Threshold Guidelines

### Match Threshold

| Range | Use Case |
|-------|----------|
| 0.40-0.60 | Lenient matching, more results |
| 0.60-0.70 | Balanced (default) |
| 0.70-0.85 | Strict matching, high confidence |

> **Note**: The legacy `filter` subcommand has been removed in favor of the more general `preprocess` pipeline.
> 
Threshold tuning for one-way detection is now controlled via `--oneway-ack-threshold` and related preprocess settings (see `capmaster preprocess --help`).

---

## Output Files

### Analyze Output

```
<input_dir>/statistics/
├── <basename>-1-protocol-hierarchy.txt
├── <basename>-1-tcp-conversations.txt
├── <basename>-1-tcp-zero-window.txt
└── ... (12 files total)
```

### Match Output

```
=== TCP Connection Matching Results ===

File 1: client.pcap
File 2: server.pcap

Matched Pairs: 63

Match #1 (Score: 0.95)
  File 1: Stream 5 | 192.168.1.100:54321 -> 93.184.216.34:443
  File 2: Stream 12 | 10.0.0.50:54321 -> 93.184.216.34:443
```



---

## Common Workflows

### 1. Complete Analysis

```bash
# Analyze all files
capmaster analyze -i captures/ -r

# View results
ls captures/statistics/
```



### 3. Debug Workflow

```bash
# Run with debug output
capmaster -vv analyze -i problem.pcap 2> debug.log

# Check log
cat debug.log
```

---

## Troubleshooting

### tshark Not Found

```bash
# macOS
brew install wireshark

# Ubuntu
sudo apt install tshark

# Verify
which tshark
```

### No Matches Found

```bash
# Try lower threshold
capmaster match -i captures/ --threshold 0.40

# Try different bucketing
capmaster match -i captures/ --bucket none

# Check files
ls -lh captures/*.pcap
```

### Permission Denied

```bash
# Check permissions
ls -l file.pcap

# Fix permissions
chmod 644 file.pcap
```

---

## Performance Tips

1. **Use filtering first** for large files
2. **Enable bucketing** for match operations
3. **Use concurrent workers** for batch analysis (`-w`)
4. **Adjust thresholds** based on needs
5. **Use SSD storage** for better I/O

---

## Environment Variables

```bash
# Set tshark path (if not in PATH)
export TSHARK_PATH=/custom/path/to/tshark

# Set log level
export CAPMASTER_LOG_LEVEL=DEBUG
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | File not found |
| 4 | tshark error |

---

## Getting Help

```bash
# General help
capmaster --help

# Command-specific help
capmaster analyze --help
capmaster match --help
capmaster preprocess --help
capmaster topology --help
capmaster streamdiff --help
capmaster comparative-analysis --help

# Version info
capmaster --version
```

---

## Match & Compare Consistency

Ensure consistent results between match and compare commands:

```bash
# Step 1: Match and save JSON
capmaster match -i /path/to/pcaps/ --match-json matches.json

# Step 2: Packet diff via comparative-analysis (preferred)
capmaster comparative-analysis --packet-diff -i /path/to/pcaps/ --match-file matches.json

# Legacy fallback (will be removed in a future release)
capmaster compare -i /path/to/pcaps/ --match-file matches.json

# Benefits:
# - Guaranteed consistency between match and packet diff
# - Reusable match results
# - Faster compare (skips matching step)
```

---

## Sampling Control (Large Datasets)

Control sampling for large datasets:

```bash
# Default: No sampling (all connections processed)
capmaster match -i captures/

# Enable sampling with custom threshold
capmaster match -i captures/ --sample-threshold 5000 --sample-rate 0.5

# Aggressive sampling for very large datasets
capmaster match -i huge_dataset/ --sample-threshold 10000 --sample-rate 0.2

# Sampling decision tree:
# < 1,000 connections    → No sampling needed
# 1,000 - 5,000          → Optional: --sample-rate 0.5
# 5,000 - 10,000         → Recommended: --sample-rate 0.3-0.7
# > 10,000               → Recommended: --sample-rate 0.2-0.5
```

**Note**: Header-only connections and special ports (HTTP, HTTPS, SSH, DNS, etc.) are always preserved.

---

## F5 Load Balancer Support

For PCAP files with F5 Ethernet Trailer:

```bash
# Automatic F5 detection (recommended)
capmaster match \
  --file1 SNAT.pcap --file1-pcapid 0 \
  --file2 VIP.pcap --file2-pcapid 1

# Explicit F5 mode
capmaster match \
  --file1 SNAT.pcap --file1-pcapid 0 \
  --file2 VIP.pcap --file2-pcapid 1 \
  --f5-mode

# F5 matching provides 100% accuracy (confidence = 1.00)
```

---

## Resources

- **README**: Installation and quick start
- **USER_GUIDE**: Detailed usage guide with advanced features
- **CHANGELOG**: Version history
- **MATCH_LOGIC_COMPLETE**: Detailed matching algorithm documentation

---

## Examples

### Example 1: Quick Analysis

```bash
capmaster analyze -i sample.pcap
cat statistics/sample-1-protocol-hierarchy.txt
```

### Example 2: Match with Custom Settings

```bash
capmaster match -i captures/ \
  --threshold 0.70 \
  --bucket server \
  -o high_confidence_matches.txt
```

### Example 3: Preprocess and Analyze

```bash
# Preprocess noisy capture into a clean directory
capmaster preprocess -i noisy.pcap -o clean/

# Run analysis on preprocessed PCAPs
capmaster analyze -i clean/
```

### Example 4: Consistent Match & Compare Workflow

```bash
# Generate matches
capmaster match -i captures/ --match-json m.json -o matches.txt

# Compare using same matches
capmaster compare -i captures/ --match-file m.json -o comparison.txt
```

### Example 5: Large Dataset with Sampling

```bash
capmaster match -i large_capture/ \
  --sample-threshold 5000 \
  --sample-rate 0.5 \
  --threshold 0.60 \
  -o matches.txt
```

---

**Quick Reference Card v1.0.0**
*For detailed information, see USER_GUIDE.md*
