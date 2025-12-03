# CapMaster User Guide

This comprehensive guide covers all aspects of using CapMaster for PCAP analysis, TCP connection matching, and filtering.

> **Scope（范围）**：面向人类用户和 AI Agent，描述 CapMaster CLI 的对外行为和典型使用场景。
> **Contract（契约）**：只约定命令名称、关键参数和输入/输出形态，不保证穷举所有 flags 或内部实现细节。
> **Implementation Pointers**：需要精确语义时，请直接阅读 `capmaster/plugins/*` 中各插件的 `setup_cli` / `execute` 实现，以及 `tests/` 目录下的端到端用例。
> **Maintenance**：当 CLI 行为有变更时，仅更新受影响的小节；避免在文档中复制大段实现细节，以 `--help` 输出和测试为准。

## Table of Contents

1. [Getting Started](#getting-started)
2. [Analyze Command](#analyze-command)
3. [Match Command](#match-command)
4. [Compare Command](#compare-command)
5. [Preprocess Command](#preprocess-command)
6. [Topology Command](#topology-command)
7. [StreamDiff Command](#streamdiff-command)
8. [Comparative Analysis Command](#comparative-analysis-command)
9. [Clean Command](#clean-command)
10. [Advanced Usage](#advanced-usage)
11. [Troubleshooting](#troubleshooting)
12. [Best Practices](#best-practices)

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

# Analyze all files in a directory (non-recursive)
capmaster analyze -i /path/to/captures/

# Analyze specific files
capmaster analyze --file1 capture1.pcap --file2 capture2.pcap
```

### Output Structure

By default, statistics are saved to `<input_dir>/statistics/`:

```
statistics/
├── capture-protocol-hierarchy.txt
├── capture-ipv4-conversations.txt
├── capture-ipv4-source-ttls.txt
├── capture-ipv4-destinations-and-ports.txt
├── capture-ipv4-hosts.txt
├── capture-tcp-conversations.txt
├── capture-tcp-zero-window.txt
├── capture-tcp-connection-duration.txt
├── capture-tcp-completeness.txt
├── capture-udp-conversations.txt
├── capture-dns-stats.txt
├── capture-dns-query-response.txt
├── capture-http-stats.txt
├── capture-http-response-code.txt
├── capture-ftp-response-code.txt
├── capture-ftp-data-stats.txt
├── capture-tls-alert-message.txt
├── capture-icmp-messages.txt
├── capture-sip-stats.txt
├── capture-rtp-stats.txt
├── capture-rtcp-stats.txt
├── capture-mgcp-stats.txt
├── capture-sdp-stats.txt
├── capture-voip-quality.txt
├── capture-ssh-stats.txt
├── capture-json-stats.txt
├── capture-xml-stats.txt
└── capture-mq-stats.txt
```

Note: The actual files generated depend on the protocols detected in the PCAP file. Not all files will be created if the corresponding protocols are not present.

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
# Match connections in a directory (containing exactly 2 files)
capmaster match -i /path/to/captures/

# Match specific files
capmaster match --file1 client.pcap --file2 server.pcap

# Save results to file
capmaster match -i /path/to/captures/ -o matches.txt
```

### Input Requirements

You must provide **exactly 2 PCAP files** using either:
- `-i /path/to/dir/` (directory containing 2 files)
- `-i file1.pcap,file2.pcap` (comma-separated list)
- `--file1 file1.pcap --file2 file2.pcap` (explicit arguments)


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

## Compare Command

The `compare` command performs detailed packet-level comparison of matched TCP connections between two PCAP files.
> **Deprecation Notice**: `capmaster comparative-analysis --packet-diff` now提供完全一致的逐包对比输出，
> 并将在稳定后取代 `capmaster compare`。可以继续使用 compare 作为回退入口，但建议尽快迁移。

### Use Cases

- Verify packet-level consistency between client and server captures
- Identify differences in IP ID, TCP flags, sequence numbers, and acknowledgment numbers
- Analyze network behavior differences across capture points
- Debug NAT, load balancer, or proxy issues

### Basic Usage

```bash
# Compare two PCAP files in a directory
capmaster compare -i /path/to/captures/

# Compare specific files
capmaster compare --file1 client.pcap --file2 server.pcap

# Save results to file
capmaster compare -i /path/to/captures/ -o comparison.txt

# Show flow hash for each connection
capmaster compare -i /path/to/captures/ --show-flow-hash

# Preferred new workflow (equivalent output)
capmaster comparative-analysis --packet-diff -i /path/to/captures/
```

### Input Requirements

You must provide **exactly 2 PCAP files** using either:
- `-i /path/to/dir/` (directory containing 2 files)
- `-i file1.pcap,file2.pcap` (comma-separated list)
- `--file1 file1.pcap --file2 file2.pcap` (explicit arguments)


### Comparison Process

The compare command works in three stages:

1. **Match Connections**: Uses the same matching algorithm as the `match` command
2. **Extract Packets**: Extracts all packets for each matched connection pair
3. **Compare Packets**: Performs detailed packet-level comparison using IP ID as the pairing key

### Comparison Fields

For each packet pair, the following fields are compared:

| Field | Description |
|-------|-------------|
| IP ID | IP identification field (used as pairing key) |
| TCP Flags | TCP flags (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR) |
| Sequence Number | TCP sequence number |
| Acknowledgment Number | TCP acknowledgment number |

### Flow Hash Feature

The `--show-flow-hash` option calculates and displays a bidirectional flow identifier for each TCP connection:

```bash
capmaster compare -i captures/ --show-flow-hash
```

**Flow Hash Characteristics:**
- **Bidirectional**: Same hash for both directions of a flow
- **5-Tuple Based**: Uses source IP, destination IP, source port, destination port, and protocol
- **Normalized**: Endpoints are ordered consistently

**Use Cases:**
- Identify the same connection across different PCAP files
- Group packets belonging to the same flow
- Correlate connections in network analysis

For implementation details of the flow hash algorithm (bidirectional, 5-tuple based, normalized), see the code and tests around `capmaster.plugins.compare_common.flow_hash` and `tests/test_flow_hash.py`.

### Score Threshold

Adjust the minimum score for connection matching:

```bash
# Default threshold (0.60)
capmaster compare -i captures/

# Stricter matching (higher threshold)
capmaster compare -i captures/ --threshold 0.80

# More lenient matching (lower threshold)
capmaster compare -i captures/ --threshold 0.40
```

### Bucketing Strategies

Same as the `match` command:

```bash
# Auto (default)
capmaster compare -i captures/ --bucket auto

# Server IP bucketing
capmaster compare -i captures/ --bucket server

# Port bucketing
capmaster compare -i captures/ --bucket port

# No bucketing
capmaster compare -i captures/ --bucket none
```

### Output Format

#### Overall Summary

```
================================================================================
TCP Connection Packet-Level Comparison Report
================================================================================
File A: client.pcap
File B: server.pcap
Matched Connections: 50

Overall Summary:
  Total matched connections: 50
  Identical connections: 35
  Connections with differences: 15
```

#### Flow Hash Summary (with --show-flow-hash)

```
================================================================================
Flow Hash Summary
================================================================================
Connection                                                   Flow Hash                 Status
--------------------------------------------------------------------------------
192.168.1.100:54321 <-> 10.0.0.1:80                         a6bdc8ceba87bd4e (LHS>=RHS) Identical
192.168.1.101:54322 <-> 10.0.0.1:443                        db6b29fa86d8297f (RHS>LHS)  3 diffs
...
```

#### Difference Type Statistics

```
================================================================================
Difference Type Statistics
================================================================================
Difference Type      Total Count     Affected Connections
--------------------------------------------------------------------------------
TCP FLAGS            45              12
SEQUENCE             23              8
ACKNOWLEDGMENT       18              7
IPID                 5               3
--------------------------------------------------------------------------------
TOTAL                91              15
```

#### TCP FLAGS Detailed Breakdown

```
================================================================================
TCP FLAGS Detailed Breakdown
================================================================================
File A FLAGS                        File B FLAGS                        Count
--------------------------------------------------------------------------------
0x0010 [ACK]                        0x0018 [PSH, ACK]                   25
  Example Frame ID pairs (File A → File B):
    (123→456), (124→457), (125→458), (126→459), (127→460)
    ... and 20 more pairs
0x0002 [SYN]                        0x0012 [SYN, ACK]                   10
  Example Frame ID pairs (File A → File B):
    (100→400), (101→401), (102→402)
...
```

#### Per-Connection Summary

```
================================================================================
Per-Connection Summary
================================================================================
Connection ID                                      Score      Diffs      Types
--------------------------------------------------------------------------------
192.168.1.100:54321 <-> 10.0.0.1:80               0.95       3          tcp_flags
192.168.1.101:54322 <-> 10.0.0.1:443              0.88       5          tcp_flags, sequence
...
```

Or with `--show-flow-hash`:

```
================================================================================
Per-Connection Summary
================================================================================
Connection ID                                      Score      Diffs      Flow Hash
--------------------------------------------------------------------------------
192.168.1.100:54321 <-> 10.0.0.1:80               0.95       3          a6bdc8ceba87bd4e (LHS>=RHS)
192.168.1.101:54322 <-> 10.0.0.1:443              0.88       5          db6b29fa86d8297f (RHS>LHS)
...
```

### Examples

#### Basic Comparison

```bash
capmaster compare -i captures/
```

#### High-Confidence Matches Only

```bash
capmaster compare -i captures/ --threshold 0.80
```

#### With Flow Hash

```bash
capmaster compare -i captures/ --show-flow-hash -o results.txt
```

#### Custom Bucketing

```bash
capmaster compare -i captures/ --bucket port --threshold 0.70
```



## Preprocess Command

The `preprocess` command cleans and standardises PCAP files before further analysis.

### Basic Usage

```bash
# Preprocess a single file with default configuration
capmaster preprocess -i capture.pcap

# Preprocess multiple files (comma-separated list)
capmaster preprocess -i "a.pcap,b.pcap,c.pcap"

# Preprocess all files in a directory
capmaster preprocess -i /path/to/pcaps/
```

### Typical Pipeline

```bash
# Preprocess then analyze
capmaster preprocess -i noisy/ -o clean/
capmaster analyze -i clean/
```

Key steps performed by preprocess:

- **time-align**: compute a common time window and trim captures
- **dedup**: remove duplicate packets within a sliding window
- **oneway**: detect one-way TCP streams (using ACK threshold)

Use `capmaster preprocess --help` 查看完整参数说明，包括：

- `--step` 显式指定步骤（`time-align`、`dedup`、`oneway`）
- `--enable/--disable-*` 控制各个步骤是否启用
- `--dedup-window-packets` / `--dedup-ignore-bytes`
- `--oneway-ack-threshold`
- `--archive-original-files` / `--no-archive-original-files`
- 报告控制：`--no-report`、`--report-path`

## Pipeline Command

`run-pipeline` 允许借助 YAML 描述多步骤流程，例如先 match、再 topology、再 quality analysis。示例配置见 `examples/pipeline_standard.yaml`，最小可运行模板位于 `resources/pipeline_match_test.yaml`。

```bash
capmaster run-pipeline --file1 A.pcap --file2 B.pcap \
  -c resources/pipeline_match_test.yaml -o artifacts/tmp/pipeline_output
```

全局 CLI 参数会自动传入每个步骤：

- `-q/--quiet`：所有步骤以安静模式运行，不需要在 YAML 中逐一设置。
- `--strict`：子命令共享同一严格模式，任何 warning 直接提升为错误。
- `--allow-no-input`：当输入文件数量不足时，各子命令会按其内建逻辑静默退出（必要时会触发 `SystemExit(0)`，由 pipeline 捕获后跳过该步骤）。
- `-i/--input` 与 `--file1`~`--file6`：默认继承到每个步骤，除非在 YAML 的该步骤 `args` 中显式覆盖。若步骤引用的 `${FILEn}` 未能替换（例如只提供了 file1），该参数会被自动移除，从而触发 `allow-no-input` 的验证。

如果确实需要让某个步骤覆盖这些行为，仍可在 YAML 的对应 `args` 中显式设置 `quiet`/`strict`/`allow-no-input`，该值会覆盖从 CLI 继承的标志。

### 条件执行（`when`）

Pipeline 支持在每个步骤上添加 `when` 守卫来做条件执行，例如：

```yaml
- id: match_conn
  command: match
  when:
    min_input_files: 2          # 至少需要双抓包
  args:
    output: "${OUTPUT}/matched_connections.txt"

- id: topo_analysis
  command: topology
  when:
    require_steps: [match_conn] # 依赖上一步已执行
  args:
    matched-connections: "${STEP.match_conn.output}"
```

可用条件：

- `min_input_files` / `max_input_files`：以 run-pipeline 实际输入数量做上下限；不满足时跳过该步。
- `require_steps`：字符串或字符串列表；只有在列出的步骤已经成功执行并产生输出时才运行当前步骤。适合处理“若 match 被跳过则 topology 也跳过”的场景。

当某一步因 `when` 条件不满足而跳过时，后续引用其输出的步骤需要额外 `require_steps` 保护，否则变量解析会失败。

## Artifact Workspace

所有运行产出默认落在 `artifacts/` 下，按类型划分：

- `artifacts/analysis/`：脚本与手工汇总的 Markdown/JSON 报告。
- `artifacts/benchmarks/`：批量基准脚本的原始 stdout 与汇总 CSV。
- `artifacts/tmp/`：一次性调试输出（match/topology/streamdiff/pipeline 等）。

采集报告推荐流程：

1. 将 CLI 的 `-o/--output`、脚本输出目录等指向 `artifacts/...`。
2. 检查生成内容是否符合预期。
3. 需要版本沉淀时，将成品复制到 `reports/analysis/<case>/` 并在提交中跟踪。

示例：

```bash
mkdir -p artifacts/tmp
capmaster match -i data/2hops/aomenjinguanju_10MB -o artifacts/tmp/matched_connections.txt
cp artifacts/tmp/matched_connections.txt reports/analysis/aomenjinguanju-matched.txt
```

示例服务列表位于 `resources/services.txt`，可通过 `--service-list resources/services.txt` 传给 match/topology/pipeline 命令。

## Topology Command

The `topology` command renders network topology for one or two capture points.

### Basic Usage

```bash
# Single capture point topology
capmaster topology --single-file single_capture.pcap -o single_topology.txt

# Directory containing exactly two captures + matched connections
capmaster topology -i /path/to/data/2hops/ --matched-connections matched_connections.txt -o topology.txt

# Explicit files
capmaster topology --file1 a.pcap --file2 b.pcap --matched-connections matched_connections.txt -o topology.txt
```

Key options:

- `-i/--input`: 目录或逗号分隔的 PCAP 文件列表（1 或 2 个文件）
- `--single-file`: 单文件拓扑分析（单抓包点）
- `--file1/--file2`: 显式指定两个 PCAP 文件
- `--matched-connections`: 来自 `capmaster match` 的匹配连接结果
- `--empty-match-behavior`: 无有效匹配时的行为（`error` / `fallback-single`）
- `--service-list`: 可选服务列表文件，辅助服务端识别
- `-o/--output`: 输出报告文件（默认 stdout）

## StreamDiff Command

The `streamdiff` command compares a single TCP connection between two captures and lists packets that are present only in A or only in B (by IP ID).

### Basic Usage

```bash
# 使用 matched-connections 文件选择连接对
capmaster streamdiff -i /path/to/2pcaps \
  --matched-connections matched_connections.txt \
  --pair-index 1 -o streamdiff_report.txt

# 使用显式 tcp.stream ID 选择连接
capmaster streamdiff -i /path/to/2pcaps \
  --file1-stream-id 7 --file2-stream-id 33 -o streamdiff_report.txt
```

Key options:

- `-i/--input` 或 `--file1/--file2`：指定两个 PCAP 文件
- `--matched-connections` + `--pair-index`：从 `capmaster match` 输出中选择连接对
- `--file1-stream-id` / `--file2-stream-id`：手动指定两个文件中的 `tcp.stream` ID
- `-o/--output`：输出报告文件（默认 stdout）

## Comparative Analysis Command

The `comparative-analysis` command performs network quality analysis between two capture points.

It is exposed as a top-level command by the match plugin and uses the same dual-file input options as `match` and `compare`.

For详细说明（丢包、重传、ACK Lost、Real Loss 等指标，以及服务级别/连接对级别输出示例），参见:

- `docs/COMPARATIVE_ANALYSIS_GUIDE.md`
- `docs/ACK_LOST_SEGMENT_FEATURE.md`

## Managing Statistics Cleanup

CapMaster previously shipped a dedicated `capmaster clean` subcommand to remove `statistics/` directories. That utility is no longer maintained. Use your operating system tools (or custom scripts) to reclaim disk space when analysis outputs are no longer needed.

```bash
# Preview then remove statistics directories on Linux/macOS
find /path/to/data -type d -name "statistics" -print -exec rm -rf {} +
```

Best practices:

1. Run destructive commands behind a "dry run" preview (for example, execute the `find` command without `-exec` first).
2. Keep CapMaster outputs organized per capture so whole directories can be removed safely—`capmaster preprocess` already writes artifacts under `statistics/` for each input file.
3. Archive important reports (e.g., `tar -czf statistics_backup.tar.gz */statistics/`) before deleting local copies.

## Advanced Usage

### Selective Module Analysis

Run only specific analysis modules for faster execution:

```bash
# Analyze only protocol distribution
capmaster analyze -i capture.pcap -m protocol_hierarchy

# Analyze multiple specific modules
capmaster analyze -i capture.pcap -m protocol_hierarchy -m dns_stats -m http_stats

# Available modules: protocol_hierarchy, ipv4_conversations, tcp_conversations,
# dns_stats, http_stats, tls_alert, sip_stats, rtp_stats, voip_quality, etc.
# See full list with: capmaster analyze --help
```

### F5 Load Balancer Matching

For PCAP files captured from F5 load balancers with F5 Ethernet Trailer:

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

# F5 matching provides 100% accuracy when F5 trailers are present
# Match confidence will be 1.00 for all F5-based matches
```

### Flow Hash Analysis

Display bidirectional flow identifiers for connection correlation:

```bash
# Show flow hash in compare output
capmaster compare -i /path/to/pcaps/ --show-flow-hash

# Flow hash is consistent across both directions of a connection
# Useful for identifying the same flow across different PCAP files
```

### Sampling Control for Large Datasets

Control sampling behavior when processing large numbers of connections:

```bash
# Set custom sampling threshold (default: 5000 connections)
capmaster match -i /path/to/pcaps/ --sample-threshold 10000

# Set custom sampling rate (default: 0.5 = 50%)
capmaster match -i /path/to/pcaps/ --sample-rate 0.3

# Combine both parameters
capmaster match -i /path/to/pcaps/ --sample-threshold 8000 --sample-rate 0.4
```

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
# Preprocess then analyze
capmaster preprocess -i noisy.pcap -o clean/
capmaster analyze -i clean/

# Match, preprocess by capture point, then compare or analyze
capmaster match -i captures/ -o matches.txt
capmaster preprocess -i captures/client.pcap -o captures/client_clean/
capmaster preprocess -i captures/server.pcap -o captures/server_clean/
# Now you can run analyze/match/compare on the cleaned PCAPs
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
├── data/             # Symlinks to large datasets (2hops, cases, sample_captures, etc.)
├── artifacts/        # Runtime outputs (ignored by Git)
│   ├── analysis/
│   ├── benchmarks/
│   └── tmp/
└── reports/          # Curated, versioned deliverables
    └── analysis/
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
# Clean old statistics stored under artifacts
find artifacts/analysis -name "*.txt" -mtime +30 -delete
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

- 如需以编程方式集成 CapMaster，当前推荐通过 CLI 封装（例如 Python 的 `subprocess.run(["capmaster", ...])`），或直接阅读 `capmaster/` 源码和对应 tests 了解调用方式（目前仓库中不再维护单独的 API.md 文档）。
- Check the [CHANGELOG](../CHANGELOG.md) for version history
- Report issues on [GitHub](https://github.com/yourusername/capmaster/issues)
