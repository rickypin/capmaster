# Match 和 Compare 结果一致性指南

## 问题背景

在之前的实现中，`match` 和 `compare` 命令各自独立进行连接匹配，可能导致以下问题：

1. **匹配结果不一致**：两个命令可能为同一对 PCAP 文件产生不同的匹配结果
2. **调试困难**：当 match 显示某个连接对匹配，但 compare 却比对了不同的连接对时，难以追踪问题
3. **非确定性**：当多个连接得分相同时，贪心算法可能选择不同的匹配对

## 解决方案

新增功能允许 `compare` 命令复用 `match` 命令的匹配结果，确保两者使用完全相同的连接对。

### 工作流程

```
┌─────────────────┐
│  match 命令     │
│  生成匹配结果   │
└────────┬────────┘
         │
         ├─> 输出文本结果 (stdout/file)
         │
         └─> 保存 JSON 格式 (--match-json)
                    │
                    ▼
         ┌──────────────────────┐
         │  matches.json        │
         │  (序列化的匹配结果)  │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  compare 命令        │
         │  (--match-file)      │
         │  复用匹配结果        │
         └──────────────────────┘
```

## 使用方法

### 步骤 1: 运行 match 命令并保存结果

```bash
# 基本用法
capmaster match -i /path/to/pcaps/ --match-json matches.json

# 使用显式文件指定
capmaster match \
  --file1 baseline.pcap --file1-pcapid 0 \
  --file2 compare.pcap --file2-pcapid 1 \
  --match-json matches.json

# 同时输出文本和 JSON
capmaster match -i /path/to/pcaps/ \
  -o matches.txt \
  --match-json matches.json
```

### 步骤 2: 使用 match 结果运行 compare 命令

```bash
# 基本用法
capmaster compare -i /path/to/pcaps/ --match-file matches.json

# 使用显式文件指定
capmaster compare \
  --file1 baseline.pcap --file1-pcapid 0 \
  --file2 compare.pcap --file2-pcapid 1 \
  --match-file matches.json

# 输出到文件
capmaster compare -i /path/to/pcaps/ \
  --match-file matches.json \
  -o comparison.txt

# 写入数据库
capmaster compare -i /path/to/pcaps/ \
  --match-file matches.json \
  --show-flow-hash \
  --db-connection "postgresql://user:pass@host:port/db" \
  --kase-id 133
```

## JSON 文件格式

`--match-json` 生成的 JSON 文件包含以下信息：

```json
{
  "version": "1.0",
  "file1": "/path/to/baseline.pcap",
  "file2": "/path/to/compare.pcap",
  "metadata": {
    "total_connections_1": 12,
    "total_connections_2": 4877,
    "matched_pairs": 12,
    "unmatched_1": 0,
    "unmatched_2": 4865,
    "match_rate_1": 1.0,
    "match_rate_2": 0.002,
    "average_score": 0.58,
    "match_mode": "one-to-one"
  },
  "matches": [
    {
      "conn1": {
        "stream_id": 9,
        "client_ip": "173.173.173.51",
        "client_port": 65448,
        "server_ip": "172.100.8.40",
        "server_port": 8000,
        ...
      },
      "conn2": {
        "stream_id": 24091,
        "client_ip": "172.100.8.102",
        "client_port": 24091,
        "server_ip": "172.168.200.216",
        "server_port": 8000,
        ...
      },
      "score": {
        "normalized_score": 0.57,
        "evidence": "isnC isnS dataC dataS ipid*",
        "force_accept": false,
        "microflow_accept": false
      }
    }
  ]
}
```

## 验证和错误处理

### 文件路径验证

当使用 `--match-file` 时，compare 命令会验证：

1. **文件名匹配**：检查 JSON 中记录的文件名是否与当前文件匹配
2. **Stream ID 存在性**：验证匹配中的 stream ID 是否在当前 PCAP 文件中存在

如果验证失败，会显示警告但继续执行（使用有效的匹配）。

### 示例警告

```
WARNING: Match file was created for different files:
  Expected: baseline.pcap, compare.pcap
  Actual:   old_baseline.pcap, old_compare.pcap
Proceeding anyway, but results may be incorrect.

WARNING: Skipped 2 matches that don't exist in current connections.
Using 10 valid matches.
```

## 优势

1. **一致性保证**：match 和 compare 使用完全相同的连接对
2. **可重现性**：保存的 JSON 文件可以重复使用，确保结果可重现
3. **调试友好**：可以检查 JSON 文件确认具体匹配了哪些连接
4. **性能优化**：compare 不需要重新进行匹配计算

## 注意事项

1. **文件一致性**：确保 compare 使用的 PCAP 文件与 match 时使用的相同
2. **版本兼容性**：JSON 格式包含版本号，未来版本可能不兼容
3. **存储空间**：JSON 文件包含完整的连接信息，可能较大

## 完整示例

```bash
# 1. 运行 match 并保存结果
capmaster match -i /Users/ricky/Downloads/2hops/aomenjinguanju/ \
  --match-json /tmp/aomen_matches.json \
  -o /tmp/aomen_matches.txt

# 输出:
# ================================================================================
# TCP Connection Matching Results
# ================================================================================
# Statistics:
#   Total connections (file 1): 12
#   Total connections (file 2): 4877
#   Matched pairs: 12
#   ...

# 2. 使用相同的匹配结果运行 compare
capmaster compare -i /Users/ricky/Downloads/2hops/aomenjinguanju/ \
  --match-file /tmp/aomen_matches.json \
  --show-flow-hash \
  -o /tmp/aomen_comparison.txt

# 现在 compare 的输出中，连接对将与 match 的结果完全一致：
# Stream Pair: Baseline Stream 9 ↔ Compare Stream 24091
# Connection: 173.173.173.51:65448 <-> 172.100.8.40:8000
```

## 故障排除

### 问题：compare 报告 "No valid matches found"

**原因**：JSON 文件中的 stream ID 在当前 PCAP 文件中不存在

**解决方案**：
1. 确认使用的是相同的 PCAP 文件
2. 检查 PCAP 文件是否被修改过
3. 重新运行 match 命令生成新的 JSON 文件

### 问题：文件名不匹配警告

**原因**：PCAP 文件路径或名称发生变化

**解决方案**：
1. 如果只是路径变化（文件名相同），可以忽略警告
2. 如果文件名也变化了，建议重新运行 match 命令

## API 参考

### match 命令新增选项

```
--match-json PATH
    输出 JSON 文件保存匹配结果。此文件可用作 compare 命令的输入，
    确保 match 和 compare 操作之间的匹配一致性。
```

### compare 命令新增选项

```
--match-file PATH
    包含 match 命令结果的 JSON 文件。当提供此选项时，compare 将使用
    这些匹配结果而不是执行自己的匹配。这确保了 match 和 compare 结果
    之间的一致性。
```

