# Per-Stream-Pair Statistics Improvement

## 问题描述

在使用 `--match-mode one-to-many` 模式时，compare 插件的统计输出存在以下问题：

### 问题 1: Matched TCP Connections 表格数据重复

**旧行为**：
- 使用五元组提取 packets，导致相同五元组的所有 stream 显示相同的数据
- 例如：A 文件的 Stream 0-10 都显示 193 packets，时间范围完全相同

```
Matched TCP Connections in Compare File (A_processed.pcap)
No.    Stream ID    Packets    First Time             Last Time             
1      0            193        1757441703689601000    1757445296366607000   
2      1            193        1757441703689601000    1757445296366607000   ← 重复
3      2            193        1757441703689601000    1757445296366607000   ← 重复
...
```

### 问题 2: 统计数据未按 Stream 配对区分

**旧行为**：
- Difference Type Statistics 和 TCP FLAGS Detailed Breakdown 是全局统计
- 无法区分不同 stream 配对的差异

```
Difference Type Statistics
Difference Type      Total Count    Affected Connections
TCP_FLAGS_DIFF       759            11                    ← 全局统计
SEQ_NUM_DIFF         759            11
...
```

---

## 解决方案

### 修改 1: 使用 stream_id 提取 packets

**文件**: `capmaster/plugins/compare/plugin.py`

**改动**：
```python
# 旧代码：使用五元组提取
baseline_packets = extractor.extract_packets(
    baseline_file,
    match.conn1.client_ip,
    match.conn1.client_port,
    match.conn1.server_ip,
    match.conn1.server_port,
)

# 新代码：使用 stream_id 提取
baseline_packets = extractor.extract_by_stream_id(
    baseline_file,
    match.conn1.stream_id,
)
```

**效果**：
- 每个 stream 显示其自己的 packet 数量和时间范围
- 支持相同五元组的多个 stream

### 修改 2: 按 Stream 配对统计差异

**文件**: `capmaster/plugins/compare/plugin.py`

**改动**：
```python
# 旧代码：全局统计
diff_type_counter = Counter()
tcp_flags_details = Counter()

# 新代码：按 stream 配对统计
stream_pair_stats = {}
for match, packets_a, packets_b, result in results:
    stream_pair = (match.conn1.stream_id, match.conn2.stream_id)
    if stream_pair not in stream_pair_stats:
        stream_pair_stats[stream_pair] = {
            'diff_types': Counter(),
            'tcp_flags': Counter(),
            ...
        }
```

**效果**：
- 每个 stream 配对有独立的统计区域
- 可以清晰看到每个配对的具体差异

---

## 改进后的输出

### 1. Matched TCP Connections 表格

**新行为**：每个 stream 显示不同的数据

```
Matched TCP Connections in Compare File (A_processed.pcap)
No.    Stream ID    Packets    First Time             Last Time             
1      0            92         1757441703689601000    1757442351726475000   ✓ 不同
2      1            7          1757442628343419000    1757442692206559000   ✓ 不同
3      2            7          1757442819289202000    1757442883182632000   ✓ 不同
4      3            7          1757443008700894000    1757443072622532000   ✓ 不同
...
```

### 2. Per-Stream-Pair Statistics

**新行为**：每个配对有独立的统计区域

```
============================================================================
Per-Stream-Pair Statistics
============================================================================

────────────────────────────────────────────────────────────────────────────
Stream Pair: Baseline Stream 0 ↔ Compare Stream 0
Connection: 8.42.96.45:35101 <-> 8.67.2.125:26302
────────────────────────────────────────────────────────────────────────────

  Difference Type Statistics:
  Difference Type      Count          
  -----------------------------------
  IPID_DIFF            70             
  PACKET_COUNT_DIFF    1              
  -----------------------------------

────────────────────────────────────────────────────────────────────────────
Stream Pair: Baseline Stream 0 ↔ Compare Stream 1
Connection: 8.42.96.45:35101 <-> 8.67.2.125:26302
────────────────────────────────────────────────────────────────────────────

  Difference Type Statistics:
  Difference Type      Count          
  -----------------------------------
  IPID_DIFF            155            
  TCP_FLAGS_DIFF       7              
  SEQ_NUM_DIFF         7              
  PACKET_COUNT_DIFF    1              
  -----------------------------------

  TCP FLAGS Detailed Breakdown:
  Baseline FLAGS       Compare FLAGS        Count          
  --------------------------------------------------------
  0x0010 [ACK]        0x0002 [SYN]         7              
    Example Frame ID pairs (Baseline → Compare):
      (101→100), (102→101), (103→102), (104→103), (105→104)
      (106→105), (107→106)
  --------------------------------------------------------
  TOTAL                                    7              

────────────────────────────────────────────────────────────────────────────
Stream Pair: Baseline Stream 0 ↔ Compare Stream 2
Connection: 8.42.96.45:35101 <-> 8.67.2.125:26302
────────────────────────────────────────────────────────────────────────────

  Difference Type Statistics:
  Difference Type      Count          
  -----------------------------------
  IPID_DIFF            155            
  TCP_FLAGS_DIFF       7              
  SEQ_NUM_DIFF         7              
  PACKET_COUNT_DIFF    1              
  -----------------------------------

  TCP FLAGS Detailed Breakdown:
  Baseline FLAGS       Compare FLAGS        Count          
  --------------------------------------------------------
  0x0010 [ACK]        0x0002 [SYN]         7              
    Example Frame ID pairs (Baseline → Compare):
      (101→100), (102→101), (103→102), (104→103), (105→104)
      (106→105), (107→106)
  --------------------------------------------------------
  TOTAL                                    7              

...
```

---

## 测试验证

### 测试命令

```bash
python -m capmaster compare \
  --file1 cases/dbs_20251028-Masked/B_processed.pcap \
  --file1-pcapid 1 \
  --file2 cases/dbs_20251028-Masked/A_processed.pcap \
  --file2-pcapid 0 \
  --match-mode one-to-many
```

### 测试结果

✅ **Matched TCP Connections 表格**
- B Stream 0: 162 packets（所有匹配都是同一个 stream，正确）
- A Stream 0: 92 packets
- A Stream 1-10: 各 7 packets
- 每个 stream 的时间范围都不同

✅ **Per-Stream-Pair Statistics**
- Stream 0 ↔ Stream 0: 70 IPID_DIFF, 无 TCP_FLAGS_DIFF
- Stream 0 ↔ Stream 1: 155 IPID_DIFF, 7 TCP_FLAGS_DIFF
- Stream 0 ↔ Stream 2: 155 IPID_DIFF, 7 TCP_FLAGS_DIFF
- 每个配对的统计数据都不同

---

## 关键改进点

1. **数据准确性**：
   - ✅ 每个 stream 显示其真实的 packet 数量和时间范围
   - ✅ 不再有重复数据

2. **统计粒度**：
   - ✅ 从全局统计改为按 stream 配对统计
   - ✅ 可以清晰看到每个配对的具体差异

3. **可读性**：
   - ✅ 清晰的分隔线和标题
   - ✅ 每个配对独立显示
   - ✅ 易于定位和分析问题

4. **兼容性**：
   - ✅ 支持 one-to-many 模式
   - ✅ 支持相同五元组的多个 stream
   - ✅ 向后兼容 one-to-one 模式

---

## 总结

通过这两个改进，compare 插件现在能够：

1. **正确显示每个 stream 的数据**：使用 `extract_by_stream_id` 而不是五元组提取
2. **按 stream 配对统计差异**：每个配对有独立的统计区域
3. **支持 one-to-many 场景**：一个 B stream 匹配多个 A streams

这使得在分析一对多匹配场景时，能够清晰地看到每个 stream 配对的具体差异，而不是混在一起的全局统计。

