# ACK Lost Segment 指标功能

## 概述

新增 `tcp.analysis.ack_lost_segment` 指标，用于更准确地区分真实网络丢包和抓包遗漏。

> **Scope（范围）**：定义 ACK Lost Segment / Real Loss 相关字段及其关系，用于网络质量分析和报表。
> **Contract（契约）**：以字段名和公式为准，保证这些指标在代码中存在且语义一致；不在此重复实现细节。
> **Implementation Pointers**：需要精确行为时，请查看 `QualityMetrics`、`TcpAnalysisPacket` 等数据类以及对应的解析与计算逻辑和测试。
> **Maintenance**：新增或修改相关字段、公式或含义时务必同步更新本文件的“字段与公式”描述。

## 问题背景

原有的 `tcp.analysis.lost_segment` 指标存在局限性：
- **无法区分**真实网络丢包 vs 抓包点遗漏
- 可能将抓包遗漏误判为网络丢包
- 影响网络质量分析的准确性

## 解决方案

### 新增指标

1. **`tcp.analysis.ack_lost_segment`** (ACKed Lost Segment)
   - 含义：ACK 确认了一个未被捕获的数据段
   - 说明：该数据段**实际到达了对端**，只是抓包点没抓到
   - 用途：识别抓包遗漏

2. **Real Loss** (真实丢包)
   - 计算公式：`Real Loss = max(0, Lost Segments - ACK Lost Segments)`
   - 含义：排除抓包遗漏后的真实网络丢包

### 判断逻辑

| Lost Segment | ACK Lost Segment | 结论 |
|--------------|------------------|------|
| 高 | 高 | **抓包遗漏** - 数据段实际到达，只是没抓到 |
| 高 | 低 | **真实网络丢包** - 数据段确实丢失 |
| 低 | 低 | 网络质量良好 |

## 代码变更

### 1. QualityMetrics 数据类

新增字段：
```python
client_ack_lost_segments: int = 0
"""ACKed segments that weren't captured on client side"""

server_ack_lost_segments: int = 0
"""ACKed segments that weren't captured on server side"""
```

新增属性方法：
```python
@property
def client_ack_lost_rate(self) -> float:
    """Calculate client-to-server ACKed lost segment rate."""

@property
def client_real_loss_rate(self) -> float:
    """Calculate client-to-server real packet loss rate (excluding capture misses)."""

@property
def server_ack_lost_rate(self) -> float:
    """Calculate server-to-client ACKed lost segment rate."""

@property
def server_real_loss_rate(self) -> float:
    """Calculate server-to-client real packet loss rate (excluding capture misses)."""
```

### 2. TcpAnalysisPacket 数据类

新增字段：
```python
has_ack_lost_segment: bool
```

### 3. tshark 提取字段

新增提取字段：
```python
"-e", "tcp.analysis.ack_lost_segment",
```

### 4. 性能评分算法

更新为使用真实丢包率：
```python
# 使用 real_loss_rate 替代 loss_rate
avg_real_loss_rate = (metrics.client_real_loss_rate + metrics.server_real_loss_rate) / 2
penalty = (avg_retrans_rate * 0.4) + (avg_dup_ack_rate * 0.3) + (avg_real_loss_rate * 0.3)
```

### 5. 报告格式

新增列：
- **Lost Seg**: 丢失段（可能包含抓包遗漏）
- **ACK Lost**: ACK 丢失段（抓包遗漏指标）
- **Real Loss**: 真实丢包（排除抓包遗漏）

## 使用示例

### 服务级别分析

```bash
capmaster comparative-analysis \
    -i /path/to/pcaps/ \
    --service \
    --topology topology.txt \
    -o report.txt
```

输出将包含新的指标列：
```
Service                File   Direction        Packets    Retrans      Dup ACK      Lost Seg     ACK Lost     Real Loss
10.93.75.130:8443      A      Client->Server   1,000         10 (1.0%)     5 (0.5%)     8 (0.8%)     5 (0.5%)     3 (0.3%)
                              Server->Client   1,000          8 (0.8%)     4 (0.4%)     6 (0.6%)     4 (0.4%)     2 (0.2%)
```

### 连接对分析

```bash
capmaster comparative-analysis \
    -i /path/to/pcaps/ \
    --matched-connections matched_connections.txt \
    --top-n 10
```

## 优势

1. **更准确的丢包判断**：区分真实丢包和抓包遗漏
2. **更可靠的性能评分**：基于真实丢包率计算
3. **更好的故障诊断**：识别是网络问题还是抓包问题
4. **向后兼容**：保留原有 `lost_segment` 指标

## 测试

运行测试脚本验证功能：
```bash
python scripts/manual/test_ack_lost_segment.py
```

## 参考

- tshark 字段文档：`tshark -G fields | grep tcp.analysis`
- Wireshark TCP Analysis: https://wiki.wireshark.org/TCP_Analyze_Sequence_Numbers

