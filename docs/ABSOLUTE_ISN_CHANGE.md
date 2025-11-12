# 绝对序列号（Absolute ISN）修改说明

## 修改日期
2025-11-12

## 修改原因

### 问题发现
在分析匹配结果时发现，当前 Match 插件使用的是**相对序列号（Relative Sequence Numbers）**，导致：

1. **所有连接的 ISN 都是 0**
   - tshark 默认使用相对序列号模式
   - 在相对模式下，SYN 包的序列号被归一化为 0
   - 所有有 SYN 包的连接，其 `client_isn` 和 `server_isn` 都是 0

2. **ISN 失去区分能力**
   - ISN 匹配变成了"是否都有 SYN 包"的检查
   - 无法通过 ISN 排除不同连接的误匹配
   - 降低了匹配算法的准确性

3. **与 Compare 插件不一致**
   - Compare 插件使用绝对序列号（`-o tcp.relative_sequence_numbers:false`）
   - Match 插件使用相对序列号（默认行为）
   - 两个插件的行为不一致

### 示例：修改前的问题

```
Match 1: Score=0.61 | Evidence=isnC isnS ts shape(1.00) ipid*
A: 10.52.170.71:36114 <-> 10.95.35.148:8080
   Client ISN: 0 (0x00000000)  ← 所有连接都是 0
   Server ISN: 0 (0x00000000)  ← 所有连接都是 0

B: 10.52.170.71:44614 <-> 10.95.35.148:8080
   Client ISN: 0 (0x00000000)  ← 所有连接都是 0
   Server ISN: 0 (0x00000000)  ← 所有连接都是 0

✓ Client ISN matches: 0  ← 假阳性！
✓ Server ISN matches: 0  ← 假阳性！
```

## 修改内容

### 1. 修改 `capmaster/core/connection/extractor.py`

**修改前：**
```python
args = [
    "-r", str(pcap_file),
    "-Y", "tcp",
    # NOTE: Use relative sequence numbers to match original script behavior
    "-o", "tcp.desegment_tcp_streams:false",
    ...
]
```

**修改后：**
```python
args = [
    "-r", str(pcap_file),
    "-Y", "tcp",
    # Use absolute sequence numbers for accurate ISN matching
    "-o", "tcp.relative_sequence_numbers:false",  # ← 新增
    "-o", "tcp.desegment_tcp_streams:false",
    ...
]
```

### 2. 更新 `capmaster/core/connection/scorer.py` 注释

更新了 `_score_isn_client()` 和 `_score_isn_server()` 的注释，说明：
- ISN 现在是真实的 32 位绝对值
- ISN 匹配是真正的值匹配，而不是"是否都有 SYN 包"的检查

### 3. 更新文档 `docs/MATCH_LOGIC_COMPLETE.md`

在 ISN 特征说明中添加：
- **格式**: 32 位整数（绝对序列号）
- **重要性**: 32 位随机数，碰撞概率 < 10^-9，是强区分特征

## 修改效果

### 修改后的行为

```
Match 1: Score=0.40 | Evidence=ts shape(1.00) ipid*
A: 10.52.170.71:36114 <-> 10.95.35.148:8080
   Client ISN: 3377375738 (0xc94ea9fa)  ← 真实的 32 位值
   Server ISN: 3004422537 (0xb313d989)  ← 真实的 32 位值

B: 10.52.170.71:44614 <-> 10.95.35.148:8080
   Client ISN: 1712228007 (0x660e86a7)  ← 真实的 32 位值
   Server ISN: 1960931316 (0x74e16ff4)  ← 真实的 32 位值

✗ Client ISN differs  ← 正确识别出不同！
✗ Server ISN differs  ← 正确识别出不同！
```

### 对匹配结果的影响

使用测试数据 `/Users/ricky/Downloads/2hops/dbs_1112`：

| 指标 | 修改前 | 修改后 | 变化 |
|------|--------|--------|------|
| 匹配对数 | 2 | 1 | -1 |
| 第一个匹配置信度 | 0.61 | 0.40 | -0.21 |
| 第一个匹配证据 | `isnC isnS ts shape(1.00) ipid*` | `ts shape(1.00) ipid*` | 失去 ISN 证据 |
| 第二个匹配 | 存在 | 消失 | ISN 不匹配被正确排除 |

### 详细分析：唯一的匹配

```
Connection A:
  10.52.170.71:36114 <-> 10.95.35.148:8080
  Packets: 3716
  Client ISN: 3377375738 (0xc94ea9fa)
  Server ISN: 3004422537 (0xb313d989)
  IPID Set Size: 1210

Connection B:
  10.52.170.71:44614 <-> 10.95.35.148:8080
  Packets: 2721
  Client ISN: 1712228007 (0x660e86a7)
  Server ISN: 1960931316 (0x74e16ff4)
  IPID Set Size: 742

IPID Analysis:
  IPID Intersection: 673
  Overlap Ratio: 90.70%
  Jaccard Similarity: 52.62%

Feature Comparison:
  Client ISN Match: False  ← ISN 不匹配
  Server ISN Match: False  ← ISN 不匹配
  SYN Options Match: False
  Timestamp TSval Match: False
  Timestamp TSecr Match: True
  Length Signature Match: True

Conclusion:
  ✓ Strong IPID match (force_accept=True)
    - IPID overlap: 673 IPIDs, 90.7% ratio
  ⚠️ Score 0.40 is below threshold 0.60
  ⚠️ This match relies entirely on strong IPID evidence
```

## 重要发现

### 1. ISN 不匹配揭示了真相

修改后发现，之前匹配的两个连接：
- **ISN 完全不同**（客户端和服务器的 ISN 都不同）
- **SYN Options 也不同**
- **TCP Timestamp TSval 也不同**

这说明它们很可能是**不同的连接**，只是：
- IPID 高度重叠（90.7%）
- 包长度序列相同
- 时间戳 TSecr 相同（都是 0）

### 2. 强 IPID 匹配的局限性

虽然 IPID 重叠率达到 90.7%，但：
- ISN、SYN Options、Timestamp TSval 都不匹配
- 最终得分只有 0.40（低于 0.60 阈值）
- 仅因为 `force_accept=True`（强 IPID）才被接受

这提示我们：
- **强 IPID 条件可能过于宽松**
- 应该考虑增加其他必要条件
- 或者提高强 IPID 的阈值

### 3. 相对序列号的危害

使用相对序列号导致：
- **假阳性增加**：ISN 总是匹配（都是 0）
- **置信度虚高**：错误地增加了 ISN 的权重（12% + 6% = 18%）
- **误匹配风险**：无法通过 ISN 排除不同连接

## 建议

### 1. 短期建议

✅ **已完成**：使用绝对序列号
- 修改 `extractor.py` 添加 `-o tcp.relative_sequence_numbers:false`
- 更新相关注释和文档

### 2. 中期建议

⚠️ **待评估**：调整强 IPID 条件
- 当前：IPID 重叠 ≥ 10 且比例 ≥ 80%
- 建议：增加其他必要条件（如至少一个方向特征匹配）
- 或者：提高阈值（如 IPID 重叠 ≥ 20 且比例 ≥ 90%）

### 3. 长期建议

📋 **待实现**：增强匹配算法
- 实现角色互换尝试（自动尝试交换客户端/服务器角色）
- 增加更多方向无关特征
- 支持部分四元组匹配（NAT 场景）

## 兼容性影响

### 对现有用户的影响

⚠️ **破坏性变更**：
- 匹配结果可能会减少（排除了之前的假阳性）
- 置信度可能会降低（ISN 不再总是匹配）
- 证据字符串可能会变化（ISN 证据可能消失）

✅ **正面影响**：
- 提高匹配准确性（减少假阳性）
- ISN 成为真正的强区分特征
- 与 Compare 插件行为一致

### 迁移建议

对于现有用户：
1. **重新运行匹配**：使用新版本重新匹配 PCAP 文件
2. **检查结果差异**：对比新旧结果，分析差异原因
3. **调整阈值**（如需要）：如果匹配数过少，可以适当降低 `score_threshold`

## 测试验证

### 测试环境
- 测试数据：`/Users/ricky/Downloads/2hops/dbs_1112`
- 文件 1：`x01saulvweb3a-L.pcap` (1492 连接)
- 文件 2：`x01saulvweb3a-c.pcap` (1143 连接)

### 测试结果
- ✅ ISN 提取正确（非零的 32 位值）
- ✅ ISN 匹配逻辑正确（能够区分不同连接）
- ✅ 假阳性减少（匹配数从 2 降到 1）
- ✅ 与 Compare 插件行为一致

## 总结

这次修改是一个**重要的 bug 修复**：

1. **修复了 ISN 特征失效的问题**
   - 从相对序列号改为绝对序列号
   - ISN 恢复了作为强区分特征的能力

2. **提高了匹配准确性**
   - 减少假阳性
   - 更准确地识别不同连接

3. **统一了插件行为**
   - Match 和 Compare 插件现在都使用绝对序列号
   - 行为一致，易于理解和维护

4. **揭示了潜在问题**
   - 强 IPID 条件可能需要调整
   - 需要更多测试数据验证新算法

**建议后续工作**：
- 收集更多测试数据，验证新算法的准确性
- 评估是否需要调整强 IPID 条件
- 考虑实现角色互换尝试功能

