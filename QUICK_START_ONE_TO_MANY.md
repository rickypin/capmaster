# 一对多匹配功能快速入门

## 什么时候使用一对多匹配？

当你遇到以下情况时，应该使用 `--match-mode one-to-many`：

### 典型场景

**场景 1：一个长连接被分割成多个短连接**

```
File A: 多个短 stream，相同 5 元组，不同时间段
├─ Stream 0: [0, 1000]
├─ Stream 1: [1000, 2000]
└─ Stream 2: [2000, 3000]

File B: 一个长 stream，覆盖整个时间范围
└─ Stream 0: [0, 3000]

问题：默认一对一匹配只能匹配 1 个 A stream
解决：使用一对多匹配，B Stream 0 可以匹配所有 A streams
```

**场景 2：不同抓包点导致的 stream 分割**

```
抓包点 A: 在客户端附近，连接被中间设备重置，产生多个 stream
抓包点 B: 在服务器附近，看到完整的长连接

需求：将 A 的多个 stream 与 B 的单个 stream 匹配
```

---

## 快速使用

### 基本命令

```bash
# 一对一匹配（默认）
capmaster compare --file1 B.pcap --file2 A.pcap

# 一对多匹配
capmaster compare --file1 B.pcap --file2 A.pcap --match-mode one-to-many
```

### 完整示例

```bash
capmaster compare \
  --file1 cases/B_processed.pcap \
  --file1-pcapid 1 \
  --file2 cases/A_processed.pcap \
  --file2-pcapid 0 \
  --match-mode one-to-many \
  --show-flow-hash \
  --matched-only \
  --db-connection "postgresql://user:pass@host:port/db" \
  --kase-id 133
```

---

## 匹配条件

一对多匹配需要满足以下**所有**条件：

1. ✅ **IPID 匹配**（必要条件）
2. ✅ **时间重叠**（必要条件）
3. ✅ **特征评分 ≥ 阈值**（默认 0.60）

### 示例

```
B Stream 0: IPID=61507, 时间=[0, 10000]
A Stream 0: IPID=61507, 时间=[0, 1000]   → ✅ 匹配（IPID 相同，时间重叠）
A Stream 1: IPID=61507, 时间=[1000, 2000] → ✅ 匹配（IPID 相同，时间重叠）
A Stream 2: IPID=9053,  时间=[2000, 3000] → ❌ 拒绝（IPID 不同）
A Stream 3: IPID=61507, 时间=[20000, 21000] → ❌ 拒绝（无时间重叠）
```

---

## 输出解读

### 一对一匹配输出

```
Statistics:
  total_connections_1: 1
  total_connections_2: 16
  matched_pairs: 1          ← 只有 1 个匹配
  unique_matched_1: 1
  unique_matched_2: 1
  unmatched_1: 0
  unmatched_2: 15           ← 15 个 A streams 未匹配
  match_mode: one-to-one
```

### 一对多匹配输出

```
Statistics:
  total_connections_1: 1
  total_connections_2: 16
  matched_pairs: 16         ← 16 个匹配
  unique_matched_1: 1       ← B 只有 1 个 stream
  unique_matched_2: 16      ← A 的 16 个 streams 都被匹配
  unmatched_1: 0
  unmatched_2: 0
  match_mode: one-to-many
  max_matches_per_conn1: 16 ← B Stream 0 匹配了 16 次
  avg_matches_per_conn1: 16.0
```

**关键指标**：
- `matched_pairs`: 总匹配数（一对多模式下可能 > 连接数）
- `unique_matched_1/2`: 唯一匹配的连接数
- `max_matches_per_conn1`: 单个连接最多匹配次数
- `avg_matches_per_conn1`: 平均每个连接匹配次数

---

## 性能考虑

### 时间复杂度

- **一对一**: O(n1 * n2 * log(n1 * n2))
- **一对多**: O(n1 * n2)

### 匹配数量

- **一对一**: 最多 min(n1, n2) 个匹配
- **一对多**: 最多 n1 * n2 个匹配

### 建议

- 如果不确定是否需要一对多，先用一对一试试
- 如果发现大量 `unmatched` 连接，考虑使用一对多
- 如果匹配数量过多（> 10000），考虑：
  - 增加 `--threshold` 阈值
  - 使用更精确的 bucketing 策略（`--bucket server` 或 `--bucket port`）

---

## 常见问题

### Q1: 为什么一对多匹配还是只有 1 个结果？

**可能原因**：
1. IPID 不同：检查 A streams 的 IPID 是否与 B stream 相同
2. 无时间重叠：检查 A streams 的时间范围是否与 B stream 重叠
3. 评分过低：尝试降低 `--threshold` 阈值

**调试方法**：
```bash
# 查看详细日志
capmaster compare ... --match-mode one-to-many 2>&1 | grep -E "(IPID|time|score)"
```

### Q2: 一对多匹配会影响性能吗？

**答案**：影响很小。

- 时间复杂度相同：O(n1 * n2)
- 只是不使用 `used` 集合，接受所有有效匹配
- 实际测试：16 streams vs 1 stream，耗时 < 1ms

### Q3: 可以同时使用一对一和一对多吗？

**答案**：不可以，只能选择一种模式。

- 默认：`--match-mode one-to-one`
- 一对多：`--match-mode one-to-many`

### Q4: 一对多匹配会产生重复的数据库记录吗？

**答案**：会，这是预期行为。

- 每个匹配都会写入数据库
- B Stream 0 匹配 16 个 A streams → 16 条数据库记录
- 可以通过 SQL 查询聚合结果

---

## 实际案例

### 用户案例：16 个 A streams vs 1 个 B stream

**背景**：
- File A: 16 个 TCP streams (0-15)，相同 5 元组，不同时间段
- File B: 1 个 TCP stream (0)，覆盖整个时间范围
- 所有 streams 的 IPID 都是 61507

**命令**：
```bash
capmaster compare \
  --file1 cases/dbs_20251028-Masked/B_processed.pcap \
  --file1-pcapid 1 \
  --file2 cases/dbs_20251028-Masked/A_processed.pcap \
  --file2-pcapid 0 \
  --match-mode one-to-many \
  --show-flow-hash \
  --matched-only \
  --db-connection "postgresql://postgres:password@172.16.200.156:5433/r2" \
  --kase-id 133
```

**预期结果**：
- 16 个匹配
- B Stream 0 匹配所有 16 个 A streams
- 数据库中有 16 条记录

**验证**：
```sql
-- 查询匹配结果
SELECT 
    tcp_stream_file1,
    tcp_stream_file2,
    COUNT(*) as packet_count
FROM kase_133_tcp_stream_extra
GROUP BY tcp_stream_file1, tcp_stream_file2
ORDER BY tcp_stream_file2;

-- 预期输出：
-- tcp_stream_file1 | tcp_stream_file2 | packet_count
-- -----------------+------------------+-------------
--                0 |                0 |          ...
--                0 |                1 |          ...
--                0 |                2 |          ...
--              ... |              ... |          ...
--                0 |               15 |          ...
```

---

## 总结

### 何时使用一对多匹配

✅ **使用一对多**：
- 一个长连接被分割成多个短连接
- 不同抓包点导致的 stream 分割
- 需要匹配所有时间重叠的 streams

❌ **使用一对一**（默认）：
- 正常的连接匹配
- 不确定是否需要一对多
- 性能敏感的场景

### 关键命令

```bash
# 一对多匹配
capmaster compare --file1 B.pcap --file2 A.pcap --match-mode one-to-many

# 查看统计信息
# 注意 matched_pairs, unique_matched_1/2, max_matches_per_conn1
```

### 匹配条件

1. IPID 匹配（必要）
2. 时间重叠（必要）
3. 特征评分 ≥ 阈值

### 文档

- **详细设计**: `DESIGN_TIME_OVERLAP_MATCHING.md`
- **Phase 3 实现**: `PHASE3_ONE_TO_MANY_MATCHING.md`
- **完整总结**: `TIME_OVERLAP_AND_ONE_TO_MANY_COMPLETE.md`
- **快速入门**: 本文档

