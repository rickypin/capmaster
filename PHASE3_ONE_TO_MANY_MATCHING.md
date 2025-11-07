# Phase 3: 一对多匹配功能实现总结

## 实现完成 ✅

Phase 3 已完成！现在支持两种匹配模式：
- **ONE_TO_ONE**: 贪婪一对一匹配（默认，向后兼容）
- **ONE_TO_MANY**: 允许一个连接匹配多个连接（基于时间重叠）

---

## 问题回顾

### 用户的实际案例

```
File A (A_processed.pcap): 16 个 TCP streams
├─ Stream 0: 8.42.96.45:35101 <-> 8.67.2.125:26302, 时间 [T0, T1]
├─ Stream 1: 8.42.96.45:35101 <-> 8.67.2.125:26302, 时间 [T1, T2]
├─ Stream 2: 8.42.96.45:35101 <-> 8.67.2.125:26302, 时间 [T2, T3]
└─ ... (共 16 个 stream，相同 5 元组，不同时间段)

File B (B_processed.pcap): 1 个 TCP stream
└─ Stream 0: 8.42.96.45:35101 <-> 8.67.2.125:26302, 时间 [T0, T15]
              (覆盖整个时间范围，包含所有 A 的 IPID)
```

### 预期行为

- A Stream 0 应该匹配 B Stream 0 的 [T0, T1] 时间段
- A Stream 1 应该匹配 B Stream 0 的 [T1, T2] 时间段
- A Stream 2 应该匹配 B Stream 0 的 [T2, T3] 时间段
- ... 以此类推

### 旧逻辑的问题

- ❌ 贪婪一对一匹配：B Stream 0 只能匹配一个 A Stream
- ❌ 其他 A Stream 即使时间重叠也无法匹配

---

## 实现的改进

### 1. 添加 MatchMode 枚举

```python
class MatchMode(Enum):
    """Matching mode for connection matching."""

    ONE_TO_ONE = "one-to-one"
    """Greedy one-to-one matching (default, backward compatible)"""

    ONE_TO_MANY = "one-to-many"
    """Allow one connection to match multiple connections based on time overlap"""
```

### 2. 修改 ConnectionMatcher 初始化

```python
def __init__(
    self,
    bucket_strategy: BucketStrategy = BucketStrategy.AUTO,
    score_threshold: float = 0.60,
    match_mode: MatchMode = MatchMode.ONE_TO_ONE,  # 新增参数
):
    """
    Initialize the matcher.

    Args:
        bucket_strategy: Strategy for bucketing connections
        score_threshold: Minimum normalized score for a valid match (default: 0.60)
        match_mode: Matching mode (ONE_TO_ONE or ONE_TO_MANY, default: ONE_TO_ONE)
    """
    self.bucket_strategy = bucket_strategy
    self.score_threshold = score_threshold
    self.match_mode = match_mode  # 新增字段
    self.scorer = ConnectionScorer()
```

### 3. 重构 _match_bucket 方法

```python
def _match_bucket(
    self,
    bucket1: list[TcpConnection],
    bucket2: list[TcpConnection],
) -> list[ConnectionMatch]:
    """
    Match connections within a bucket.

    Supports two modes:
    - ONE_TO_ONE: Greedy one-to-one matching (each connection matches at most once)
    - ONE_TO_MANY: Allow one connection to match multiple connections

    Args:
        bucket1: Connections from first PCAP
        bucket2: Connections from second PCAP

    Returns:
        List of matched pairs
    """
    if self.match_mode == MatchMode.ONE_TO_ONE:
        return self._match_bucket_one_to_one(bucket1, bucket2)
    else:
        return self._match_bucket_one_to_many(bucket1, bucket2)
```

### 4. 实现 _match_bucket_one_to_one (原有逻辑)

```python
def _match_bucket_one_to_one(
    self,
    bucket1: list[TcpConnection],
    bucket2: list[TcpConnection],
) -> list[ConnectionMatch]:
    """
    Match connections using greedy one-to-one algorithm.

    Each connection can match at most once.
    """
    matches = []
    used1 = set()
    used2 = set()

    # Score all pairs
    scored_pairs = []
    for i, conn1 in enumerate(bucket1):
        for j, conn2 in enumerate(bucket2):
            score = self.scorer.score(conn1, conn2)
            if score.is_valid_match(self.score_threshold):
                scored_pairs.append((score.normalized_score, i, j, conn1, conn2, score))

    # Sort by normalized score (descending)
    scored_pairs.sort(key=lambda x: x[0], reverse=True)

    # Greedy matching: take highest scoring pairs first
    for _, i, j, conn1, conn2, score in scored_pairs:
        if i not in used1 and j not in used2:
            matches.append(ConnectionMatch(conn1, conn2, score))
            used1.add(i)
            used2.add(j)

    return matches
```

### 5. 实现 _match_bucket_one_to_many (新逻辑)

```python
def _match_bucket_one_to_many(
    self,
    bucket1: list[TcpConnection],
    bucket2: list[TcpConnection],
) -> list[ConnectionMatch]:
    """
    Match connections allowing one-to-many relationships.

    One connection can match multiple connections if they have:
    - Same IPID
    - Time overlap
    - Score above threshold

    This is useful when one PCAP has a long stream that spans multiple
    shorter streams in another PCAP (same 5-tuple, different time ranges).
    """
    matches = []

    # Score all pairs and accept all valid matches
    for conn1 in bucket1:
        for conn2 in bucket2:
            score = self.scorer.score(conn1, conn2)
            if score.is_valid_match(self.score_threshold):
                matches.append(ConnectionMatch(conn1, conn2, score))

    # Sort by normalized score (descending) for consistent ordering
    matches.sort(key=lambda m: m.score.normalized_score, reverse=True)

    return matches
```

**关键区别**：
- ONE_TO_ONE: 使用 `used1` 和 `used2` 集合确保每个连接只匹配一次
- ONE_TO_MANY: 不使用 `used` 集合，接受所有有效匹配

### 6. 更新 get_match_stats 方法

```python
def get_match_stats(...) -> dict:
    """
    Get statistics about the matching operation.

    Note: In ONE_TO_MANY mode, matched_pairs can be greater than
    total_connections_1 or total_connections_2 because one connection
    can match multiple connections.
    """
    # ... 基础统计 ...
    
    stats = {
        # ... 现有字段 ...
        "unique_matched_1": len(matched1),  # 新增：唯一匹配的连接数
        "unique_matched_2": len(matched2),  # 新增：唯一匹配的连接数
        "match_mode": self.match_mode.value,  # 新增：匹配模式
    }

    # Add one-to-many specific stats
    if self.match_mode == MatchMode.ONE_TO_MANY:
        from collections import Counter
        conn1_match_counts = Counter(m.conn1.stream_id for m in matches)
        conn2_match_counts = Counter(m.conn2.stream_id for m in matches)

        stats["max_matches_per_conn1"] = max(conn1_match_counts.values()) if conn1_match_counts else 0
        stats["max_matches_per_conn2"] = max(conn2_match_counts.values()) if conn2_match_counts else 0
        stats["avg_matches_per_conn1"] = sum(conn1_match_counts.values()) / len(conn1_match_counts) if conn1_match_counts else 0
        stats["avg_matches_per_conn2"] = sum(conn2_match_counts.values()) / len(conn2_match_counts) if conn2_match_counts else 0

    return stats
```

### 7. 添加 CLI 选项

#### match 插件

```python
@click.option(
    "--match-mode",
    type=click.Choice(["one-to-one", "one-to-many"], case_sensitive=False),
    default="one-to-one",
    help="Matching mode (one-to-one: each connection matches at most once, "
    "one-to-many: allow one connection to match multiple connections based on time overlap)",
)
```

#### compare 插件

```python
@click.option(
    "--match-mode",
    type=click.Choice(["one-to-one", "one-to-many"], case_sensitive=False),
    default="one-to-one",
    help="Matching mode (one-to-one: each connection matches at most once, "
    "one-to-many: allow one connection to match multiple connections based on time overlap)",
)
```

---

## 测试验证

### 测试 1: 基本一对多匹配

```bash
python test_one_to_many_matching.py
```

**结果**：
- ✅ ONE_TO_ONE: 1 个匹配（B Stream 0 → A Stream 0）
- ✅ ONE_TO_MANY: 3 个匹配（B Stream 0 → A Stream 0, 1, 2）
- ✅ A Stream 3 正确被拒绝（无时间重叠）

### 测试 2: 真实场景（16 个 A streams vs 1 个 B stream）

```bash
python test_real_world_scenario.py
```

**结果**：
- ✅ ONE_TO_ONE: 1 个匹配（B Stream 0 → A Stream 0）
- ✅ ONE_TO_MANY: 16 个匹配（B Stream 0 → A Stream 0-15）
- ✅ 所有 A streams 都被匹配
- ✅ 统计信息正确：
  - `max_matches_per_conn1`: 16
  - `avg_matches_per_conn1`: 16.0

---

## 使用示例

### 使用 match 命令

```bash
# 默认：一对一匹配
capmaster match -i captures/

# 一对多匹配
capmaster match -i captures/ --match-mode one-to-many
```

### 使用 compare 命令

```bash
# 默认：一对一匹配
capmaster compare \
  --file1 B_processed.pcap \
  --file2 A_processed.pcap

# 一对多匹配
capmaster compare \
  --file1 B_processed.pcap \
  --file2 A_processed.pcap \
  --match-mode one-to-many
```

### 实际案例命令

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

---

## 总结

### ✅ 已完成的功能

1. **MatchMode 枚举**：定义两种匹配模式
2. **ConnectionMatcher 改进**：支持两种匹配模式
3. **一对一匹配**：保持原有逻辑，向后兼容
4. **一对多匹配**：允许一个连接匹配多个连接
5. **统计信息增强**：添加一对多特定统计
6. **CLI 选项**：match 和 compare 插件都支持 `--match-mode`
7. **测试验证**：基本测试和真实场景测试都通过

### 🎯 解决的问题

**用户案例**：
- File A: 16 个 streams，相同 5 元组，不同时间段
- File B: 1 个 stream，覆盖整个时间范围

**改进前**：
- ❌ 只能匹配 1 个 A stream

**改进后**：
- ✅ 可以匹配所有 16 个 A streams
- ✅ 基于时间重叠和 IPID 匹配
- ✅ 每个 A stream 匹配 B stream 的对应时间段

### 📊 性能影响

- **ONE_TO_ONE**: 性能不变（原有逻辑）
- **ONE_TO_MANY**: 
  - 时间复杂度：O(n1 * n2)（与 ONE_TO_ONE 相同）
  - 空间复杂度：可能产生更多匹配结果
  - 适用场景：当预期有一对多关系时使用

### 🔄 向后兼容性

- ✅ 默认使用 ONE_TO_ONE 模式
- ✅ 现有脚本和命令无需修改
- ✅ 只有显式指定 `--match-mode one-to-many` 才启用新功能

