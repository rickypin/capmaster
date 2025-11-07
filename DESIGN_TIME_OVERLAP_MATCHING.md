# 时间重叠匹配设计方案

## 问题描述

### 当前问题

在实际案例中发现：
- **File A**: 有 16 个 TCP stream (0-15)，都是相同的 5 元组 `8.42.96.45:35101 <-> 8.67.2.125:26302`
- **File B**: 有 1 个 TCP stream (0)，也是相同的 5 元组
- **实际情况**: A 的 stream 1-15 中的 IPID 在 B 的 stream 0 中也出现过
- **预期行为**: 
  - A 的 stream 0 应该匹配 B 的 stream 0 的一部分数据包
  - A 的 stream 1 应该匹配 B 的 stream 0 的另一部分数据包
  - A 的其他 stream 也应该分别匹配 B 的 stream 0 的不同时间段的数据包

### 当前逻辑的局限

1. **缺少时间范围信息**
   - `TcpConnection` 只有 `syn_timestamp`（SYN 包时间或首包时间）
   - 没有 `first_packet_time` 和 `last_packet_time`
   - 无法判断两个 stream 是否在时间上有重叠

2. **一对一匹配限制**
   - `ConnectionMatcher` 使用贪婪一对一匹配算法
   - 每个连接只能匹配一次（line 226-229）
   - B 的 stream 0 只能匹配 A 的一个 stream（得分最高的）
   - 其他 A 的 stream 即使 IPID 相同也无法匹配

3. **缺少时间重叠检查**
   - `ConnectionScorer` 不检查时间重叠
   - 只基于特征（IPID、ISN、Payload 等）评分

## 改进方案

### 方案 1: 添加时间范围字段（推荐）

#### 1.1 修改 `TcpConnection` 数据结构

```python
@dataclass
class TcpConnection:
    # ... 现有字段 ...
    
    # 新增字段
    first_packet_time: float
    """Stream 中最早的数据包时间戳（Unix timestamp）"""
    
    last_packet_time: float
    """Stream 中最晚的数据包时间戳（Unix timestamp）"""
    
    packet_count: int
    """Stream 中的数据包总数"""
```

**说明**:
- `first_packet_time`: 不一定是 SYN 包，可能是任意报文，只要是时间最早的
- `last_packet_time`: 不一定是 FIN/RST 包，可能是任意报文，只要是时间最晚的
- `packet_count`: 用于辅助判断 stream 的规模

#### 1.2 修改 `ConnectionBuilder._build_connection()`

```python
def _build_connection(self, stream_id: int, packets: list[TcpPacket]) -> TcpConnection | None:
    if not packets:
        return None
    
    # Sort packets by frame number
    packets = sorted(packets, key=lambda p: p.frame_number)
    
    # 计算时间范围
    timestamps = [p.timestamp for p in packets if p.timestamp is not None]
    if timestamps:
        first_packet_time = min(timestamps)
        last_packet_time = max(timestamps)
    else:
        # Fallback: 使用 syn_timestamp
        first_packet_time = packets[0].timestamp or 0.0
        last_packet_time = packets[-1].timestamp or 0.0
    
    packet_count = len(packets)
    
    # ... 现有逻辑 ...
    
    return TcpConnection(
        # ... 现有字段 ...
        first_packet_time=first_packet_time,
        last_packet_time=last_packet_time,
        packet_count=packet_count,
    )
```

#### 1.3 修改 `ConnectionScorer` 添加时间重叠检查

```python
class ConnectionScorer:
    # ... 现有权重 ...
    
    def score(self, conn1: TcpConnection, conn2: TcpConnection) -> MatchScore:
        """Score connection similarity."""
        
        # Step 1: Check IPID requirement (必要条件)
        ipid_match = self._check_ipid(conn1, conn2)
        if not ipid_match:
            return MatchScore(
                normalized_score=0.0,
                raw_score=0.0,
                available_weight=0.0,
                ipid_match=False,
                evidence="no-ipid",
            )
        
        # Step 2: Check time overlap (新增)
        time_overlap = self._check_time_overlap(conn1, conn2)
        if not time_overlap:
            return MatchScore(
                normalized_score=0.0,
                raw_score=0.0,
                available_weight=0.0,
                ipid_match=True,
                evidence="no-time-overlap",
            )
        
        # Step 3: Score other features
        # ... 现有评分逻辑 ...
    
    def _check_time_overlap(self, conn1: TcpConnection, conn2: TcpConnection) -> bool:
        """
        Check if two connections have time overlap.
        
        Time overlap exists if:
        [conn1.first, conn1.last] ∩ [conn2.first, conn2.last] ≠ ∅
        
        Args:
            conn1: First connection
            conn2: Second connection
        
        Returns:
            True if time ranges overlap, False otherwise
        """
        # Check if ranges overlap
        # No overlap if: conn1 ends before conn2 starts OR conn2 ends before conn1 starts
        no_overlap = (
            conn1.last_packet_time < conn2.first_packet_time or
            conn2.last_packet_time < conn1.first_packet_time
        )
        
        return not no_overlap
```

#### 1.4 修改 `ConnectionMatcher` 支持一对多匹配（可选）

**选项 A: 保持一对一匹配，但添加时间重叠过滤**
```python
def _match_bucket(self, bucket1: list[TcpConnection], bucket2: list[TcpConnection]) -> list[ConnectionMatch]:
    # ... 现有逻辑 ...
    
    for i, conn1 in enumerate(bucket1):
        for j, conn2 in enumerate(bucket2):
            score = self.scorer.score(conn1, conn2)
            
            # 时间重叠检查已经在 scorer 中完成
            if score.is_valid_match(self.score_threshold):
                scored_pairs.append((score.normalized_score, i, j, conn1, conn2, score))
    
    # ... 现有贪婪匹配逻辑 ...
```

**选项 B: 支持一对多匹配（更复杂，需要重新设计）**
```python
def _match_bucket_one_to_many(
    self, 
    bucket1: list[TcpConnection], 
    bucket2: list[TcpConnection]
) -> list[ConnectionMatch]:
    """
    Allow one-to-many matching for time-overlapping streams.
    
    Use case:
    - B has one long stream [0, 1000]
    - A has multiple short streams [0, 100], [100, 200], [200, 300]
    - All have same 5-tuple and IPID
    - Each A stream should match B stream
    """
    matches = []
    
    for conn1 in bucket1:
        for conn2 in bucket2:
            score = self.scorer.score(conn1, conn2)
            
            if score.is_valid_match(self.score_threshold):
                matches.append(ConnectionMatch(conn1, conn2, score))
    
    return matches
```

### 方案 2: 方向检查（已废弃）

**注意：五元组一致时，方向无关。不需要检查方向。**

当五元组（src_ip, src_port, dst_ip, dst_port, protocol）一致时：
- `A:35101 → B:26302`
- `B:26302 → A:35101`

这两个方向描述的是**同一个 TCP 连接**，只是观察视角不同（抓包点不同）。

因此：
- ❌ **不需要**检查方向是否一致
- ✅ **只需要**检查五元组是否一致（已经在连接提取时完成）

## 实现步骤

### Phase 1: 添加时间范围字段 ✅ 已完成
1. ✅ 修改 `TcpConnection` 添加 `first_packet_time`, `last_packet_time`, `packet_count`
2. ✅ 修改 `ConnectionBuilder._build_connection()` 计算时间范围
3. ✅ 更新相关测试

### Phase 2: 添加时间重叠检查 ✅ 已完成
1. ✅ 在 `ConnectionScorer` 添加 `_check_time_overlap()` 方法
2. ✅ 在 `score()` 方法中添加时间重叠检查
3. ✅ 更新相关测试

### Phase 3: 支持一对多匹配（可选，需要讨论）
1. ⚠️ 评估是否需要一对多匹配
2. ⚠️ 如果需要，设计新的匹配算法
3. ⚠️ 更新 `ConnectionMatcher`
4. ⚠️ 更新 compare 插件的逻辑

## 测试案例

### 测试 1: 时间重叠检查
```python
# Overlap: [0, 100] ∩ [50, 150] = [50, 100] ✅
conn1 = TcpConnection(..., first_packet_time=0, last_packet_time=100)
conn2 = TcpConnection(..., first_packet_time=50, last_packet_time=150)
assert scorer._check_time_overlap(conn1, conn2) == True

# No overlap: [0, 100] ∩ [200, 300] = ∅ ❌
conn1 = TcpConnection(..., first_packet_time=0, last_packet_time=100)
conn2 = TcpConnection(..., first_packet_time=200, last_packet_time=300)
assert scorer._check_time_overlap(conn1, conn2) == False
```

### 测试 2: 实际案例
```
File B Stream 0: [0, 1000], IPID 61507
File A Stream 0: [0, 100], IPID 61507 → ✅ Match (time overlap)
File A Stream 1: [100, 200], IPID 61507 → ✅ Match (time overlap)
File A Stream 2: [200, 300], IPID 61507 → ✅ Match (time overlap)
File A Stream 3: [2000, 3000], IPID 61507 → ❌ No match (no time overlap)
```

## 兼容性考虑

1. **向后兼容**: 新增字段有默认值，不影响现有代码
2. **性能影响**: 时间重叠检查是 O(1) 操作，性能影响可忽略
3. **数据库**: 如果需要持久化，需要更新数据库 schema

## 问题和讨论

1. **是否需要一对多匹配？**
   - 优点: 更准确地反映实际情况
   - 缺点: 增加复杂度，可能产生大量匹配结果
   - 建议: 先实现时间重叠检查，观察效果后再决定

2. **时间重叠的容忍度？**
   - 是否需要允许一定的时间误差（如 ±1ms）？
   - 建议: 先使用严格的时间重叠检查，根据实际情况调整

3. **方向检查的优先级？**
   - 应该在 IPID 检查之后、时间重叠检查之前
   - 还是在时间重叠检查之后？
   - 建议: IPID → 方向 → 时间重叠 → 其他特征

## 总结

通过添加时间范围字段和时间重叠检查，可以解决当前案例中的问题：
- ✅ 区分相同 5 元组但不同时间段的 stream
- ✅ 避免将不重叠的 stream 错误匹配
- ✅ 为未来的一对多匹配打下基础

