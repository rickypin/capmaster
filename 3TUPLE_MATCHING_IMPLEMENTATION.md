# 3-Tuple (Port Pair) Matching Implementation

## 概述

本文档描述了将 TCP 连接匹配逻辑从 **5 元组匹配** 改为 **3 元组（端口对）匹配** 的实现。

## 修改动机

原有的匹配逻辑要求：
1. ✅ 5 元组匹配（IP1, Port1, IP2, Port2）- 必要条件
2. ✅ IPID 匹配 - 必要条件
3. ✅ 时间重叠 - 必要条件

这种严格的匹配逻辑在 **NAT（网络地址转换）场景** 下会失败，因为：
- NAT 会改变 IP 地址
- 但 TCP 端口通常保持不变
- IPID 在 NAT 转换中通常不变

**新的匹配逻辑**：
1. ✅ **3 元组匹配（Port1, Port2）** - 必要条件（只要求端口对匹配，方向无关）
2. ✅ **IPID 匹配** - 必要条件（保持不变）
3. ❌ **时间重叠** - 已移除（不再是必要条件）

## 实现细节

### 1. 新增 `get_normalized_3tuple()` 方法

**文件**: `capmaster/plugins/match/connection.py`

```python
def get_normalized_3tuple(self) -> tuple[int, int]:
    """
    Get normalized 3-tuple (port pair) for direction-independent matching.

    This method returns only the two TCP ports in canonical order,
    ignoring IP addresses. This is useful for NAT scenarios where
    IP addresses change but ports remain the same.

    Returns:
        Tuple of (port1, port2) where port1 <= port2

    Example:
        Connection: 10.0.0.1:8080 <-> 192.168.1.1:443
        Returns: (443, 8080)

        Connection: 192.168.1.1:443 <-> 10.0.0.1:8080
        Returns: (443, 8080)  # Same result, direction-independent
    """
    port1 = self.client_port
    port2 = self.server_port

    # Sort ports to get canonical order
    if port1 <= port2:
        return (port1, port2)
    else:
        return (port2, port1)
```

**关键特性**：
- 只返回两个端口号，忽略 IP 地址
- 方向无关：`(8080, 443)` 和 `(443, 8080)` 返回相同结果 `(443, 8080)`
- 按升序排列端口号以确保一致性

### 2. 修改 `ConnectionScorer.score()` 方法

**文件**: `capmaster/plugins/match/scorer.py`

**修改前**：
```python
def score(self, conn1: TcpConnection, conn2: TcpConnection, use_payload: bool = True) -> MatchScore:
    # Check 5-tuple requirement (必要条件, direction-independent)
    if not self._check_5tuple(conn1, conn2):
        return MatchScore(..., evidence="no-5tuple")

    # Check IPID requirement (必要条件)
    ipid_match = self._check_ipid(conn1, conn2)
    if not ipid_match:
        return MatchScore(..., evidence="no-ipid")

    # Check time overlap requirement (新增)
    time_overlap = self._check_time_overlap(conn1, conn2)
    if not time_overlap:
        return MatchScore(..., evidence="no-time-overlap")
    
    # ... 特征评分 ...
```

**修改后**：
```python
def score(self, conn1: TcpConnection, conn2: TcpConnection, use_payload: bool = True) -> MatchScore:
    # Check 3-tuple requirement (必要条件, direction-independent)
    # Only requires TCP port pair to match, IP addresses can differ (for NAT scenarios)
    if not self._check_3tuple(conn1, conn2):
        return MatchScore(..., evidence="no-3tuple")

    # Check IPID requirement (必要条件)
    ipid_match = self._check_ipid(conn1, conn2)
    if not ipid_match:
        return MatchScore(..., evidence="no-ipid")
    
    # 时间重叠检查已移除
    
    # ... 特征评分 ...
```

**关键变化**：
1. 将 `_check_5tuple()` 改为 `_check_3tuple()`
2. 移除了 `_check_time_overlap()` 检查
3. 失败证据从 `"no-5tuple"` 改为 `"no-3tuple"`

### 3. 新增 `_check_3tuple()` 方法

**文件**: `capmaster/plugins/match/scorer.py`

```python
def _check_3tuple(self, conn1: TcpConnection, conn2: TcpConnection) -> bool:
    """
    Check if 3-tuple (port pair) matches (direction-independent).

    Two connections match if they have the same TCP port pair,
    regardless of IP addresses or which side is labeled as client/server.
    This is useful for NAT scenarios where IP addresses change but ports remain the same.

    Args:
        conn1: First connection
        conn2: Second connection

    Returns:
        True if normalized port pairs match, False otherwise

    Example:
        conn1: 10.0.0.1:8080 <-> 192.168.1.1:443
        conn2: 172.16.0.1:443 <-> 10.10.10.1:8080
        → Match ✅ (same port pair: 443, 8080)

        conn1: 10.0.0.1:8080 <-> 192.168.1.1:443
        conn2: 172.16.0.1:8080 <-> 10.10.10.1:9000
        → No match ❌ (different port pairs)
    """
    return conn1.get_normalized_3tuple() == conn2.get_normalized_3tuple()
```

## 测试结果

### 单元测试

运行 `test_3tuple_matching.py` 的结果：

```
================================================================================
Testing 3-tuple (Port Pair) Matching Logic
================================================================================

New matching requirements:
  1. ✅ 3-tuple matching (port pair only, direction-independent) - REQUIRED
  2. ✅ IPID matching (flexible) - REQUIRED
  3. ❌ Time overlap - REMOVED (no longer required)

Test 1.1: Same port pair, different IPs (NAT scenario)
  Status: ✅ PASS

Test 1.2: Different port pair
  Status: ✅ PASS

Test 1.3: Same port pair but no shared IPID
  Status: ✅ PASS

Test 2.1: Same port pair, shared IPID, NO time overlap
  Status: ✅ PASS

Test 3.1: Same port pair, reversed direction
  Status: ✅ PASS
```

**所有测试通过！** ✅

### 实际测试用例

**测试用例**: `TC-001-1-20160407`

**修改前**（5 元组 + 时间重叠）：
```
Total connections (file 1): 166
Total connections (file 2): 465
Matched pairs: 0
Match rate (file 1): 0.0%
Match rate (file 2): 0.0%
```

**修改后**（3 元组，无时间重叠要求）：
```
Total connections (file 1): 166
Total connections (file 2): 465
Matched pairs: 63
Match rate (file 1): 38.0%
Match rate (file 2): 13.5%
Average score: 0.71
```

**改进效果**：
- ✅ 匹配对数：0 → 63
- ✅ 匹配率（文件 1）：0% → 38%
- ✅ 匹配率（文件 2）：0% → 13.5%
- ✅ 平均置信度：0.71

### 匹配示例

```
[1] A: 17.17.17.45:39765 <-> 10.30.50.101:6096
    B: 17.17.17.45:39765 <-> 10.0.6.33:6096
    置信度: 0.72 | 证据: isnC isnS dataC dataS shape(1.00) ipid
```

**分析**：
- 客户端 IP：相同（`17.17.17.45`）
- 客户端端口：相同（`39765`）
- 服务器 IP：**不同**（`10.30.50.101` vs `10.0.6.33`）← NAT 转换
- 服务器端口：相同（`6096`）
- 3 元组：`(6096, 39765)` - 匹配 ✅
- IPID：有交集 - 匹配 ✅
- 置信度：0.72（高置信度）

## 适用场景

### ✅ 适合使用 3 元组匹配的场景

1. **NAT 环境**
   - 网络地址转换会改变 IP 地址
   - 端口通常保持不变
   - IPID 在 NAT 中通常不变

2. **负载均衡器**
   - 后端服务器 IP 可能不同
   - 但服务端口相同

3. **代理服务器**
   - 代理会改变源/目标 IP
   - 端口可能保持不变

### ❌ 不适合使用 3 元组匹配的场景

1. **端口复用严重的环境**
   - 同一端口对可能对应多个不同的连接
   - 可能导致误匹配

2. **需要严格 IP 地址匹配的场景**
   - 如果 IP 地址是关键识别信息
   - 应使用原有的 5 元组匹配

## 向后兼容性

- ✅ 保留了原有的 `get_normalized_5tuple()` 方法
- ✅ 保留了原有的 `_check_5tuple()` 方法
- ✅ 新增的 `get_normalized_3tuple()` 和 `_check_3tuple()` 不影响现有代码
- ⚠️ 匹配行为发生变化：更宽松的匹配条件

## 总结

### 核心变化

1. **必要条件 1**：5 元组匹配 → **3 元组（端口对）匹配**
2. **必要条件 2**：IPID 匹配 → **保持不变**
3. **必要条件 3**：时间重叠 → **已移除**

### 优势

- ✅ 支持 NAT 场景
- ✅ 更灵活的匹配条件
- ✅ 提高了匹配率（TC-001 从 0% 提升到 38%）
- ✅ 保持了 IPID 验证以避免误匹配

### 注意事项

- ⚠️ 端口对相同但实际是不同连接的情况可能被误匹配
- ⚠️ 需要依赖 IPID 和其他特征来区分真正的匹配
- ⚠️ 移除时间重叠检查可能导致时间上不相关的连接被匹配

## 相关文件

- `capmaster/plugins/match/connection.py` - 新增 `get_normalized_3tuple()` 方法
- `capmaster/plugins/match/scorer.py` - 修改匹配逻辑，新增 `_check_3tuple()` 方法
- `test_3tuple_matching.py` - 单元测试脚本

