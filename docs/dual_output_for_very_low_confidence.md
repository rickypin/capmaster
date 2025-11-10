# VERY_LOW 置信度双向输出机制

## 背景

在服务端检测中，当连接落入端口比较逻辑（FALLBACK_PORT_COMPARISON）时，置信度为 VERY_LOW。这种情况通常发生在：

1. ❌ 没有 SYN 包
2. ❌ 端口不在知名/数据库端口列表
3. ❌ 无法利用基数分析（单个孤立连接）

在这种情况下，服务端判断完全依赖于端口号大小比较，准确性很低，可能导致：
- **误判**：将客户端识别为服务端，或反之
- **遗漏**：因为服务端识别错误，导致连接无法正确聚合和匹配

## 问题场景

### 场景描述

```
单个连接：A:50001 <-> B:60001

端口比较逻辑：
- 50001 < 60001
- 判断：A:50001 是服务端（因为端口号更小）

但实际情况可能是：
- B:60001 才是服务端
- A:50001 是客户端的临时端口
```

### 问题

如果判断错误：
- 聚合时会按错误的服务端进行分组
- 可能导致本应匹配的连接无法匹配
- 用户需要手动检查和修正

## 解决方案

### 核心思想

> **对于 VERY_LOW 置信度的连接，同时提供两种可能的服务端判断**

这样可以：
- ✅ 避免因为识别错误导致的遗漏
- ✅ 让用户看到两种可能性，自行判断
- ✅ 提高匹配的召回率（recall）

### 实现机制

#### 条件

只有当以下条件**全部满足**时，才触发双向输出：

1. **置信度为 VERY_LOW**
   - 即连接落入 FALLBACK_PORT_COMPARISON
   - 无法通过其他方法确定服务端

2. **五元组唯一**
   - 该连接是孤立的，没有其他连接可以提供基数信息
   - 无法利用端点基数、端口复用、端口稳定性等特征

#### 输出

对于每个 VERY_LOW 置信度的连接，输出**两个** endpoint pairs：

**Interpretation 1（原始判断）**：
```
Client: A
Server: B:60001
Confidence: VERY_LOW
Method: FALLBACK_PORT_COMPARISON
```

**Interpretation 2（反向判断）**：
```
Client: B
Server: A:50001
Confidence: VERY_LOW
Method: FALLBACK_PORT_COMPARISON_SWAPPED
```

## 实现细节

### 代码修改

**文件**：`capmaster/plugins/match/endpoint_stats.py`

**修改位置**：`_process_match()` 方法

```python
def _process_match(self, match: ConnectionMatch) -> None:
    # ... 原有逻辑 ...
    
    # Track confidence (use the lower of the two)
    confidence = self._min_confidence(info_a.confidence, info_b.confidence)
    self.confidences[pair_key].append(confidence)

    # For VERY_LOW confidence, also add the reversed interpretation
    # This helps avoid missing connections due to incorrect server detection
    if confidence == "VERY_LOW":
        # Create reversed tuples (swap server/client roles)
        tuple_a_reversed = EndpointTuple(
            client_ip=info_a.server_ip,
            server_ip=info_a.client_ip,
            server_port=info_a.client_port,
        )
        tuple_b_reversed = EndpointTuple(
            client_ip=info_b.server_ip,
            server_ip=info_b.client_ip,
            server_port=info_b.client_port,
        )

        # Add reversed pair
        pair_key_reversed = (tuple_a_reversed, tuple_b_reversed)
        self.pair_stats[pair_key_reversed] += 1
        self.confidences[pair_key_reversed].append(confidence)
```

### 逻辑流程

```
1. 检测连接的服务端（使用多层检测）
   ↓
2. 获取置信度
   ↓
3. 如果置信度 == VERY_LOW:
   ├─ 添加原始判断的 endpoint pair
   └─ 添加反向判断的 endpoint pair
   
4. 否则:
   └─ 只添加原始判断的 endpoint pair
```

## 使用示例

### 输入

两个 PCAP 文件，每个包含一个孤立连接：

```
File A: 192.168.1.100:50001 <-> 192.168.1.200:60001
File B: 10.0.1.100:50001 <-> 10.0.2.200:60001
```

### 输出

```bash
python -m capmaster match -i fileA.pcap,fileB.pcap --endpoint-stats
```

```
Endpoint Statistics (Matched Connections Only)
================================================================================

Total unique endpoint pairs: 2
Total matched connections: 1

Endpoint Pairs:
--------------------------------------------------------------------------------

[1] Count: 1 | Confidence: VERY_LOW
    File A: Client 192.168.1.200 → Server 192.168.1.100:50001
    File B: Client 10.0.2.200 → Server 10.0.1.100:50001

[2] Count: 1 | Confidence: VERY_LOW
    File A: Client 192.168.1.100 → Server 192.168.1.200:60001
    File B: Client 10.0.1.100 → Server 10.0.2.200:60001
```

### 解释

- **[1]** 假设 `192.168.1.100:50001` 是服务端（因为端口号更小）
- **[2]** 假设 `192.168.1.200:60001` 是服务端（反向判断）

用户可以根据实际情况选择正确的解释。

## 优势

### 1. 避免遗漏

如果只输出一种判断，可能因为判断错误导致连接无法正确匹配。双向输出确保至少有一种判断是正确的。

### 2. 提高召回率

在不确定的情况下，提供两种可能性，提高了匹配的召回率（recall）。

### 3. 用户友好

用户可以看到两种可能性，根据实际情况（如已知的服务端口、网络拓扑等）自行判断。

### 4. 向后兼容

- 对于高置信度的连接，行为不变
- 只有 VERY_LOW 置信度的连接才会触发双向输出
- 不影响现有功能和 API

## 局限性

### 1. 输出数量增加

对于 VERY_LOW 置信度的连接，输出的 endpoint pairs 数量会翻倍。

**影响**：
- 输出更长
- 需要用户手动筛选

**缓解**：
- 只有 VERY_LOW 置信度才触发
- 通常这类连接数量较少

### 2. 不适用于批量分析

如果有大量 VERY_LOW 置信度的连接，双向输出可能导致输出过于冗长。

**建议**：
- 优先改进 PCAP 质量（包含 SYN 包）
- 使用标准端口
- 增加连接数量以利用基数分析

### 3. 仍需人工判断

双向输出只是提供了两种可能性，最终仍需用户根据实际情况判断。

## 测试

### 测试用例 1：VERY_LOW 置信度

```python
# 单个孤立连接，无 SYN 包，非标准端口
conn1 = TcpConnection(
    client_ip="192.168.1.100",
    client_port=50001,
    server_ip="192.168.1.200",
    server_port=60001,
    syn_options="",  # No SYN
)

# 预期：输出 2 个 endpoint pairs（双向）
```

### 测试用例 2：MEDIUM/HIGH 置信度

```python
# 多个连接，触发端口稳定性检测
conn1 = TcpConnection(client_port=50001, server_port=60001)
conn2 = TcpConnection(client_port=50002, server_port=60001)
conn3 = TcpConnection(client_port=50003, server_port=60001)

# 预期：输出 1 个 endpoint pair（不触发双向输出）
```

### 运行测试

```bash
python test_dual_output.py
```

**预期输出**：
```
================================================================================
Testing Dual Output for VERY_LOW Confidence Connections
================================================================================
✅ Test passed! Dual output is working correctly.

================================================================================
Testing NO Dual Output for HIGH Confidence Connections
================================================================================
✅ Test passed! No dual output for high confidence connections.

================================================================================
All tests passed! ✅
================================================================================
```

## 总结

双向输出机制是对 VERY_LOW 置信度场景的重要改进：

### 核心特性

✅ **自动触发**：置信度为 VERY_LOW 时自动启用
✅ **双向输出**：同时提供原始和反向两种判断
✅ **避免遗漏**：确保至少有一种判断是正确的
✅ **向后兼容**：不影响高置信度连接的行为

### 适用场景

- 单个孤立连接
- 无 SYN 包
- 非标准端口
- 无法利用基数分析

### 使用建议

1. **优先改进数据质量**
   - 尽量包含 SYN 包
   - 使用标准端口
   - 增加连接数量

2. **人工判断**
   - 根据实际情况选择正确的解释
   - 参考已知的服务端口、网络拓扑等信息

3. **批量处理**
   - 如果有大量 VERY_LOW 连接，考虑过滤或分组处理
   - 使用脚本自动筛选

这个机制显著提高了在不确定场景下的匹配召回率，避免了因服务端识别错误导致的连接遗漏。

