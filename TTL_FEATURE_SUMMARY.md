# TTL 统计功能实现总结

## 功能概述

为 `match --endpoint-stats` 命令增加了 TTL (Time To Live) 统计功能。现在在 endpoint pair 的条目上会标记出 client 和 server 的 TTL 数值。

## 实现的修改

### 1. 数据提取层 (`capmaster/plugins/match/extractor.py`)

**修改内容：**
- 在 `TcpFieldExtractor.FIELDS` 列表中添加了 `"ip.ttl"` 字段
- 更新了 `_parse_row` 方法以解析 TTL 值（第 17 个字段）

**代码变更：**
```python
FIELDS = [
    # ... 其他字段 ...
    "ip.ttl",  # IP Time To Live
]

# 在 _parse_row 中：
ttl = int(row[17]) if len(row) > 17 and row[17] else 0
```

### 2. 数据模型层 (`capmaster/plugins/match/connection.py`)

**修改内容：**

#### TcpPacket 数据类
- 添加了 `ttl: int = 0` 字段用于存储每个数据包的 TTL 值

#### TcpConnection 数据类
- 添加了 `client_ttl: int = 0` 字段：存储客户端最常见的 TTL 值
- 添加了 `server_ttl: int = 0` 字段：存储服务器最常见的 TTL 值

#### ConnectionBuilder 类
- 添加了 `_compute_ttl_values` 方法：
  - 从数据包列表中提取客户端和服务器的 TTL 值
  - 使用 `Counter` 计算最常见的 TTL 值
  - 返回 `(client_ttl, server_ttl)` 元组

**代码变更：**
```python
def _compute_ttl_values(
    self, packets: list[TcpPacket], client_ip: str, server_ip: str
) -> tuple[int, int]:
    """计算客户端和服务器的最常见 TTL 值"""
    from collections import Counter
    
    client_ttls = []
    server_ttls = []
    
    for packet in packets:
        if packet.ttl > 0:
            if packet.src_ip == client_ip:
                client_ttls.append(packet.ttl)
            elif packet.src_ip == server_ip:
                server_ttls.append(packet.ttl)
    
    client_ttl = Counter(client_ttls).most_common(1)[0][0] if client_ttls else 0
    server_ttl = Counter(server_ttls).most_common(1)[0][0] if server_ttls else 0
    
    return client_ttl, server_ttl
```

### 3. 统计收集层 (`capmaster/plugins/match/endpoint_stats.py`)

**修改内容：**

#### EndpointPairStats 数据类
- 添加了 4 个 TTL 字段：
  - `client_ttl_a: int = 0` - 文件 A 的客户端 TTL
  - `server_ttl_a: int = 0` - 文件 A 的服务器 TTL
  - `client_ttl_b: int = 0` - 文件 B 的客户端 TTL
  - `server_ttl_b: int = 0` - 文件 B 的服务器 TTL
- 更新了 `__str__` 方法以显示 TTL 信息

#### EndpointStatsCollector 类
- 添加了 4 个字典用于跟踪 TTL 值：
  - `client_ttls_a`
  - `server_ttls_a`
  - `client_ttls_b`
  - `server_ttls_b`
- 在 `_process_match` 方法中收集 TTL 值
- 添加了 `_most_common_ttl` 方法计算最常见的 TTL 值
- 更新了 `get_stats` 方法以包含 TTL 统计

**代码变更：**
```python
def _most_common_ttl(self, ttls: list[int]) -> int:
    """获取最常见的 TTL 值"""
    if not ttls:
        return 0
    from collections import Counter
    return Counter(ttls).most_common(1)[0][0]
```

### 4. 输出格式层 (`capmaster/plugins/match/endpoint_stats.py`)

**修改内容：**

#### format_endpoint_stats 函数
- 在每个 endpoint pair 下方添加 TTL 信息显示
- 格式：`TTL: Client=XX, Server=YY`

#### format_endpoint_stats_table 函数
- 在表格中添加了两列：`TTL A (C/S)` 和 `TTL B (C/S)`
- 格式：`64/128` (客户端/服务器)
- 调整了表格宽度从 140 到 180 字符

**输出示例：**
```
[1] Count: 1 | Confidence: HIGH
    File A: Client 192.168.1.100 → Server 10.0.0.1:80 (TCP)
            TTL: Client=64, Server=128
    File B: Client 192.168.1.100 → Server 10.0.0.1:80 (TCP)
            TTL: Client=63, Server=127
```

## 测试验证

创建了 `test_ttl_feature.py` 测试脚本，包含三个测试：

1. **TTL 提取测试**：验证从数据包中正确提取 TTL 值
2. **统计收集测试**：验证 EndpointStatsCollector 正确收集和聚合 TTL 信息
3. **格式化输出测试**：验证输出格式正确显示 TTL 信息

所有测试均通过 ✓

## 使用方法

```bash
# 运行 match 命令并生成 endpoint 统计
python -m capmaster match -i /path/to/pcaps --endpoint-stats

# 输出到文件
python -m capmaster match -i /path/to/pcaps --endpoint-stats --endpoint-stats-output stats.txt
```

## 技术细节

### TTL 值的计算逻辑
1. 从每个数据包中提取 TTL 值
2. 根据源 IP 地址判断是客户端还是服务器的数据包
3. 分别收集客户端和服务器的所有 TTL 值
4. 使用 `Counter.most_common(1)` 获取最常见的 TTL 值
5. 如果没有有效的 TTL 值，则返回 0

### 为什么使用最常见值而不是平均值？
- TTL 值通常是固定的（如 64, 128, 255）
- 在连接过程中 TTL 应该保持不变
- 使用最常见值可以过滤掉异常值
- 更符合网络实际情况

### 反转情况的处理
对于 VERY_LOW confidence 的连接，系统会同时记录正常和反转的 endpoint pair。在反转情况下：
- 客户端和服务器角色互换
- TTL 值也相应互换（client_ttl ↔ server_ttl）

## 兼容性

- 向后兼容：所有 TTL 字段都有默认值 0
- 如果 PCAP 文件中没有 TTL 信息，功能会优雅降级
- 不影响现有的匹配逻辑和其他统计功能

## 文件清单

修改的文件：
1. `capmaster/plugins/match/extractor.py`
2. `capmaster/plugins/match/connection.py`
3. `capmaster/plugins/match/endpoint_stats.py`

新增的文件：
1. `test_ttl_feature.py` - 功能测试脚本
2. `TTL_FEATURE_SUMMARY.md` - 本文档

