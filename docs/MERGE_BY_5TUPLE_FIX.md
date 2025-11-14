# Fix for --merge-by-5tuple with F5/TLS Matching

## 问题描述

当使用 `--merge-by-5tuple` 参数时，F5 和 TLS 匹配模式无法找到任何匹配结果。

### 根本原因

**Stream ID 不匹配问题**：

1. **F5/TLS 匹配器**使用 tshark 提取的原始 `tcp.stream` ID（例如：0, 1, 2, 3...）
2. **FiveTupleConnectionBuilder** 使用合成的 stream ID（通过 hash 5-tuple 生成）：
   ```python
   stream_id = hash(five_tuple) & 0x7FFFFFFF  # 合成的 hash 值
   ```
3. 转换函数 `convert_f5_matches_to_connection_matches()` 和 `convert_tls_matches_to_connection_matches()` 使用 stream_id 查找连接：
   - F5 匹配器找到的匹配对使用原始 stream_id（如 stream_id=5）
   - 但 connections1/connections2 中的连接使用 hash 后的 stream_id（如 stream_id=1234567890）
   - `conn_map.get(stream_id)` 返回 `None`
   - **所有匹配都被丢弃！**

## 解决方案

### 方案 3：在转换函数中使用 5-tuple 而不是 stream_id

修改了以下文件：

#### 1. `capmaster/core/connection/f5_matcher.py`

- 在 `F5ConnectionPair` 中添加了 5-tuple 信息字段：
  - `snat_src_ip`, `snat_src_port`, `snat_dst_ip`, `snat_dst_port`
  - `vip_src_ip`, `vip_src_port`, `vip_dst_ip`, `vip_dst_port`
- 添加了辅助方法：`get_snat_5tuple()`, `get_vip_5tuple()`
- 修改 `_extract_snat_peers()` 和 `_extract_vip_clients()` 提取 5-tuple 信息
- 修改 `_match_connections()` 保存 5-tuple 信息到匹配结果

#### 2. `capmaster/core/connection/tls_matcher.py`

- 在 `TlsConnectionPair` 中添加了 5-tuple 信息字段：
  - `src_ip_1`, `src_port_1`, `dst_ip_1`, `dst_port_1`
  - `src_ip_2`, `src_port_2`, `dst_ip_2`, `dst_port_2`
- 添加了辅助方法：`get_5tuple_1()`, `get_5tuple_2()`
- 修改 `_match_connections()` 保存 5-tuple 信息到匹配结果

#### 3. `capmaster/plugins/match/strategies.py`

- 修改 `convert_f5_matches_to_connection_matches()`：
  - 同时构建 stream_id 和 5-tuple 两种查找映射
  - 优先使用 stream_id 查找（正常模式）
  - 失败时回退到 5-tuple 查找（merge-by-5tuple 模式）
  - 添加调试日志记录匹配统计

- 修改 `convert_tls_matches_to_connection_matches()`：
  - 同样的双重查找策略
  - 添加调试日志

- 添加辅助函数 `_normalize_5tuple()`：
  - 将 5-tuple 标准化为方向无关的形式
  - 与 `TcpConnection.get_normalized_5tuple()` 保持一致

## 匹配逻辑说明

### 正常模式（不使用 --merge-by-5tuple）

```
F5 Matcher → stream_id (原始) → ConnectionMatch
                ↓
         stream_id 查找成功 ✓
```

### Merge-by-5tuple 模式

```
F5 Matcher → stream_id (原始) → stream_id 查找失败 ✗
                ↓
         5-tuple 信息 → 5-tuple 查找成功 ✓
                ↓
         ConnectionMatch
```

## 测试验证

使用你的命令测试：

```bash
capmaster match \
  --file1 /Users/ricky/Downloads/2hops/dbs_1112_2/SNAT.pcap --file1-pcapid 0 \
  --file2 /Users/ricky/Downloads/2hops/dbs_1112_2/VIP.pcap --file2-pcapid 1 \
  --endpoint-stats \
  --merge-by-5tuple
```

预期结果：
- 应该能够找到匹配的连接
- 日志中会显示 5-tuple 匹配统计

## 技术细节

### 5-tuple 标准化

为了支持方向无关的匹配，5-tuple 被标准化为：
- 较小的 endpoint (IP:Port) 总是在前
- 例如：`(10.0.0.1, 8080, 192.168.1.1, 443)` 和 `(192.168.1.1, 443, 10.0.0.1, 8080)` 都会被标准化为同一个形式

### 兼容性

- 完全向后兼容：正常模式（不使用 --merge-by-5tuple）仍然使用 stream_id 查找
- 性能影响：构建额外的 5-tuple 映射，但影响很小（O(n)）
- 不影响其他匹配模式（feature-based, behavioral）

## 相关文件

- `capmaster/core/connection/f5_matcher.py`
- `capmaster/core/connection/tls_matcher.py`
- `capmaster/plugins/match/strategies.py`
- `capmaster/core/connection/models.py` (使用 `get_normalized_5tuple()`)

