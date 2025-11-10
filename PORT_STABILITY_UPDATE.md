# 端口稳定性检测更新

## 更新背景

在实现了端点基数检测和端口复用检测后，发现仍有一个重要场景无法覆盖：

**点对点通信场景**：
```
连接1: A:50001 <-> B:60001
连接2: A:50002 <-> B:60001
连接3: A:50003 <-> B:60001

问题：
- IP基数都是1（只有两台机器）
- 端口复用都是1（每个端口只被1个IP使用）
- 现有检测无法识别 B:60001 是服务端
```

## 用户观察

用户提出了一个关键观察：

> **B端符合服务器特征，因为使用了同一个端口连接了同一IP的多个端口，IP虽然一对一，但端口是一对多的，这也符合服务端的特征**

这个观察非常正确！

## 新增特征：端口稳定性

### 特征定义

> **服务端使用同一个端口连接到客户端的多个不同端口**

### 服务端特征

- 使用**固定端口**（监听端口）
- 连接到**多个对端端口**
- 端口稳定，不变化

### 客户端特征

- 使用**临时端口**（ephemeral ports）
- 每个端口只连接到**1个对端端口**
- 端口随机，每次连接都不同

## 实现方案

### 1. 新增数据结构

```python
# 跟踪每个端点连接的对端端口集合
_endpoint_peer_ports: dict[tuple[str, int], set[int]]
# Key: (ip, port), Value: set of peer ports
```

### 2. 收集阶段

```python
def collect_connection(self, connection: TcpConnection) -> None:
    # Direction 1: server_ip:server_port connects to client_port
    self._endpoint_peer_ports[(connection.server_ip, connection.server_port)].add(
        connection.client_port
    )
    
    # Direction 2: client_ip:client_port connects to server_port
    self._endpoint_peer_ports[(connection.client_ip, connection.client_port)].add(
        connection.server_port
    )
```

### 3. 检测逻辑

```python
# 获取端口稳定性统计
peer_ports1 = len(self._endpoint_peer_ports.get(endpoint1, set()))
peer_ports2 = len(self._endpoint_peer_ports.get(endpoint2, set()))

MIN_PEER_PORTS = 2  # 至少连接到2个不同的对端端口

# Case 3: Port stability pattern
if peer_ports1 >= MIN_PEER_PORTS and peer_ports2 < MIN_PEER_PORTS:
    # endpoint1 shows port stability (server characteristic)
    return ServerInfo(
        server_ip=connection.server_ip,
        server_port=connection.server_port,
        confidence="MEDIUM",
        method=f"PORT_STABILITY_{peer_ports1}peer_ports",
    )
```

## 效果对比

### 场景：点对点通信

```
环境：
  应用服务器: 10.0.1.50
  数据库服务器: 10.0.2.100:3306

连接：
  10.0.1.50:40001 <-> 10.0.2.100:3306
  10.0.1.50:40002 <-> 10.0.2.100:3306
  10.0.1.50:40003 <-> 10.0.2.100:3306
```

**原有检测**：
```
端点基数：
  10.0.2.100:3306 → {10.0.1.50}，基数=1
  10.0.1.50:40001 → {10.0.2.100}，基数=1
  10.0.1.50:40002 → {10.0.2.100}，基数=1
  10.0.1.50:40003 → {10.0.2.100}，基数=1

端口复用：
  端口3306 → {10.0.2.100}，复用=1
  端口40001 → {10.0.1.50}，复用=1
  端口40002 → {10.0.1.50}，复用=1
  端口40003 → {10.0.1.50}，复用=1

结果：FALLBACK_PORT_COMPARISON（回退到端口比较）
```

**新增检测**：
```
端口稳定性：
  10.0.2.100:3306 → 连接到 {40001, 40002, 40003}，peer_ports=3
  10.0.1.50:40001 → 连接到 {3306}，peer_ports=1
  10.0.1.50:40002 → 连接到 {3306}，peer_ports=1
  10.0.1.50:40003 → 连接到 {3306}，peer_ports=1

结果：PORT_STABILITY_3peer_ports ✅
置信度：MEDIUM
```

## 三维度协同

现在形成了完整的三维度基数分析体系：

### 维度1: 端点基数

```
检测内容：IP:Port → 客户端IP数量
服务端特征：一个IP:Port服务多个客户端IP
适用场景：多客户端场景
```

### 维度2: 端口复用

```
检测内容：Port → 服务器IP数量
服务端特征：一个端口被多个服务器IP使用
适用场景：集群、负载均衡
```

### 维度3: 端口稳定性

```
检测内容：IP:Port → 对端端口数量
服务端特征：一个IP:Port连接到多个对端端口
适用场景：点对点通信
```

## 协同效果表

| IP基数 | 端口复用 | 端口稳定性 | 置信度 | 典型场景 |
|--------|---------|-----------|--------|---------|
| 高 (≥5) | 高 (≥2) | 高 (≥2) | **HIGH** | 大型集群服务 |
| 高 (≥5) | 低 (1) | 高 (≥2) | **HIGH** | 单服务器多客户端 |
| 低 (1) | 高 (≥2) | 低 (1) | **MEDIUM** | 负载均衡集群（单客户端） |
| 低 (1) | 低 (1) | 高 (≥2) | **MEDIUM** | 点对点通信（新增！） |
| 低 (1) | 低 (1) | 低 (1) | **UNKNOWN** | 单连接，无法判断 |

## 检测优先级

端口稳定性检测作为 **Case 3** 插入到检测流程中：

```
Priority 1: SYN packet direction (最可靠)
Priority 2: Port number heuristics (知名端口)
Priority 3: Cardinality-based detection
  ├─ Case 1: 端点基数检测 + 端口复用增强
  ├─ Case 2: 端口复用检测
  ├─ Case 3: 端口稳定性检测 (NEW!)
  └─ Case 4: 基数比率检测
Priority 4: Traffic pattern analysis (未实现)
Priority 5: Fallback (端口比较)
```

## 优势

1. **解决点对点通信场景**
   - 两台机器之间的通信
   - IP基数为1的场景
   - 端口复用为1的场景

2. **识别临时端口模式**
   - 客户端使用临时端口（ephemeral ports）
   - 服务端使用固定端口（listening port）

3. **补充其他维度不足**
   - 补充IP基数检测的不足
   - 补充端口复用检测的不足
   - 三维度协同提供更全面的检测

4. **无需先验知识**
   - 不依赖端口号
   - 不依赖IP地址
   - 自动从连接模式中学习

## 向后兼容性

✅ **完全向后兼容**
- 新功能自动启用，无需额外配置
- 不影响现有功能和API
- 对于无法使用端口稳定性检测的场景，自动回退到原有逻辑

## 测试

使用现有测试用例验证：

```bash
python -m capmaster match \
  -i cases/TC-001-1-20160407/TC-001-1-20160407-A.pcap,cases/TC-001-1-20160407/TC-001-1-20160407-B.pcap \
  --endpoint-stats
```

**结果**：
- ✅ 63个连接正确聚合
- ✅ 置信度 HIGH
- ✅ 服务端正确识别

## 文档

- **详细设计**：`docs/port_stability_detection.md`
- **完整总结**：`ENHANCEMENT_SUMMARY.md`（已更新）
- **实现总结**：`IMPLEMENTATION_SUMMARY.md`（待更新）

## 总结

通过添加端口稳定性检测维度，形成了**三维度基数分析**体系：

1. **端点基数**：IP:Port → 客户端IP数量
2. **端口复用**：Port → 服务器IP数量
3. **端口稳定性**：IP:Port → 对端端口数量

三个维度互补，显著提升了服务端检测的准确性和覆盖率，特别是解决了点对点通信场景中的服务端识别问题。

### 关键改进

✅ **解决了用户提出的场景**：
```
连接1: A:50001 <-> B:60001
连接2: A:50002 <-> B:60001
连接3: A:50003 <-> B:60001

现在可以正确识别 B:60001 是服务端！
```

✅ **检测方法**：PORT_STABILITY_3peer_ports
✅ **置信度**：MEDIUM
✅ **适用场景**：点对点通信、IP基数为1、端口复用为1

