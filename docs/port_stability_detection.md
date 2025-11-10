# 端口稳定性检测 (Port Stability Detection)

## 概述

端口稳定性检测是基数分析的第三个维度，用于识别点对点通信场景中的服务端特征：

> **服务端使用同一个端口连接到客户端的多个不同端口**

这个特征在以下场景中特别有效：
- 两台机器之间的点对点通信
- IP基数为1（无法利用IP基数检测）
- 端口复用为1（无法利用端口复用检测）
- 但客户端使用多个临时端口连接到服务端的同一个端口

## 核心原理

### 服务端端口稳定性

在点对点通信中，服务端的典型特征：

```
场景：机器A连接到机器B的服务

连接1: A:50001 <-> B:60001
连接2: A:50002 <-> B:60001
连接3: A:50003 <-> B:60001

分析：
- B:60001 使用同一个端口连接到 A 的多个不同端口（50001, 50002, 50003）
- A 使用多个不同的端口（50001, 50002, 50003）连接到 B 的同一个端口

结论：B:60001 是服务端（端口稳定）
```

### 客户端端口随机性

客户端的典型特征：

```
客户端视角：
- A:50001 只连接到 B:60001（peer_ports = 1）
- A:50002 只连接到 B:60001（peer_ports = 1）
- A:50003 只连接到 B:60001（peer_ports = 1）

服务端视角：
- B:60001 连接到 A:50001, A:50002, A:50003（peer_ports = 3）

端口稳定性：
- 客户端端口：每个端口只连接到1个对端端口（不稳定，临时端口）
- 服务端端口：同一端口连接到多个对端端口（稳定，监听端口）
```

## 检测逻辑

### 数据结构

```python
# 跟踪每个端点连接的对端端口集合
_endpoint_peer_ports: dict[tuple[str, int], set[int]]
# Key: (ip, port), Value: set of peer ports
```

### 收集阶段

```python
def collect_connection(connection):
    # Direction 1: server_ip:server_port connects to client_port
    _endpoint_peer_ports[(connection.server_ip, connection.server_port)].add(
        connection.client_port
    )
    
    # Direction 2: client_ip:client_port connects to server_port
    _endpoint_peer_ports[(connection.client_ip, connection.client_port)].add(
        connection.server_port
    )
```

### 检测规则

```python
MIN_PEER_PORTS = 2  # 至少连接到2个不同的对端端口

# 获取端口稳定性统计
peer_ports1 = len(_endpoint_peer_ports.get(endpoint1, set()))
peer_ports2 = len(_endpoint_peer_ports.get(endpoint2, set()))

# 规则：一端连接多个对端端口，另一端只连接1个对端端口
if peer_ports1 >= 2 and peer_ports2 < 2:
    # endpoint1 显示端口稳定性（服务端特征）
    confidence = "MEDIUM"
    method = f"PORT_STABILITY_{peer_ports1}peer_ports"
```

## 应用场景

### 场景1: 点对点数据库连接

```
环境：
  应用服务器: 10.0.1.50
  数据库服务器: 10.0.2.100:3306

连接：
  10.0.1.50:40001 <-> 10.0.2.100:3306
  10.0.1.50:40002 <-> 10.0.2.100:3306
  10.0.1.50:40003 <-> 10.0.2.100:3306

端口稳定性分析：
  10.0.2.100:3306 → 连接到 {40001, 40002, 40003}，peer_ports = 3
  10.0.1.50:40001 → 连接到 {3306}，peer_ports = 1
  10.0.1.50:40002 → 连接到 {3306}，peer_ports = 1
  10.0.1.50:40003 → 连接到 {3306}，peer_ports = 1

其他维度分析：
  IP基数：都是1（点对点通信）
  端口复用：都是1（每个端口只被1个IP使用）
  
检测结果：
  ✅ 端口稳定性检测识别 10.0.2.100:3306 为服务端
  ✅ 置信度: MEDIUM (PORT_STABILITY_3peer_ports)
```

### 场景2: 点对点API调用

```
环境：
  客户端: 192.168.1.100
  API服务器: 192.168.1.200:8080

连接：
  192.168.1.100:55001 <-> 192.168.1.200:8080
  192.168.1.100:55002 <-> 192.168.1.200:8080
  192.168.1.100:55003 <-> 192.168.1.200:8080
  192.168.1.100:55004 <-> 192.168.1.200:8080
  192.168.1.100:55005 <-> 192.168.1.200:8080

端口稳定性分析：
  192.168.1.200:8080 → 连接到 {55001, 55002, 55003, 55004, 55005}，peer_ports = 5
  192.168.1.100:55001-55005 → 每个都只连接到 {8080}，peer_ports = 1

检测结果：
  ✅ 端口稳定性检测识别 192.168.1.200:8080 为服务端
  ✅ 置信度: MEDIUM (PORT_STABILITY_5peer_ports)
```

### 场景3: 长连接服务

```
环境：
  客户端: 172.16.1.50
  长连接服务: 172.16.2.100:9000

连接：
  172.16.1.50:60001 <-> 172.16.2.100:9000
  172.16.1.50:60002 <-> 172.16.2.100:9000

端口稳定性分析：
  172.16.2.100:9000 → 连接到 {60001, 60002}，peer_ports = 2
  172.16.1.50:60001 → 连接到 {9000}，peer_ports = 1
  172.16.1.50:60002 → 连接到 {9000}，peer_ports = 1

检测结果：
  ✅ 端口稳定性检测识别 172.16.2.100:9000 为服务端
  ✅ 置信度: MEDIUM (PORT_STABILITY_2peer_ports)
```

## 与其他维度的协同

端口稳定性检测是三维度基数分析的重要组成部分：

### 维度1: 端点基数（IP:Port → 客户端IP数量）

```
服务端特征: 一个 IP:Port 服务多个客户端IP
适用场景: 多客户端场景
示例: Web服务器服务多个客户端
```

### 维度2: 端口复用（Port → 服务器IP数量）

```
服务端特征: 一个 Port 被多个服务器IP使用
适用场景: 集群、负载均衡
示例: 3个Web服务器都使用端口80
```

### 维度3: 端口稳定性（IP:Port → 对端端口数量）

```
服务端特征: 一个 IP:Port 连接到多个对端端口
适用场景: 点对点通信
示例: 数据库服务器的3306端口连接到应用服务器的多个临时端口
```

## 三维度协同效果

| IP基数 | 端口复用 | 端口稳定性 | 置信度 | 典型场景 |
|--------|---------|-----------|--------|---------|
| 高 (≥5) | 高 (≥2) | 高 (≥2) | **HIGH** | 大型集群服务 |
| 高 (≥5) | 低 (1) | 高 (≥2) | **HIGH** | 单服务器多客户端 |
| 低 (1) | 高 (≥2) | 低 (1) | **MEDIUM** | 负载均衡集群（单客户端） |
| 低 (1) | 低 (1) | 高 (≥2) | **MEDIUM** | 点对点通信（新增！） |
| 低 (1) | 低 (1) | 低 (1) | **UNKNOWN** | 单连接，无法判断 |

## 优势

1. **解决点对点通信场景**
   - 两台机器之间的通信
   - IP基数为1的场景
   - 端口复用为1的场景

2. **识别临时端口模式**
   - 客户端使用临时端口（ephemeral ports）
   - 服务端使用固定端口（listening port）

3. **提升检测覆盖率**
   - 补充IP基数检测的不足
   - 补充端口复用检测的不足
   - 三维度协同提供更全面的检测

4. **无需先验知识**
   - 不依赖端口号
   - 不依赖IP地址
   - 自动从连接模式中学习

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

## 实现细节

### 数据收集

```python
# 在 collect_connection() 中
def collect_connection(self, connection: TcpConnection) -> None:
    # Direction 1: server_ip:server_port -> client_ip
    self._endpoint_peer_ports[(connection.server_ip, connection.server_port)].add(
        connection.client_port
    )
    
    # Direction 2: client_ip:client_port -> server_ip
    self._endpoint_peer_ports[(connection.client_ip, connection.client_port)].add(
        connection.server_port
    )
```

### 检测逻辑

```python
# 在 _detect_by_cardinality() 中
def _detect_by_cardinality(self, connection: TcpConnection) -> ServerInfo:
    # 获取端口稳定性统计
    endpoint1 = (connection.server_ip, connection.server_port)
    endpoint2 = (connection.client_ip, connection.client_port)
    
    peer_ports1 = len(self._endpoint_peer_ports.get(endpoint1, set()))
    peer_ports2 = len(self._endpoint_peer_ports.get(endpoint2, set()))
    
    MIN_PEER_PORTS = 2
    
    # Case 3: Port stability pattern
    if peer_ports1 >= MIN_PEER_PORTS and peer_ports2 < MIN_PEER_PORTS:
        return ServerInfo(
            server_ip=connection.server_ip,
            server_port=connection.server_port,
            confidence="MEDIUM",
            method=f"PORT_STABILITY_{peer_ports1}peer_ports",
        )
    
    if peer_ports2 >= MIN_PEER_PORTS and peer_ports1 < MIN_PEER_PORTS:
        return ServerInfo(
            server_ip=connection.client_ip,
            server_port=connection.client_port,
            confidence="MEDIUM",
            method=f"PORT_STABILITY_SWAPPED_{peer_ports2}peer_ports",
        )
```

## 局限性

1. **需要多个连接**
   - 至少需要2个连接才能识别端口稳定性
   - 单个连接无法利用此特征

2. **假设客户端使用临时端口**
   - 如果客户端也使用固定端口，可能误判
   - 例如：两个服务之间的双向通信

3. **内存开销**
   - 需要额外存储端点到对端端口的映射
   - 对于大规模数据集，内存开销增加

## 测试建议

### 测试场景: 点对点通信

```bash
# 准备测试数据：客户端使用多个临时端口连接到服务器的固定端口
# 预期：端口稳定性检测识别服务端口

python -m capmaster match -i client.pcap,server.pcap --endpoint-stats
```

预期输出：
```
[1] Count: 3 | Confidence: MEDIUM
    File A: Client 10.0.1.50 → Server 10.0.2.100:3306
    File B: Client 10.0.1.50 → Server 10.0.2.100:3306
    
检测方法: PORT_STABILITY_3peer_ports
```

## 总结

端口稳定性检测是三维度基数分析的重要补充，专门解决点对点通信场景中的服务端识别问题。

### 核心特征

✅ **服务端**：使用同一个端口连接到多个对端端口（端口稳定）
✅ **客户端**：使用多个不同的端口，每个端口只连接到1个对端端口（端口随机）

### 适用场景

- ✅ 两台机器之间的点对点通信
- ✅ IP基数为1的场景
- ✅ 端口复用为1的场景
- ✅ 客户端使用临时端口的场景

### 协同效果

结合端点基数检测和端口复用检测，形成**三维度基数分析**体系，显著提升服务端检测的准确性和覆盖率。

