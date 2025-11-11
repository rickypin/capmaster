# 端口复用检测 (Port Reuse Detection)

## 概述

端口复用检测是基数分析的第二个维度，利用服务端的另一个重要特征：

> **多个服务器IP使用相同的端口向客户端提供服务**

这是服务端架构的一个普遍模式，特别是在以下场景中：
- 负载均衡集群（多个后端服务器使用相同端口）
- 分布式系统（多个节点提供相同服务）
- 高可用架构（主备服务器使用相同端口）

## 核心原理

### 服务端端口复用模式

在典型的服务端架构中：

```
客户端视角：
  Client A → Server1:8080
  Client A → Server2:8080
  Client A → Server3:8080
  
端口8080被3个不同的服务器IP使用 → 8080是服务端口
```

### 客户端端口随机模式

相比之下，客户端端口通常是随机分配的：

```
服务端视角：
  Server → Client1:50001
  Server → Client2:50002
  Server → Client3:50003
  
每个客户端使用不同的端口 → 这些是客户端口
```

## 检测逻辑

### 数据结构

```python
# 跟踪每个端口被多少个不同的IP用作服务端口
_port_server_ips: dict[int, set[str]]
# Key: port, Value: set of IPs using this port as server

# 跟踪每个端口被多少个不同的IP用作客户端口
_port_client_ips: dict[int, set[str]]
# Key: port, Value: set of IPs using this port as client
```

### 检测规则

```python
MIN_PORT_REUSE = 2  # 至少2个不同的服务器IP使用同一端口

# 规则1: 端口复用增强基数检测
if cardinality1 >= 2 and port1_server_ips >= 2:
    # 端点1既有高基数，又显示端口复用模式
    confidence = "HIGH"  # 提升置信度
    method = "CARDINALITY_PORT_REUSE"

# 规则2: 纯端口复用检测（即使基数不高）
if port1_server_ips >= 2 and port2_server_ips < 2:
    # 端口1显示服务端复用模式
    confidence = "MEDIUM"
    method = "PORT_REUSE"
```

## 应用场景

### 场景1: 负载均衡集群

```
环境：
  3个Web服务器: 10.0.1.1:80, 10.0.1.2:80, 10.0.1.3:80
  客户端: 192.168.1.100

连接：
  192.168.1.100:50001 <-> 10.0.1.1:80
  192.168.1.100:50002 <-> 10.0.1.2:80
  192.168.1.100:50003 <-> 10.0.1.3:80

端口复用分析：
  端口80: 被3个不同的服务器IP使用 (10.0.1.1, 10.0.1.2, 10.0.1.3)
  端口50001/50002/50003: 每个只被1个IP使用

检测结果：
  ✅ 端口80是服务端口 (PORT_REUSE: 3 servers)
  ✅ 置信度: MEDIUM → HIGH (如果基数也高)
```

### 场景2: 数据库集群

```
环境：
  主库: 10.0.2.10:3306
  从库1: 10.0.2.11:3306
  从库2: 10.0.2.12:3306
  应用服务器: 10.0.1.50

连接：
  10.0.1.50:40001 <-> 10.0.2.10:3306  (写操作)
  10.0.1.50:40002 <-> 10.0.2.11:3306  (读操作)
  10.0.1.50:40003 <-> 10.0.2.12:3306  (读操作)

端口复用分析：
  端口3306: 被3个不同的数据库服务器使用
  端口40001/40002/40003: 每个只被应用服务器使用

检测结果：
  ✅ 端口3306是服务端口 (PORT_REUSE: 3 servers)
  ✅ 即使3306不在知名端口列表中，也能准确识别
```

### 场景3: 微服务架构

```
环境：
  API服务实例1: 10.0.3.1:8080
  API服务实例2: 10.0.3.2:8080
  API服务实例3: 10.0.3.3:8080
  API服务实例4: 10.0.3.4:8080
  客户端: 172.16.1.100

连接：
  172.16.1.100:60001 <-> 10.0.3.1:8080
  172.16.1.100:60002 <-> 10.0.3.2:8080
  172.16.1.100:60003 <-> 10.0.3.3:8080
  172.16.1.100:60004 <-> 10.0.3.4:8080

端口复用分析：
  端口8080: 被4个不同的API服务实例使用
  端口60001-60004: 每个只被客户端使用

检测结果：
  ✅ 端口8080是服务端口 (PORT_REUSE: 4 servers)
  ✅ 置信度: HIGH (端口复用 + 高基数)
```

## 与基数检测的协同

端口复用检测和基数检测是互补的两个维度：

### 维度1: 端点基数（IP:Port → 客户端IP数量）

```
服务端特征: 一个 IP:Port 服务多个客户端IP
示例: 10.0.1.1:80 → {Client1, Client2, Client3, ...}
```

### 维度2: 端口复用（Port → 服务器IP数量）

```
服务端特征: 一个 Port 被多个服务器IP使用
示例: Port 80 → {Server1, Server2, Server3, ...}
```

### 协同效果

| 端点基数 | 端口复用 | 置信度 | 说明 |
|---------|---------|--------|------|
| 高 (≥5) | 高 (≥2) | **HIGH** | 双重确认，最可靠 |
| 中 (2-4) | 高 (≥2) | **HIGH** | 端口复用提升置信度 |
| 低 (1) | 高 (≥2) | **MEDIUM** | 仅端口复用可用 |
| 高 (≥5) | 低 (1) | **HIGH** | 仅基数可用 |
| 中 (2-4) | 低 (1) | **MEDIUM** | 仅基数可用 |
| 低 (1) | 低 (1) | **UNKNOWN** | 无法判断 |

## 实现细节

### 收集阶段

在 `collect_connection()` 中同时跟踪两个方向：

```python
# 方向1: server_ip:server_port → client_ip
self._port_server_ips[connection.server_port].add(connection.server_ip)
self._port_client_ips[connection.server_port].add(connection.client_ip)

# 方向2: client_ip:client_port → server_ip
self._port_server_ips[connection.client_port].add(connection.client_ip)
self._port_client_ips[connection.client_port].add(connection.server_ip)
```

### 检测阶段

在 `_detect_by_cardinality()` 中使用端口复用信息：

```python
# 获取端口复用统计
port1_server_ips = len(self._port_server_ips.get(connection.server_port, set()))
port2_server_ips = len(self._port_server_ips.get(connection.client_port, set()))

# Case 1: 基数检测 + 端口复用增强
if cardinality1 >= 2 and cardinality2 < 2:
    confidence = "HIGH" if cardinality1 >= 5 else "MEDIUM"
    
    # 如果端口也显示复用模式，提升置信度
    if port1_server_ips >= 2 and port2_server_ips < 2:
        confidence = "HIGH"
        method = f"CARDINALITY_PORT_REUSE_{cardinality1}v{cardinality2}_P{port1_server_ips}"

# Case 2: 纯端口复用检测
if port1_server_ips >= 2 and port2_server_ips < 2:
    return ServerInfo(
        server_ip=connection.server_ip,
        server_port=connection.server_port,
        confidence="MEDIUM",
        method=f"PORT_REUSE_{port1_server_ips}servers_on_port{connection.server_port}",
    )
```

## 优势

1. **识别集群服务**
   - 自动识别负载均衡后端
   - 识别分布式服务节点
   - 识别高可用集群

2. **提升检测准确性**
   - 为基数检测提供额外验证
   - 在基数不足时提供替代方案
   - 双重特征确认提升置信度

3. **适用于复杂架构**
   - 微服务架构
   - 容器化部署（多个容器使用相同端口）
   - 云原生应用

4. **无需先验知识**
   - 不依赖端口号
   - 不依赖IP地址范围
   - 自动从数据中学习

## 局限性

1. **需要多服务器场景**
   - 单服务器部署无法利用此特征
   - 至少需要2个服务器IP使用相同端口

2. **可能的误判场景**
   - NAT环境中，多个内部客户端可能显示为不同IP
   - 端口转发可能导致混淆

3. **内存开销**
   - 需要额外存储端口到IP的映射
   - 对于大规模数据集，内存开销增加

## 测试建议

### 测试场景1: 负载均衡

```bash
# 准备测试数据：客户端连接到3个后端服务器
# 预期：端口复用检测识别服务端口
python -m capmaster match -i client.pcap,server1.pcap --endpoint-stats
```

### 测试场景2: 数据库集群

```bash
# 准备测试数据：应用连接到主从数据库
# 预期：端口3306被识别为服务端口（即使不在知名端口列表）
python -m capmaster match -i app.pcap,db_master.pcap --endpoint-stats
```

### 测试场景3: 微服务

```bash
# 准备测试数据：客户端连接到多个微服务实例
# 预期：端口8080被识别为服务端口，置信度HIGH
python -m capmaster match -i client.pcap,service1.pcap --endpoint-stats
```

## 调试

如果需要查看端口复用统计，可以在检测方法中添加调试输出：

```python
# 在 _detect_by_cardinality() 中
print(f"Port {connection.server_port}: {port1_server_ips} server IPs")
print(f"Port {connection.client_port}: {port2_server_ips} server IPs")
```

## 总结

端口复用检测是基数分析的重要补充，通过识别"多个服务器IP使用相同端口"这一模式，显著提升了服务端检测的准确性，特别是在以下场景：

- ✅ 负载均衡集群
- ✅ 分布式系统
- ✅ 高可用架构
- ✅ 微服务部署
- ✅ 容器化应用

结合端点基数检测，形成了双维度的服务端识别体系，使检测更加智能和可靠。

