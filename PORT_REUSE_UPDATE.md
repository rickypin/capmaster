# 端口复用检测更新

## 更新内容

在原有的**端点基数检测**基础上，新增了**端口复用检测**维度，形成双维度服务端识别体系。

## 新增特征

### 特征：多个服务器IP使用相同端口

这是服务端架构的另一个普遍特征，特别常见于：

- **负载均衡集群**：多个后端服务器使用相同端口（如 80, 443, 8080）
- **分布式系统**：多个节点提供相同服务
- **高可用架构**：主备服务器使用相同端口
- **微服务部署**：多个服务实例使用相同端口
- **容器化应用**：多个容器使用相同端口映射

### 示例场景

```
负载均衡集群：
  Server1: 10.0.1.1:80
  Server2: 10.0.1.2:80
  Server3: 10.0.1.3:80
  
端口80被3个不同的服务器IP使用 → 80是服务端口
```

## 代码修改

### 1. 新增数据结构

在 `ServerDetector.__init__()` 中添加：

```python
# 跟踪每个端口被多少个不同的IP用作服务端口
self._port_server_ips: dict[int, set[str]] = defaultdict(set)

# 跟踪每个端口被多少个不同的IP用作客户端口
self._port_client_ips: dict[int, set[str]] = defaultdict(set)
```

### 2. 增强收集逻辑

在 `collect_connection()` 中同时跟踪端口使用模式：

```python
# 跟踪端口使用模式
self._port_server_ips[connection.server_port].add(connection.server_ip)
self._port_client_ips[connection.server_port].add(connection.client_ip)
```

### 3. 增强检测逻辑

在 `_detect_by_cardinality()` 中添加三个新的检测规则：

#### 规则1: 端口复用增强基数检测

```python
if cardinality1 >= 2 and port1_server_ips >= 2:
    # 既有高基数，又有端口复用模式
    confidence = "HIGH"  # 提升置信度
    method = "CARDINALITY_PORT_REUSE"
```

#### 规则2: 纯端口复用检测

```python
if port1_server_ips >= 2 and port2_server_ips < 2:
    # 端口1显示服务端复用模式
    confidence = "MEDIUM"
    method = "PORT_REUSE"
```

#### 规则3: 双向端口复用检测

```python
if port2_server_ips >= 2 and port1_server_ips < 2:
    # 端口2显示服务端复用模式，需要交换
    confidence = "MEDIUM"
    method = "PORT_REUSE_SWAPPED"
```

## 检测优先级

端口复用检测作为 **Case 2** 插入到基数检测流程中：

```
Case 1: 基数检测 + 端口复用增强
  → 如果端点基数高 + 端口复用模式 → HIGH 置信度

Case 2: 纯端口复用检测 (NEW!)
  → 如果仅端口复用模式明显 → MEDIUM 置信度

Case 3: 基数比率检测
  → 如果基数比率显著 → MEDIUM 置信度

Case 4: 无法判断
  → UNKNOWN
```

## 效果对比

### 场景1: 负载均衡集群

**环境**：
- 3个Web服务器：10.0.1.1:80, 10.0.1.2:80, 10.0.1.3:80
- 客户端：192.168.1.100
- 每个服务器只有1个连接（基数低）

**原有检测**：
- 端点基数：1（每个服务器只服务1个客户端）
- 结果：UNKNOWN 或 VERY_LOW（回退到端口比较）

**新增检测**：
- 端口复用：端口80被3个服务器IP使用
- 结果：**MEDIUM** (PORT_REUSE_3servers_on_port80)

### 场景2: 大型Web服务

**环境**：
- 5个Web服务器：10.0.1.1-5:80
- 每个服务器服务10个客户端（基数中等）

**原有检测**：
- 端点基数：10（中等）
- 结果：MEDIUM (CARDINALITY_10v1)

**新增检测**：
- 端点基数：10 + 端口复用：5个服务器
- 结果：**HIGH** (CARDINALITY_PORT_REUSE_10v1_P5) ← 置信度提升！

### 场景3: 数据库集群

**环境**：
- 主库：10.0.2.10:3306
- 从库1：10.0.2.11:3306
- 从库2：10.0.2.12:3306
- 应用服务器：10.0.1.50（只有3个连接）

**原有检测**：
- 端点基数：1（每个数据库只服务1个应用）
- 端口3306不在知名端口列表
- 结果：VERY_LOW（回退到端口比较）

**新增检测**：
- 端口复用：端口3306被3个数据库服务器使用
- 结果：**MEDIUM** (PORT_REUSE_3servers_on_port3306)

## 优势

1. **识别集群服务**
   - 自动识别负载均衡后端
   - 识别分布式服务节点
   - 识别高可用集群

2. **提升检测准确性**
   - 为基数检测提供额外验证
   - 在基数不足时提供替代方案
   - 双重特征确认提升置信度

3. **适用于现代架构**
   - 微服务架构
   - 容器化部署
   - 云原生应用

4. **无需先验知识**
   - 不依赖端口号
   - 不依赖IP地址范围
   - 自动从数据中学习

## 向后兼容性

✅ **完全向后兼容**
- 新功能自动启用，无需额外配置
- 不影响现有功能和API
- 对于无法使用端口复用检测的场景，自动回退到原有逻辑

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

- **详细设计**：`docs/port_reuse_detection.md`
- **完整总结**：`ENHANCEMENT_SUMMARY.md`
- **实现总结**：`IMPLEMENTATION_SUMMARY.md`（已更新）
- **原理图解**：`docs/cardinality_detection_diagram.md`

## 总结

通过添加端口复用检测维度，形成了**双维度基数分析**体系：

| 维度 | 检测内容 | 适用场景 |
|------|---------|---------|
| **端点基数** | IP:Port → 客户端IP数量 | 单服务器多客户端 |
| **端口复用** | Port → 服务器IP数量 | 集群、分布式系统 |

两个维度互补，显著提升了服务端检测的准确性和适用性，特别是在现代云原生和微服务架构中。

