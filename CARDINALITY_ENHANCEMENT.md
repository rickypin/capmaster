# 基于基数的服务端检测增强

## 概述

本次增强为 `--endpoint-stats` 功能添加了基于基数（Cardinality）的服务端检测逻辑，利用"同一对服务端IP和端口往往服务于多个客户端IP"这一普遍特征来提高服务端识别的准确性。

## 核心原理

### 服务端与客户端的基数特征

在典型的客户端-服务端架构中：

**服务端特征（高基数）：**
- 同一个服务端 IP:Port 组合会服务于**多个不同的客户端IP**
- 例如：Web服务器 `192.168.1.100:80` 可能同时服务 100+ 个不同的客户端IP
- 基数（Cardinality）= 连接到该端点的唯一客户端IP数量

**客户端特征（低基数）：**
- 同一个客户端IP通常只连接到**少数几个服务端**
- 例如：客户端 `10.0.0.50` 可能只连接到 2-3 个不同的服务端
- 基数 = 该客户端连接的唯一服务端 IP:Port 组合数量

### 判断逻辑

通过比较连接两端的基数，可以推断哪一端更可能是服务端：

```
如果 endpoint1 的基数 >> endpoint2 的基数
  → endpoint1 更可能是服务端
  
如果 endpoint2 的基数 >> endpoint1 的基数
  → endpoint2 更可能是服务端
```

## 实现细节

### 1. 数据结构

在 `ServerDetector` 类中添加了两个跟踪字典：

```python
# 跟踪每个 IP:Port 组合服务的唯一客户端IP集合
self._endpoint_clients: dict[tuple[str, int], set[str]] = defaultdict(set)

# 跟踪每个客户端IP连接的唯一服务端 IP:Port 集合
self._client_servers: dict[str, set[tuple[str, int]]] = defaultdict(set)
```

### 2. 三阶段处理流程

#### 阶段1: 收集连接信息
```python
def collect_connection(self, connection: TcpConnection) -> None:
    """收集所有连接的端点信息，建立基数统计"""
```

对每个连接，双向记录：
- `server_ip:server_port` → `client_ip`
- `client_ip:client_port` → `server_ip`

这样做是因为在收集阶段我们还不确定哪一端是服务端。

#### 阶段2: 完成基数分析
```python
def finalize_cardinality(self) -> None:
    """标记基数分析已完成，可以开始检测"""
```

#### 阶段3: 基于基数检测服务端
```python
def _detect_by_cardinality(self, connection: TcpConnection) -> ServerInfo:
    """使用基数分析判断服务端"""
```

### 3. 检测规则

基数检测使用以下规则（按优先级）：

#### 规则1: 明确的服务端模式（HIGH/MEDIUM置信度）
```python
MIN_SERVER_CLIENTS = 2  # 至少服务2个不同的客户端IP

if cardinality1 >= MIN_SERVER_CLIENTS and cardinality2 < MIN_SERVER_CLIENTS:
    # endpoint1 是服务端
    confidence = "HIGH" if cardinality1 >= 5 else "MEDIUM"
```

- 如果一端基数 ≥ 2，另一端 < 2 → 高基数端是服务端
- 基数 ≥ 5 → HIGH 置信度
- 基数 2-4 → MEDIUM 置信度

#### 规则2: 基数比率判断（MEDIUM置信度）
```python
if cardinality1 > 0 and cardinality2 > 0:
    ratio = max(cardinality1, cardinality2) / min(cardinality1, cardinality2)
    
    if ratio >= 3.0:
        # 基数较大的一端是服务端
        confidence = "MEDIUM"
```

- 如果两端基数比率 ≥ 3:1 → 高基数端是服务端
- 置信度：MEDIUM

#### 规则3: 无法判断（UNKNOWN）
```python
# 基数相近或都为0
confidence = "UNKNOWN"
```

### 4. 检测方法字段

为了便于调试和分析，检测方法字段包含基数信息：

- `CARDINALITY_63v1` - 基数 63:1，未交换
- `CARDINALITY_SWAPPED_63v1` - 基数 63:1，已交换
- `CARDINALITY_RATIO_10v3` - 基数比率 10:3
- `CARDINALITY_UNCLEAR_1v1` - 基数相同，无法判断

## 优先级调整

在原有的多层检测体系中，基数检测被插入为**第3优先级**：

```
Priority 1: SYN packet direction (最可靠)
Priority 2: Port number heuristics (知名端口)
Priority 3: Cardinality-based detection (新增！)
Priority 4: Traffic pattern analysis (未实现)
Priority 5: Port number comparison (兜底)
```

这个位置的选择理由：
1. **低于SYN包检测**：SYN包方向是最可靠的，应该优先使用
2. **低于端口启发式**：知名端口（如80, 443, 3306）的判断也很可靠
3. **高于兜底逻辑**：基数分析比简单的端口号比较更有意义

## 使用示例

### 示例1: 典型的Web服务器场景

假设有以下连接：
```
Client 10.0.0.1:50001 <-> Server 192.168.1.100:80
Client 10.0.0.2:50002 <-> Server 192.168.1.100:80
Client 10.0.0.3:50003 <-> Server 192.168.1.100:80
...
Client 10.0.0.63:50063 <-> Server 192.168.1.100:80
```

基数分析：
- `192.168.1.100:80` 的基数 = 63（服务63个不同的客户端IP）
- 每个客户端端口的基数 = 1（只连接到1个服务端）

检测结果：
```
Server: 192.168.1.100:80
Confidence: HIGH
Method: CARDINALITY_63v1
```

### 示例2: 数据库服务器场景

```
Client 10.0.1.10:40001 <-> Server 10.0.2.100:3306
Client 10.0.1.11:40002 <-> Server 10.0.2.100:3306
Client 10.0.1.12:40003 <-> Server 10.0.2.100:3306
```

基数分析：
- `10.0.2.100:3306` 的基数 = 3
- 每个客户端端口的基数 = 1

检测结果：
```
Server: 10.0.2.100:3306
Confidence: MEDIUM  (基数3，未达到5的HIGH阈值)
Method: CARDINALITY_3v1
```

### 示例3: 点对点连接（无法判断）

```
Client 10.0.0.1:50001 <-> Server 10.0.0.2:60001
```

基数分析：
- 两端基数都是 1

检测结果：
```
Confidence: UNKNOWN
Method: CARDINALITY_UNCLEAR_1v1
```

会继续尝试其他检测方法（如端口号比较）。

## 测试结果

### 测试用例: TC-001-1-20160407

**场景**：63个TCP连接，都是同一个客户端连接到同一个服务端

**输入**：
- File A: 166 connections
- File B: 465 connections
- Matched: 63 connections

**基数统计**：
- 服务端 `10.30.50.101:6096` (File A) / `10.0.6.33:6096` (File B)
  - 基数 = 63（服务于63个不同的客户端端口）
- 客户端 `17.17.17.45`
  - 每个客户端端口的基数 = 1

**检测结果**：
```
[1] Count: 63 | Confidence: HIGH
    File A: Client 17.17.17.45 → Server 10.30.50.101:6096
    File B: Client 17.17.17.45 → Server 10.0.6.33:6096
```

**分析**：
- ✅ 正确识别服务端（基数 63 vs 1）
- ✅ 置信度 HIGH（基数 ≥ 5）
- ✅ 即使没有SYN包或知名端口，也能准确判断

## 优势

1. **适用于非标准端口**：不依赖端口号，可以识别使用自定义端口的服务
2. **适用于无SYN包场景**：当PCAP文件不包含连接建立过程时仍然有效
3. **统计学可靠性**：基于大量连接的统计特征，比单个连接的特征更可靠
4. **自动学习**：无需预先配置端口列表，自动从数据中学习服务端特征

## 局限性

1. **需要多个连接**：对于只有1-2个连接的场景，基数分析无法发挥作用
2. **点对点场景**：在P2P或对等连接场景中可能无法准确判断
3. **需要完整数据集**：必须先收集所有连接才能进行基数分析
4. **内存开销**：需要存储所有端点的客户端集合

## 未来改进方向

1. **动态阈值**：根据数据集大小自动调整 `MIN_SERVER_CLIENTS` 阈值
2. **加权基数**：考虑连接持续时间、数据量等因素
3. **双向基数**：同时考虑"服务多少客户端"和"被多少客户端连接"
4. **时间窗口分析**：在时间维度上分析基数变化趋势
5. **异常检测**：识别异常的基数模式（如DDoS攻击）

## 总结

基于基数的服务端检测是对现有多层检测体系的重要补充，特别适用于：
- 使用非标准端口的服务
- 缺少SYN包的PCAP文件
- 需要高置信度判断的场景

通过利用"服务端服务多个客户端"这一普遍特征，显著提高了服务端识别的准确性和鲁棒性。

