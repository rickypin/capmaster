# capmaster Match 插件完整匹配逻辑

## 概述

capmaster match 插件用于匹配两个 PCAP 文件中的 TCP 连接，识别在不同网络捕获点捕获的同一 TCP 连接。

**核心设计理念：**
- 基于多特征加权评分的匹配算法
- IPID 作为必要条件（必须满足）
- 强 IPID 重叠作为充分条件（可单独判定匹配）
- 方向无关的匹配逻辑（支持角色识别错误场景）
- 分桶优化（提高大规模匹配性能）

---

## 一、整体流程

```
1. 连接提取 (Connection Extraction)
   ├─ 从 PCAP 文件提取 TCP 连接
   ├─ 识别客户端/服务器角色
   └─ 提取 8 大特征

2. 分桶策略 (Bucketing)
   ├─ AUTO: 自动选择策略
   ├─ SERVER: 按服务器 IP 分桶
   ├─ PORT: 按端口分桶
   └─ NONE: 不分桶（全量比较）

3. 预筛选 (Pre-filtering)
   ├─ 服务器端口检查（至少一个公共端口）
   └─ IPID 快速检查（至少 2 个重叠）

4. 评分 (Scoring)
   ├─ 必要条件检查（IPID）
   ├─ 强 IPID 判定（充分条件）
   └─ 8 大特征加权评分

5. 匹配模式 (Matching Mode)
   ├─ ONE_TO_ONE: 贪心一对一匹配
   └─ ONE_TO_MANY: 允许一对多匹配

6. 结果输出
   └─ 匹配对 + 置信度 + 证据
```

---

## 二、连接特征提取（8 大特征）

### 特征列表

| # | 特征名称 | 权重 | 方向性 | 说明 |
|---|---------|------|--------|------|
| 1 | SYN Options | 25% | 方向感知 | TCP SYN 包的选项指纹 |
| 2 | Client ISN | 12% | 方向感知 | 客户端初始序列号 |
| 3 | Server ISN | 6% | 方向感知 | 服务器初始序列号 |
| 4 | TCP Timestamp | 10% | 方向感知 | TCP 时间戳（TSval/TSecr） |
| 5 | Client Payload | 15% | 方向感知 | 客户端首包 Payload MD5 |
| 6 | Server Payload | 8% | 方向感知 | 服务器首包 Payload MD5 |
| 7 | Length Signature | 8% | 方向无关 | 包长度序列签名 |
| 8 | **IPID** | **16%** | **方向无关** | **IP 标识符集合** |

**总权重：100%**

### 特征详解

#### 1. SYN Options (25%)
- **提取位置**: TCP SYN 包
- **格式**: `mss=1460;ws=7;sack=1;ts=1`
- **匹配条件**: 完全相同
- **不可用情况**: 缺少 SYN 包

#### 2. Client ISN (12%)
- **提取位置**: TCP SYN 包
- **格式**: 32 位整数
- **匹配条件**: 完全相同
- **不可用情况**: 缺少 SYN 包

#### 3. Server ISN (6%)
- **提取位置**: TCP SYN-ACK 包
- **格式**: 32 位整数
- **匹配条件**: 完全相同
- **不可用情况**: 缺少 SYN-ACK 包

#### 4. TCP Timestamp (10%)
- **提取位置**: TCP SYN 包的 Timestamp 选项
- **格式**: TSval 和 TSecr
- **匹配条件**: TSval 或 TSecr 任一匹配
- **不可用情况**: 未启用 TCP Timestamp

#### 5. Client Payload MD5 (15%)
- **提取位置**: 客户端首个有 Payload 的数据包
- **格式**: MD5 哈希（前 256 字节）
- **匹配条件**: 完全相同
- **不可用情况**: 无 Payload 或 header-only

#### 6. Server Payload MD5 (8%)
- **提取位置**: 服务器首个有 Payload 的数据包
- **格式**: MD5 哈希（前 256 字节）
- **匹配条件**: 完全相同
- **不可用情况**: 无 Payload 或 header-only

#### 7. Length Signature (8%)
- **提取位置**: 所有数据包
- **格式**: `C:100 S:200 C:50 ...`（C=客户端，S=服务器）
- **匹配条件**: Jaccard 相似度 ≥ 0.6
- **计算方法**: |A ∩ B| / |A ∪ B|

#### 8. IPID (16%) - **核心特征**
- **提取位置**: 所有 IP 包的 IP.ID 字段
- **格式**: 16 位整数集合
- **匹配策略**: **全局 IPID 匹配**（不区分方向）
- **必要条件**: 
  - 重叠数量 ≥ 2
  - 重叠比例 ≥ 50%（交集 / min(集合1, 集合2)）
- **充分条件**（强 IPID）:
  - 重叠数量 ≥ 10
  - 重叠比例 ≥ 80%

---

## 三、分桶策略 (Bucketing)

### 目的
减少比较次数，提高性能（从 O(n²) 降低到 O(n)）

### 策略类型

#### 1. AUTO（自动选择）
根据连接特征自动选择最佳策略：

```python
if 服务器 IP 完全相同:
    使用 SERVER 策略
elif 服务器 IP 不同 but 有公共端口:
    使用 PORT 策略
elif 有部分公共服务器:
    使用 SERVER 策略
else:
    使用 PORT 策略（默认，对 NAT 友好）
```

#### 2. SERVER（按服务器 IP 分桶）
- **分桶键**: `{ip1}:{ip2}`（归一化后的 IP 对）
- **适用场景**: 两个 PCAP 捕获的是相同服务器
- **优点**: 精确匹配，性能最优
- **缺点**: 不支持 NAT/负载均衡场景

#### 3. PORT（按端口分桶）
- **分桶键**: 端口号（每个连接放入两个桶：客户端端口 + 服务器端口）
- **适用场景**: NAT/负载均衡/代理场景
- **优点**: 对 IP 变化不敏感
- **缺点**: 桶内连接数可能较多

#### 4. NONE（不分桶）
- **分桶键**: `"all"`（所有连接在一个桶）
- **适用场景**: 连接数很少（< 100）
- **优点**: 不会遗漏任何匹配
- **缺点**: 性能差（O(n²)）

---

## 四、预筛选 (Pre-filtering)

在进行昂贵的评分计算前，先进行快速检查：

### 1. 服务器端口检查
```python
ports1 = {conn1.client_port, conn1.server_port}
ports2 = {conn2.client_port, conn2.server_port}
if not (ports1 & ports2):
    跳过此配对  # 没有公共端口
```

**目的**: 确保至少有一个公共端口（通常是服务器端口）

### 2. IPID 快速检查
```python
intersection = conn1.ipid_set & conn2.ipid_set
if len(intersection) < 2:
    跳过此配对  # IPID 重叠不足
```

**目的**: 快速排除 IPID 不匹配的连接对

---

## 五、评分算法 (Scoring)

### 评分流程

```
1. 检查服务器端口（必要条件）
   └─ 不满足 → 返回 0 分

2. 检查 IPID（必要条件）
   ├─ 不满足 → 返回 0 分
   └─ 满足 → 继续

3. 判断强 IPID（充分条件）
   ├─ 重叠数 ≥ 10 且 重叠率 ≥ 80%
   └─ 满足 → 设置 force_accept = True

4. 计算各特征得分
   ├─ SYN Options
   ├─ Client ISN
   ├─ Server ISN
   ├─ TCP Timestamp
   ├─ Client Payload
   ├─ Server Payload
   ├─ Length Signature
   └─ IPID（已匹配，直接加权重）

5. 归一化得分
   normalized_score = raw_score / available_weight

6. 判定是否有效匹配
   is_valid = ipid_match AND (normalized_score ≥ 0.60 OR force_accept)
```

### IPID 匹配逻辑（核心）

#### 必要条件（基本 IPID 匹配）
```python
intersection = conn1.ipid_set & conn2.ipid_set
overlap_count = len(intersection)
min_size = min(len(conn1.ipid_set), len(conn2.ipid_set))
overlap_ratio = overlap_count / min_size

# 必须同时满足：
条件1: overlap_count ≥ 2
条件2: overlap_ratio ≥ 0.5
```

**设计理由：**
- IPID 是 16 位（65536 个值），随机碰撞概率 ~0.003%
- 要求 2 个重叠避免单点碰撞
- 要求 50% 比例避免大流量下的偶然重叠
- 使用 min(size1, size2) 作为分母，对短连接和长连接都公平

#### 充分条件（强 IPID 匹配）
```python
# 当 IPID 证据压倒性强时，其他特征不再必要
条件1: overlap_count ≥ 10
条件2: overlap_ratio ≥ 0.8

if 条件1 AND 条件2:
    force_accept = True
    # 即使 normalized_score < 0.60 也接受匹配
```

**设计理由：**
- 10 个 IPID 且 80% 重叠率，随机碰撞概率 < 10^-20
- 解决角色识别错误导致方向特征全部失效的问题
- 典型场景：缺少 SYN 包 → 角色识别错误 → 其他特征不匹配 → 但 IPID 强匹配

#### 为什么全局 IPID 是安全的？

**IPID 的本质：**
- IPID 是**主机级别**的计数器，不是连接级别
- 每个主机维护自己的 IPID 序列
- 不同主机的 IPID 序列完全独立

**安全性分析：**
1. **不同主机 IPID 碰撞概率极低**
   - 主机 A: 0x72e8, 0x72e9, 0x72ea, ...
   - 主机 B: 0x70f3, 0x70f4, 0x70f5, ...
   - 高重叠率（>80%）几乎不可能是随机碰撞

2. **同一连接 IPID 高度重叠**
   - 透明网络：IPID 不变
   - NAT 转换：IPID 不变
   - 实际数据：97.46% 重叠率（TC-001-4-20190810）

3. **不需要方向区分**
   - 即使不区分客户端/服务器方向
   - 高 IPID 重叠率本身就是强证据
   - 避免角色识别错误导致的假阴性

---

## 六、匹配模式 (Matching Mode)

### 1. ONE_TO_ONE（一对一贪心匹配）

**算法：**
```python
1. 对所有候选配对进行评分
2. 按 (force_accept, normalized_score) 降序排序
3. 贪心选择：
   - 选择得分最高的配对
   - 标记两个连接为"已使用"
   - 继续选择下一个最高分且未使用的配对
```

**特点：**
- 每个连接最多匹配一次
- 优先选择强 IPID 匹配
- 向后兼容原始脚本行为

**适用场景：**
- 标准的点对点匹配
- 两个 PCAP 捕获的是相同时间段的流量

### 2. ONE_TO_MANY（一对多匹配）

**算法：**
```python
1. 对所有候选配对进行评分
2. 接受所有有效匹配（score.is_valid_match() == True）
3. 按 (force_accept, normalized_score) 降序排序
```

**特点：**
- 一个连接可以匹配多个连接
- 适用于时间窗口不完全重叠的场景
- 需要时间重叠检查（可选）

**适用场景：**
- 一个 PCAP 有长连接，另一个 PCAP 有多个短连接（相同 5-tuple）
- 捕获时间窗口不同

---

## 七、匹配判定

### 有效匹配条件
```python
def is_valid_match(score, threshold=0.60):
    return score.ipid_match AND (
        score.normalized_score >= threshold OR
        score.force_accept
    )
```

**三种匹配情况：**

1. **标准匹配**: IPID 匹配 + 归一化得分 ≥ 0.60
2. **强 IPID 匹配**: IPID 匹配 + force_accept = True（绕过得分阈值）
3. **不匹配**: IPID 不匹配 或 (得分 < 0.60 且非强 IPID)

---

## 八、证据字符串 (Evidence)

匹配结果会生成证据字符串，显示哪些特征匹配：

```
示例1: "synopt isnC isnS ts dataC dataS shape(0.85) ipid"
  → 所有特征都匹配，标准高分匹配

示例2: "ipid*"
  → 仅 IPID 匹配，但是强 IPID（ipid* 表示 force_accept）

示例3: "synopt isnC ts ipid"
  → SYN 选项、客户端 ISN、时间戳、IPID 匹配
```

**证据标记：**
- `synopt`: SYN Options 匹配
- `isnC`: Client ISN 匹配
- `isnS`: Server ISN 匹配
- `ts`: TCP Timestamp 匹配
- `dataC`: Client Payload 匹配
- `dataS`: Server Payload 匹配
- `shape(x.xx)`: Length Signature 匹配（相似度）
- `ipid`: IPID 匹配（普通）
- `ipid*`: IPID 匹配（强匹配，force_accept）

---

## 九、当前实现的局限性

### 1. NAT 场景支持有限
**问题**: 当客户端 IP 经过 NAT 转换时，四元组不匹配
**示例**: TC-002-5-20220215-O
- File1: `10.3.36.141:29842 <-> 111.203.2.194:443`
- File2: `219.142.89.13:6672 <-> 111.203.2.194:443`
- IPID 重叠 100%（27 个），但四元组不同 → 无法匹配

**当前缓解措施**:
- PORT 分桶策略（按端口分桶，对 IP 变化不敏感）
- 服务器端口检查（只要求公共端口，不要求 IP 匹配）

**未来改进方向**:
- 支持部分四元组匹配（如只匹配服务器 IP + 端口）
- 基于时间窗口 + IPID 序列的匹配
- NAT 感知模式

### 2. 方向特征依赖角色识别
**问题**: 当角色识别错误时，所有方向特征失效
**示例**: TC-001-4-20190810（缺少 SYN 包 → 角色相反）

**当前解决方案**:
- 强 IPID 充分条件（绕过方向特征）
- 全局 IPID 匹配（不依赖方向）

**未来改进方向**:
- 角色互换尝试（自动尝试交换角色后再匹配）
- 更多方向无关特征

### 3. 性能优化空间
**当前优化**:
- 分桶策略
- 预筛选（端口 + IPID）

**未来改进方向**:
- 并行评分
- 更智能的分桶策略
- 增量匹配（流式处理）

---

## 十、配置参数

### 可调参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `score_threshold` | 0.60 | 归一化得分阈值 |
| `bucket_strategy` | AUTO | 分桶策略 |
| `match_mode` | ONE_TO_ONE | 匹配模式 |
| `MIN_IPID_OVERLAP` | 2 | IPID 最小重叠数 |
| `MIN_IPID_OVERLAP_RATIO` | 0.5 | IPID 最小重叠比例 |
| `STRONG_IPID_MIN_OVERLAP` | 10 | 强 IPID 最小重叠数 |
| `STRONG_IPID_MIN_RATIO` | 0.8 | 强 IPID 最小重叠比例 |
| `LENGTH_SIG_THRESHOLD` | 0.6 | Length Signature 相似度阈值 |

### 建议配置

**标准场景**（默认）:
```python
matcher = ConnectionMatcher(
    bucket_strategy=BucketStrategy.AUTO,
    score_threshold=0.60,
    match_mode=MatchMode.ONE_TO_ONE
)
```

**NAT 场景**:
```python
matcher = ConnectionMatcher(
    bucket_strategy=BucketStrategy.PORT,  # 按端口分桶
    score_threshold=0.50,  # 降低阈值
    match_mode=MatchMode.ONE_TO_ONE
)
```

**时间窗口不重叠场景**:
```python
matcher = ConnectionMatcher(
    bucket_strategy=BucketStrategy.AUTO,
    score_threshold=0.60,
    match_mode=MatchMode.ONE_TO_MANY  # 允许一对多
)
```

---

## 十一、典型案例分析

### 案例 1: TC-001-4-20190810（强 IPID 充分条件）
**场景**: File2 缺少 SYN 包 → 角色识别错误 → 方向特征全部失效

**IPID 分析**:
- 重叠数: 499 个
- 重叠率: 97.46%
- 满足强 IPID 条件（≥10 且 ≥80%）

**匹配结果**:
- 归一化得分: 0.38（低于 0.60 阈值）
- force_accept: True（强 IPID）
- 最终判定: **匹配成功** ✅
- 证据: `ipid*`

### 案例 2: TC-002-5-20220215-O（NAT 场景）
**场景**: 客户端 IP 经过 NAT 转换

**连接对比**:
- File1: `10.3.36.141:29842 <-> 111.203.2.194:443`
- File2: `219.142.89.13:6672 <-> 111.203.2.194:443`

**IPID 分析**:
- 重叠数: 27 个
- 重叠率: 100%
- 满足强 IPID 条件

**匹配结果**:
- 当前: **不匹配** ❌（四元组不同，未进入比较）
- 原因: 分桶阶段就被过滤掉（不在同一个桶）

**改进方向**: 需要支持部分四元组匹配或 NAT 感知模式

---

## 十二、总结

capmaster match 插件采用**多特征加权评分 + IPID 双重阈值**的匹配策略：

**核心优势：**
1. ✅ 全局 IPID 匹配 - 不依赖角色识别
2. ✅ 强 IPID 充分条件 - 解决方向特征失效问题
3. ✅ 分桶优化 - 高性能
4. ✅ 灵活的匹配模式 - 支持一对一和一对多

**当前局限：**
1. ❌ NAT 场景支持有限（需要四元组至少部分匹配）
2. ❌ 方向特征依赖角色识别（已通过强 IPID 缓解）

**适用场景：**
- ✅ 透明网络（无 NAT）
- ✅ 相同捕获时间窗口
- ✅ 完整的 TCP 握手包
- ⚠️ NAT/负载均衡场景（部分支持）
- ⚠️ 缺少 SYN 包场景（通过强 IPID 支持）

