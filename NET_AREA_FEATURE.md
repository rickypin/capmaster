# net_area 字段功能说明

## 概述

本功能为 Match 插件的数据库写入功能增加了 `net_area` 字段的智能填充，通过分析 TTL Delta（网络跳数）来判断两个抓包点的相对位置，并建立网络区域关联。

## 功能特性

### 1. 基于 TTL Delta 的位置判断

通过比较同一 `group_id` 的 endpoint pair 中两个抓包点（File A 和 File B）的 TTL 跳数，自动判断它们在网络拓扑中的相对位置。

### 2. 智能 net_area 填充

根据位置判断结果，为 Client 和 Server 节点填充 `net_area` 字段，建立网络区域之间的关联关系。

### 3. 日志输出

在数据库写入过程中，日志会输出每个 endpoint pair 的位置判断结果，便于调试和验证。

---

## 判断逻辑

### 核心算法

```python
def _determine_network_position(
    client_hops_a: int,  # File A 客户端跳数
    server_hops_a: int,  # File A 服务端跳数
    client_hops_b: int,  # File B 客户端跳数
    server_hops_b: int,  # File B 服务端跳数
) -> str:
    # 计算 TTL Delta 差异
    client_delta_diff = client_hops_b - client_hops_a
    server_delta_diff = server_hops_a - server_hops_b
    
    # 场景判断...
```

### 判断场景

#### 场景 1: A_CLOSER_TO_CLIENT
**拓扑：** `Client -> File A -> File B -> Server`

**判断条件：**
- `client_delta_diff > 0` (File B 离 Client 更远)
- `server_delta_diff > 0` (File A 离 Server 更远)

**net_area 填充：**
- File A Server 节点: `[pcap_id_b]` (流量流向 File B)
- File B Client 节点: `[pcap_id_a]` (流量来自 File A)

**示例：**
```
client_hops_a=0, server_hops_a=4
client_hops_b=2, server_hops_b=0
→ Client 直连 A，A 经过 2 跳到 B，B 直连 Server，A 经过 4 跳到 Server
```

---

#### 场景 2: B_CLOSER_TO_CLIENT
**拓扑：** `Client -> File B -> File A -> Server`

**判断条件：**
- `client_delta_diff < 0` (File A 离 Client 更远)
- `server_delta_diff < 0` (File B 离 Server 更远)

**net_area 填充：**
- File B Server 节点: `[pcap_id_a]` (流量流向 File A)
- File A Client 节点: `[pcap_id_b]` (流量来自 File B)

**示例：**
```
client_hops_a=2, server_hops_a=0
client_hops_b=0, server_hops_b=4
→ Client 直连 B，B 经过 2 跳到 A，A 直连 Server，B 经过 4 跳到 Server
```

---

#### 场景 3: A_CLOSER_TO_SERVER
**描述：** File A 更靠近 Server（仅基于服务端侧判断）

**判断条件：**
- `server_delta_diff > 0` (File A 离 Server 更远)
- 不满足场景 1 和 2 的条件

**net_area 填充：**
- File B Client 节点: `[pcap_id_a]` (流量来自 File A)

**示例：**
```
client_hops_a=0, server_hops_a=3
client_hops_b=0, server_hops_b=0
→ A 经过 3 跳到 Server，B 直连 Server
```

---

#### 场景 4: B_CLOSER_TO_SERVER
**描述：** File B 更靠近 Server（仅基于服务端侧判断）

**判断条件：**
- `server_delta_diff < 0` (File B 离 Server 更远)
- 不满足场景 1 和 2 的条件

**net_area 填充：**
- File A Client 节点: `[pcap_id_b]` (流量来自 File B)

**示例：**
```
client_hops_a=0, server_hops_a=0
client_hops_b=0, server_hops_b=3
→ A 直连 Server，B 经过 3 跳到 Server
```

---

#### 场景 5: SAME_POSITION
**描述：** 同一位置或无法判断

**判断条件：**
- `server_delta_diff == 0`
- 不满足其他场景的条件

**net_area 填充：**
- 所有节点的 `net_area` 保持为空 `[]`

**示例：**
```
client_hops_a=0, server_hops_a=0
client_hops_b=0, server_hops_b=0
→ 两个抓包点的 TTL 跳数完全相同，无法判断相对位置
```

---

## 数据库表结构

### net_area 字段

- **类型：** `integer[]` (整数数组)
- **含义：** 关联的网络区域列表，存储相关的 `pcap_id`
- **用途：** 表示流量的流向或来源

### 节点类型与 net_area 的关系

| 节点类型 | type 值 | net_area 填充规则 |
|---------|---------|------------------|
| Client  | 1       | 根据位置判断填充（可能为空或包含对端 pcap_id） |
| Server  | 2       | 根据位置判断填充（可能为空或包含对端 pcap_id） |
| Network Device (Client-Capture) | 1001 | 始终为空 `[]` |
| Network Device (Capture-Server) | 1002 | 始终为空 `[]` |

---

## 使用示例

### 命令行使用

```bash
# 写入端点统计到数据库（自动填充 net_area）
capmaster match \
  --file1 a.pcap --file1-pcapid 0 \
  --file2 b.pcap --file2-pcapid 1 \
  --endpoint-stats \
  --db-connection "postgresql://postgres:password@host:port/db" \
  --kase-id 137
```

### 日志输出示例

```
Writing endpoint statistics to database...
  File A pcap_id: 0
  File B pcap_id: 1
  Group 1 (count=10, proto=TCP/TCP, position=Client→A→B→Server): 
    A(10.0.0.1 → 10.0.0.2:80) | B(10.0.0.1 → 10.0.0.2:80)
  Group 2 (count=5, proto=TCP/TCP, position=A closer to Server): 
    A(10.0.0.3 → 10.0.0.4:443 +Capture-Server:3h) | B(10.0.0.3 → 10.0.0.4:443)
```

### 数据库查询示例

```sql
-- 查询某个 group_id 的网络拓扑
SELECT 
    pcap_id,
    group_id,
    type,
    ip,
    port,
    net_area,
    CASE 
        WHEN type = 1 THEN 'Client'
        WHEN type = 2 THEN 'Server'
        WHEN type = 1001 THEN 'NetDevice(Client-Capture)'
        WHEN type = 1002 THEN 'NetDevice(Capture-Server)'
    END as node_type
FROM kase_137_topological_graph
WHERE group_id = 1
ORDER BY pcap_id, type;
```

**查询结果示例（场景 1: Client→A→B→Server）：**

| pcap_id | group_id | type | ip | port | net_area | node_type |
|---------|----------|------|----|----- |----------|-----------|
| 0 | 1 | 1 | 10.0.0.1 | NULL | {} | Client |
| 0 | 1 | 2 | 10.0.0.2 | 80 | {1} | Server |
| 1 | 1 | 1 | 10.0.0.1 | NULL | {0} | Client |
| 1 | 1 | 2 | 10.0.0.2 | 80 | {} | Server |

**解读：**
- File A (pcap_id=0) 的 Server 节点 `net_area={1}` 表示流量流向 File B
- File B (pcap_id=1) 的 Client 节点 `net_area={0}` 表示流量来自 File A
- 拓扑关系：Client → File A → File B → Server

---

## 技术细节

### 与 R2 App 的差异

| 维度 | R2 App | Match Plugin |
|------|--------|--------------|
| 输入 | 多个 PCAP 文件（多点抓包） | 2 个 PCAP 文件 |
| 分组 | 按 stream_id 和 service 分组 | 按 endpoint pair 分组 |
| 排序 | 基于 service_count + TTL score | 已按 count 排序 |
| 关联规则 | 仅在相邻单服务 stream 间建立 | 每个 group_id 内部判断 |
| 网络设备 | 有区域关联时省略 | 始终插入，net_area 为空 |

### 设计原则

1. **不照搬 R2 代码**：根据 Match 场景特点重新设计
2. **基于科学原理**：利用 TTL Delta 判断网络位置
3. **逻辑清晰**：每种场景都有明确的判断条件和填充规则
4. **易于扩展**：未来可以加入更多判断条件

---

## 测试验证

运行测试脚本验证功能：

```bash
python test_net_area_feature.py
```

测试覆盖：
- ✓ 6 种位置判断场景
- ✓ 5 种 net_area 填充逻辑
- ✓ 边界情况和冲突信息处理

---

## 参考资料

- **TTL 原理**：IP 包头中的 TTL 字段，每经过一个路由器减 1
- **标准初始 TTL**：Linux/Unix=64, Windows=128, 网络设备=255
- **R2 App 逻辑**：参考 `host_list` 模块的 `net_area` 判断逻辑

---

## 更新日志

### 2025-01-10
- ✅ 实现 `_determine_network_position()` 方法
- ✅ 实现 `net_area` 字段智能填充
- ✅ 添加日志输出位置判断结果
- ✅ 创建测试脚本验证功能
- ✅ 编写功能文档

