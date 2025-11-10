# net_area 功能快速参考

## 一句话总结

通过分析 TTL Delta 判断两个抓包点的相对位置，并在数据库的 `net_area` 字段中建立网络区域关联。

---

## 5 种判断场景速查表

| 场景代码 | 拓扑图 | 判断条件 | net_area 填充 |
|---------|--------|----------|---------------|
| **A_CLOSER_TO_CLIENT** | `Client → A → B → Server` | `client_hops_b > client_hops_a` <br> `server_hops_a > server_hops_b` | A.server = [1] <br> B.client = [0] |
| **B_CLOSER_TO_CLIENT** | `Client → B → A → Server` | `client_hops_a > client_hops_b` <br> `server_hops_b > server_hops_a` | B.server = [0] <br> A.client = [1] |
| **A_CLOSER_TO_SERVER** | `A 更靠近 Server` | `server_hops_a > server_hops_b` | B.client = [0] |
| **B_CLOSER_TO_SERVER** | `B 更靠近 Server` | `server_hops_b > server_hops_a` | A.client = [1] |
| **SAME_POSITION** | `同一位置/无法判断` | `server_hops_a == server_hops_b` | 所有 = [] |

**注：** pcap_id_a=0, pcap_id_b=1

---

## 核心算法

```python
# 计算 TTL Delta 差异
client_delta_diff = client_hops_b - client_hops_a
server_delta_diff = server_hops_a - server_hops_b

# 判断逻辑
if client_delta_diff > 0 and server_delta_diff > 0:
    return "A_CLOSER_TO_CLIENT"  # Client → A → B → Server
elif client_delta_diff < 0 and server_delta_diff < 0:
    return "B_CLOSER_TO_CLIENT"  # Client → B → A → Server
elif server_delta_diff > 0:
    return "A_CLOSER_TO_SERVER"
elif server_delta_diff < 0:
    return "B_CLOSER_TO_SERVER"
else:
    return "SAME_POSITION"
```

---

## 实际示例

### 示例 1: Client → A → B → Server

**TTL 数据：**
```
File A: client_hops=0, server_hops=4
File B: client_hops=2, server_hops=0
```

**判断过程：**
```
client_delta_diff = 2 - 0 = 2 > 0  ✓
server_delta_diff = 4 - 0 = 4 > 0  ✓
→ A_CLOSER_TO_CLIENT
```

**net_area 填充：**
```
File A Server: net_area = [1]  (流量流向 File B)
File B Client: net_area = [0]  (流量来自 File A)
```

**拓扑解读：**
```
Client --[0 hops]--> File A --[2 hops]--> File B --[0 hops]--> Server
                     (抓包点A)            (抓包点B)
```

---

### 示例 2: Client → B → A → Server

**TTL 数据：**
```
File A: client_hops=2, server_hops=0
File B: client_hops=0, server_hops=4
```

**判断过程：**
```
client_delta_diff = 0 - 2 = -2 < 0  ✓
server_delta_diff = 0 - 4 = -4 < 0  ✓
→ B_CLOSER_TO_CLIENT
```

**net_area 填充：**
```
File B Server: net_area = [0]  (流量流向 File A)
File A Client: net_area = [1]  (流量来自 File B)
```

---

### 示例 3: A 更靠近 Server

**TTL 数据：**
```
File A: client_hops=0, server_hops=3
File B: client_hops=0, server_hops=0
```

**判断过程：**
```
client_delta_diff = 0 - 0 = 0
server_delta_diff = 3 - 0 = 3 > 0  ✓
→ A_CLOSER_TO_SERVER
```

**net_area 填充：**
```
File B Client: net_area = [0]  (流量来自 File A)
```

---

## 日志输出格式

```
Group 1 (count=10, proto=TCP/TCP, position=Client→A→B→Server): 
  A(10.0.0.1 → 10.0.0.2:80) | B(10.0.0.1 → 10.0.0.2:80)
```

**字段说明：**
- `count`: 匹配的连接数
- `proto`: 协议（File A / File B）
- `position`: 位置判断结果（人类可读格式）
- `A(...)`: File A 的端点信息
- `B(...)`: File B 的端点信息

---

## 数据库表结构

### net_area 字段

```sql
net_area integer[]  -- 整数数组，存储关联的 pcap_id
```

### 查询示例

```sql
-- 查询 group_id=1 的拓扑关系
SELECT pcap_id, type, ip, port, net_area
FROM kase_137_topological_graph
WHERE group_id = 1
ORDER BY pcap_id, type;
```

**结果示例（场景 1）：**
```
pcap_id | type | ip        | port | net_area
--------|------|-----------|------|----------
0       | 1    | 10.0.0.1  | NULL | {}
0       | 2    | 10.0.0.2  | 80   | {1}      ← 指向 File B
1       | 1    | 10.0.0.1  | NULL | {0}      ← 来自 File A
1       | 2    | 10.0.0.2  | 80   | {}
```

---

## 节点类型说明

| type | 节点类型 | net_area 规则 |
|------|---------|---------------|
| 1 | Client | 根据位置判断填充 |
| 2 | Server | 根据位置判断填充 |
| 1001 | Network Device (Client-Capture) | 始终为空 [] |
| 1002 | Network Device (Capture-Server) | 始终为空 [] |

---

## 测试命令

```bash
# 运行单元测试
python test_net_area_feature.py

# 运行集成测试
python test_net_area_integration.py
```

---

## 常见问题

### Q1: 为什么网络设备节点的 net_area 是空的？

**A:** 网络设备节点是虚拟节点，用于表示网络跳数，不参与区域关联。区域关联只在 Client 和 Server 节点之间建立。

### Q2: 如果两个抓包点的 TTL 完全相同怎么办？

**A:** 判断为 `SAME_POSITION`，所有节点的 `net_area` 保持为空 `[]`。

### Q3: net_area 数组中可以有多个 pcap_id 吗？

**A:** 在当前实现中，net_area 最多包含一个 pcap_id（对端的 pcap_id）。未来可以扩展支持多点抓包场景。

### Q4: 如何理解 "流量流向" 和 "流量来源"？

**A:** 
- **Server 节点的 net_area**：表示流量的下一跳（流向）
- **Client 节点的 net_area**：表示流量的上一跳（来源）

例如在 `Client → A → B → Server` 中：
- A 的 Server 节点 net_area=[1]：流量从 A 流向 B
- B 的 Client 节点 net_area=[0]：流量从 A 流入 B

---

## 相关文档

- **NET_AREA_FEATURE.md** - 详细功能说明（约 300 行）
- **NET_AREA_IMPLEMENTATION_SUMMARY.md** - 实施总结
- **NET_AREA_QUICK_REFERENCE.md** - 本文档

---

## 版本信息

- **实施日期：** 2025-01-10
- **版本：** 1.0
- **状态：** ✅ 已完成并测试通过

