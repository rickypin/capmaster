# 网络设备节点数据库写入功能

## 📋 功能概述

在 Match 插件的数据库写入功能中，增加了**网络设备节点**的自动插入逻辑。当路由跳数（hops）不为 0 时，表示客户端或服务端与抓包点之间存在网络设备（如路由器），系统会自动在数据库中插入相应的网络设备节点记录。

---

## 🎯 设计原理

### 跳数与网络设备的关系

- **hops = 0**: 抓包点就在 server 或 client 上，中间没有网络设备
- **hops ≠ 0**: 抓包点到 server 或 client 之间存在网络设备

### 网络设备节点类型

在数据库中，网络设备节点通过特殊的 `type` 字段标识：

| Type | 含义 | 说明 |
|------|------|------|
| 1001 | Client-Capture 网络设备 | 客户端与抓包点之间的网络设备 |
| 1002 | Capture-Server 网络设备 | 抓包点与服务器之间的网络设备 |

### 节点字段特征

网络设备节点的字段值：
- `ip`: NULL（网络设备没有具体 IP）
- `port`: NULL
- `proto`: NULL
- `type`: 1001 或 1002
- `stream_cnt`: 0
- `pktlen`: 0
- `display_name`: 描述性名称，如 "Network Device (Capture-Server, 4 hops)"

---

## 🏗️ 实现细节

### 数据库写入逻辑

在 `MatchDatabaseWriter.write_endpoint_stats()` 方法中，对每个 endpoint pair：

#### 原有节点（始终插入）
1. **File A - Client 节点** (type=1)
2. **File A - Server 节点** (type=2)
3. **File B - Client 节点** (type=1)
4. **File B - Server 节点** (type=2)

#### 新增网络设备节点（条件插入）

**File A:**
- 如果 `client_hops_a > 0`，插入 **type=1001** 节点（Client-Capture）
- 如果 `server_hops_a > 0`，插入 **type=1002** 节点（Capture-Server）

**File B:**
- 如果 `client_hops_b > 0`，插入 **type=1001** 节点（Client-Capture）
- 如果 `server_hops_b > 0`，插入 **type=1002** 节点（Capture-Server）

### 代码示例

<augment_code_snippet path="capmaster/plugins/match/db_writer.py" mode="EXCERPT">
````python
# File A - Network device between client and capture point (type=1001)
# Only insert if client_hops_a > 0
if stat.client_hops_a > 0:
    self.insert_node(
        pcap_id=pcap_id_a,
        group_id=group_id,
        ip=None,
        port=None,
        proto=None,
        node_type=1001,  # Network device between client and capture point
        is_capture=False,
        net_area=[],
        stream_cnt=0,
        pktlen=0,
        display_name=f"Network Device (Client-Capture, {stat.client_hops_a} hops)",
    )
````
</augment_code_snippet>

---

## 📊 插入场景示例

### 场景 1: 仅服务端有网络设备

**Endpoint Pair:**
- File A: Client TTL=64 (hops=0), Server TTL=60 (hops=4)
- File B: Client TTL=128 (hops=0), Server TTL=120 (hops=8)

**插入的节点：**
```
Group 1:
  [Client]                    pcap_id=0, ip=192.168.1.100
  [Server]                    pcap_id=0, ip=10.0.0.50:80
  [NetDevice(Capture-Server)] pcap_id=0, ip=NULL (4 hops)
  
  [Client]                    pcap_id=1, ip=172.16.0.200
  [Server]                    pcap_id=1, ip=10.0.0.51:80
  [NetDevice(Capture-Server)] pcap_id=1, ip=NULL (8 hops)
```

**总计：** 6 个节点（4 个基础节点 + 2 个网络设备节点）

---

### 场景 2: 客户端和服务端都有网络设备

**Endpoint Pair:**
- File A: Client TTL=61 (hops=3), Server TTL=58 (hops=6)
- File B: Client TTL=125 (hops=3), Server TTL=115 (hops=13)

**插入的节点：**
```
Group 3:
  [Client]                    pcap_id=0, ip=192.168.1.102
  [NetDevice(Client-Capture)] pcap_id=0, ip=NULL (3 hops)
  [Server]                    pcap_id=0, ip=10.0.0.54:22
  [NetDevice(Capture-Server)] pcap_id=0, ip=NULL (6 hops)
  
  [Client]                    pcap_id=1, ip=172.16.0.202
  [NetDevice(Client-Capture)] pcap_id=1, ip=NULL (3 hops)
  [Server]                    pcap_id=1, ip=10.0.0.55:22
  [NetDevice(Capture-Server)] pcap_id=1, ip=NULL (13 hops)
```

**总计：** 8 个节点（4 个基础节点 + 4 个网络设备节点）

---

## 🔍 日志输出

### 写入日志示例

```
2025-11-10 20:17:07,825 - INFO - Group 1 (count=5, proto=TCP/TCP): 
  A(192.168.1.100 → 10.0.0.50:80 +Capture-Server:4h) | 
  B(172.16.0.200 → 10.0.0.51:80 +Capture-Server:8h)

2025-11-10 20:17:08,022 - INFO - Group 3 (count=2, proto=TCP/TCP): 
  A(192.168.1.102 → 10.0.0.54:22 +Client-Capture:3h,Capture-Server:6h) | 
  B(172.16.0.202 → 10.0.0.55:22 +Client-Capture:3h,Capture-Server:13h)
```

**日志格式说明：**
- `+Capture-Server:4h`: 表示插入了 Capture-Server 网络设备节点，4 跳
- `+Client-Capture:3h,Capture-Server:6h`: 表示插入了两个网络设备节点

---

## 🧪 测试验证

### 测试文件

`test_match_endpoint_db.py` - 数据库写入集成测试

### 测试场景

测试包含 3 个 endpoint pairs：

1. **Scenario 1**: 仅服务端有网络设备（File A: 4 hops, File B: 8 hops）
2. **Scenario 2**: 仅服务端有网络设备（File A: 10 hops, File B: 2 hops）
3. **Scenario 3**: 客户端和服务端都有网络设备（File A: 3+6 hops, File B: 3+13 hops）

### 测试结果

```
✓ Successfully wrote 20 records to database
✓ Network device nodes inserted: 8
✓ Test completed successfully!
```

**节点统计：**
- 基础节点（type=1,2）: 12 个（3 个 endpoint pairs × 4）
- 网络设备节点（type=1001,1002）: 8 个
- **总计：20 个节点**

---

## 📈 数据库表结构

### 表名

`public.kase_{kase_id}_topological_graph`

### 相关字段

| 字段 | 类型 | 说明 |
|------|------|------|
| id | SERIAL | 主键 |
| pcap_id | INTEGER | PCAP 文件 ID |
| group_id | INTEGER | 端点对分组 ID |
| ip | VARCHAR | IP 地址（网络设备节点为 NULL） |
| port | INTEGER | 端口号（网络设备节点为 NULL） |
| proto | INTEGER | 协议号（网络设备节点为 NULL） |
| type | INTEGER | 节点类型（1=Client, 2=Server, 1001=Client-Capture, 1002=Capture-Server） |
| stream_cnt | INTEGER | 流数量 |
| display_name | VARCHAR | 显示名称 |

### 查询示例

```sql
-- 查询所有网络设备节点
SELECT * FROM public.kase_137_topological_graph
WHERE type IN (1001, 1002)
ORDER BY group_id, pcap_id;

-- 统计每个 group 的网络设备数量
SELECT group_id, COUNT(*) as device_count
FROM public.kase_137_topological_graph
WHERE type IN (1001, 1002)
GROUP BY group_id;
```

---

## 🎨 拓扑图可视化

网络设备节点可用于拓扑图展示，表示网络路径：

```
File A (pcap_id=0):
  Client (192.168.1.102)
    ↓ (3 hops)
  [Network Device] (type=1001)
    ↓
  Capture Point
    ↓ (6 hops)
  [Network Device] (type=1002)
    ↓
  Server (10.0.0.54:22)
```

---

## 🔧 使用方法

### 命令行使用

```bash
# 运行 match 插件并写入数据库（包含网络设备节点）
python -m capmaster match \
  -i <input_dir> \
  --endpoint-stats \
  --db-connection "postgresql://user:pass@host:port/dbname" \
  --kase-id <kase_id>
```

### 程序化使用

```python
from capmaster.plugins.match.db_writer import MatchDatabaseWriter
from capmaster.plugins.match.endpoint_stats import EndpointPairStats

# 创建数据库写入器
with MatchDatabaseWriter(db_connection, kase_id) as db:
    db.ensure_table_exists()
    
    # 写入端点统计（自动插入网络设备节点）
    records_inserted = db.write_endpoint_stats(
        endpoint_stats=stats,
        pcap_id_mapping=pcap_mapping,
        file1_path="file_a.pcap",
        file2_path="file_b.pcap",
    )
    
    db.commit()
```

---

## ✅ 功能特点

1. **自动化**: 根据 hops 值自动判断是否插入网络设备节点
2. **准确性**: 区分 Client-Capture 和 Capture-Server 两种网络设备
3. **完整性**: 保留跳数信息在 display_name 中
4. **一致性**: 与现有节点类型（1, 2）保持一致的数据结构
5. **可追溯**: 通过日志清晰记录网络设备节点的插入

---

## 📝 相关文件

- `capmaster/plugins/match/db_writer.py` - 数据库写入逻辑（已更新）
- `capmaster/plugins/match/endpoint_stats.py` - 端点统计（包含 hops 字段）
- `capmaster/plugins/match/ttl_utils.py` - TTL 跳数计算工具
- `test_match_endpoint_db.py` - 数据库写入测试

---

## 🎯 总结

网络设备节点数据库写入功能已成功实现，主要特点：

- ✅ 自动根据 hops 值插入网络设备节点
- ✅ 支持 type=1001（Client-Capture）和 type=1002（Capture-Server）
- ✅ 节点字段符合规范（ip/port/proto 为 NULL）
- ✅ 日志清晰显示网络设备信息
- ✅ 测试完整验证功能正确性

该功能为拓扑图可视化提供了完整的网络路径信息，有助于更好地理解网络结构和流量路径。

