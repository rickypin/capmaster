# 网络跳数功能使用指南

## 快速开始

### 1. 查看端点统计（包含跳数信息）

```bash
python -m capmaster match -i <pcap_directory> --endpoint-stats
```

**示例：**
```bash
python -m capmaster match -i cases_02/TC-002-5-20220215-O/ --endpoint-stats
```

**输出示例：**
```
[1] Count: 5 | Confidence: HIGH
    File A: Client 192.168.1.100 → Server 10.0.0.50:80 (TCP)
            TTL: Client=64 (hops=0), Server=60 (hops=4)
    File B: Client 172.16.0.200 → Server 10.0.0.51:80 (TCP)
            TTL: Client=128 (hops=0), Server=120 (hops=8)
```

**解读：**
- `hops=0`: 抓包点就在该节点上（直接连接）
- `hops=4`: 该节点与抓包点之间有 4 个路由器

---

### 2. 写入数据库（包含网络设备节点）

```bash
python -m capmaster match \
  -i <pcap_directory> \
  --endpoint-stats \
  --db-connection "postgresql://user:password@host:port/database" \
  --kase-id <kase_id>
```

**示例：**
```bash
python -m capmaster match \
  -i cases_02/TC-002-5-20220215-O/ \
  --endpoint-stats \
  --db-connection "postgresql://postgres:password@172.16.200.156:5433/r2" \
  --kase-id 137
```

**数据库节点类型：**
- `type=1`: 客户端节点
- `type=2`: 服务端节点
- `type=1001`: 客户端到抓包点的网络设备
- `type=1002`: 抓包点到服务器的网络设备

---

## 功能演示

### 运行完整演示

```bash
python demo_hops_and_db.py
```

**演示内容：**
1. TTL 到跳数的转换
2. TTL 分析示例
3. 端点统计输出（详细格式和表格格式）
4. 数据库节点结构说明

---

## 测试

### 单元测试

```bash
python test_hops_feature.py
```

**测试内容：**
- TTL delta 计算
- 跳数计算函数
- 最常见跳数统计
- TTL 信息综合分析
- 端点统计数据结构

### 集成测试

```bash
python test_hops_integration.py
```

**测试内容：**
- 端点统计收集完整流程
- 详细格式和表格格式输出
- 跳数信息验证

### 数据库测试

```bash
python test_match_endpoint_db.py
```

**测试内容：**
- 数据库连接
- 端点统计写入
- 网络设备节点插入
- 数据验证

---

## 核心概念

### TTL 与网络跳数

**TTL (Time To Live)** 是 IP 包头中的一个字段，每经过一个路由器就会减 1。

**计算公式：**
```
网络跳数 = 初始 TTL - 观察到的 TTL
```

**标准初始 TTL 值：**
- Linux/Unix: 64
- Windows: 128
- 网络设备: 255

**示例：**
- 观察到 TTL=60，初始 TTL=64 → 跳数=4（经过 4 个路由器）
- 观察到 TTL=64，初始 TTL=64 → 跳数=0（直接连接）

### 网络设备节点

当跳数不为 0 时，表示存在网络设备（如路由器）。系统会在数据库中插入相应的网络设备节点：

- **type=1001**: 客户端与抓包点之间的网络设备
- **type=1002**: 抓包点与服务器之间的网络设备

**节点特征：**
- `ip`: NULL
- `port`: NULL
- `proto`: NULL
- `display_name`: 包含跳数信息，如 "Network Device (Capture-Server, 4 hops)"

---

## 输出格式

### 详细格式

每个端点对显示完整的 TTL 和跳数信息：

```
[1] Count: 5 | Confidence: HIGH
    File A: Client 192.168.1.100 → Server 10.0.0.50:80 (TCP)
            TTL: Client=64 (hops=0), Server=60 (hops=4)
    File B: Client 172.16.0.200 → Server 10.0.0.51:80 (TCP)
            TTL: Client=128 (hops=0), Server=120 (hops=8)
```

### 表格格式

紧凑的表格显示，便于快速浏览：

```
Client IP (A)   | Server IP (A)   | Port (A) | TTL A (C/S)  | Hops A (C/S)  | ...
----------------------------------------------------------------------------------
192.168.1.100   | 10.0.0.50       | 80       | 64/60        | 0/4           | ...
192.168.1.102   | 10.0.0.54       | 22       | 61/58        | 3/6           | ...
```

**列说明：**
- `TTL A (C/S)`: File A 的客户端/服务端 TTL
- `Hops A (C/S)`: File A 的客户端/服务端跳数

---

## 数据库查询示例

### 查询所有网络设备节点

```sql
SELECT * FROM public.kase_137_topological_graph
WHERE type IN (1001, 1002)
ORDER BY group_id, pcap_id;
```

### 统计每个 group 的网络设备数量

```sql
SELECT group_id, COUNT(*) as device_count
FROM public.kase_137_topological_graph
WHERE type IN (1001, 1002)
GROUP BY group_id;
```

### 查询特定 group 的完整拓扑

```sql
SELECT 
    pcap_id,
    CASE 
        WHEN type = 1 THEN 'Client'
        WHEN type = 2 THEN 'Server'
        WHEN type = 1001 THEN 'NetDevice(Client-Capture)'
        WHEN type = 1002 THEN 'NetDevice(Capture-Server)'
    END as node_type,
    ip,
    port,
    display_name
FROM public.kase_137_topological_graph
WHERE group_id = 1
ORDER BY pcap_id, type;
```

---

## 应用场景

### 1. 网络拓扑分析

通过跳数信息了解网络结构：
- 判断是否存在中间网络设备
- 估算网络路径长度
- 可视化网络拓扑

### 2. 流量方向判断

结合跳数信息提高匹配准确性：
- 辅助判断流量的真实来源和目的地
- 识别对称和非对称路由

### 3. 异常检测

监控 TTL 值的变化：
- 网络路径改变
- 可能的 TTL 欺骗攻击

### 4. 性能分析

跳数与网络延迟的关系：
- 跳数越多，延迟通常越大
- 识别性能瓶颈

---

## 常见问题

### Q1: 为什么有些连接的 TTL 为 0？

**A:** TTL=0 表示该连接没有收集到 TTL 信息，可能原因：
- 只分析了包头（header-only 模式）
- PCAP 文件中没有该方向的数据包

### Q2: 为什么同一个端点对的 TTL 值会变化？

**A:** 可能原因：
- 负载均衡导致路径变化
- 网络路由动态调整
- 使用了"最常见"跳数来处理这种变化

### Q3: 网络设备节点的 IP 为什么是 NULL？

**A:** 网络设备节点是虚拟节点，用于表示网络路径中的中间设备，不对应具体的 IP 地址。跳数信息保存在 `display_name` 字段中。

### Q4: 如何判断抓包点的位置？

**A:** 通过跳数信息：
- 如果客户端 hops=0，抓包点在客户端侧
- 如果服务端 hops=0，抓包点在服务端侧
- 如果两者都不为 0，抓包点在中间某处

---

## 详细文档

- **[HOPS_FEATURE_SUMMARY.md](HOPS_FEATURE_SUMMARY.md)** - 路由跳数功能详细说明
- **[NETWORK_DEVICE_DB_FEATURE.md](NETWORK_DEVICE_DB_FEATURE.md)** - 网络设备节点数据库功能
- **[FINAL_SUMMARY.md](FINAL_SUMMARY.md)** - 完整功能总结

---

## 技术支持

如有问题或建议，请参考：
1. 运行演示脚本：`python demo_hops_and_db.py`
2. 查看测试用例：`test_hops_feature.py`, `test_hops_integration.py`
3. 阅读详细文档（见上方链接）

---

**功能状态：** ✅ 已完成并通过测试  
**版本：** 1.0  
**更新时间：** 2025-11-10

