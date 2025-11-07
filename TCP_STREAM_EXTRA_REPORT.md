# TCP Stream Extra 表查询报告

**数据库**: `postgresql://postgres:password@172.16.200.156:5433/r2`  
**查询时间**: 2025-11-07  
**状态**: ✅ 只读查询，未做任何修改

---

## 📋 查询结果摘要

找到 **1 个**包含 `tcp_stream_extra` 的表：
- `public.kase_134_tcp_stream_extra`

---

## 🗂️ 表结构详情

### 表名: `public.kase_134_tcp_stream_extra`

#### 列定义

| 列名 | 数据类型 | 可空 | 默认值 | 说明 |
|------|---------|------|--------|------|
| `pcap_id` | integer | YES | - | PCAP 文件 ID |
| `flow_hash` | bigint | YES | - | 流哈希值 |
| `first_time` | bigint | YES | - | 首次出现时间（纳秒时间戳） |
| `last_time` | bigint | YES | - | 最后出现时间（纳秒时间戳） |
| `tcp_flags_different_cnt` | bigint | YES | - | TCP 标志不同计数 |
| `tcp_flags_different_text` | ARRAY | YES | - | TCP 标志不同文本数组 |
| `seq_num_different_cnt` | bigint | YES | - | 序列号不同计数 |
| `seq_num_different_text` | ARRAY | YES | - | 序列号不同文本数组 |
| `id` | integer | NO | nextval(...) | 主键 ID（自增） |

#### 约束和索引
- **索引**: 无
- **约束**: 无（无主键约束、外键约束或唯一约束定义）

---

## 📊 数据内容

### 总体统计
- **总记录数**: 2
- **唯一 PCAP ID**: 2
- **唯一流哈希**: 2
- **时间范围**: 2021-09-01 15:41:10 ~ 2021-09-01 16:18:07
- **TCP 标志差异总数**: 0
- **序列号差异总数**: 0

### 详细记录

#### 记录 #1
```
ID                : 1
PCAP ID           : 1
Flow Hash         : 3529052843383331713
First Time        : 1630484287036468000 (2021-09-01 16:18:07.036468)
Last Time         : 1630484287106489000 (2021-09-01 16:18:07.106489)
Duration          : 70.021 ms
TCP Flags Diff    : None (空数组)
Seq Num Diff      : None (空数组)
```

#### 记录 #2
```
ID                : 2
PCAP ID           : 0
Flow Hash         : 5917182497427312977
First Time        : 1630482070018110000 (2021-09-01 15:41:10.018110)
Last Time         : 1630482070049663000 (2021-09-01 15:41:10.049663)
Duration          : 31.553 ms
TCP Flags Diff    : None (空数组)
Seq Num Diff      : None (空数组)
```

---

## 🔗 相关表信息

在 `kase_134` 系列中找到 4 个相关表：

| 表名 | 行数 | 说明 |
|------|------|------|
| `kase_134_tcp_stream` | 1,654 | TCP 流主表 |
| `kase_134_tcp_stream_extra` | 2 | TCP 流额外信息表（当前表） |
| `kase_134_tls_stream` | 61 | TLS 流表 |
| `kase_134_topological_graph` | 66 | 拓扑图表 |

---

## 💡 数据分析

### 观察结果

1. **表用途**: 该表似乎用于存储 TCP 流的额外分析信息，特别是：
   - TCP 标志的差异
   - 序列号的差异

2. **当前状态**: 
   - 表中只有 2 条记录
   - 所有差异计数字段都为 `None`
   - 所有差异文本数组都为空 `[]`
   - 这表明这两个流没有检测到异常或差异

3. **时间特征**:
   - 两条记录来自不同的 PCAP 文件（pcap_id: 0 和 1）
   - 时间跨度约 37 分钟
   - 流持续时间都很短（31-70 毫秒）

4. **数据完整性**:
   - 表没有定义主键约束（虽然有 id 字段）
   - 没有索引，可能影响查询性能
   - 没有外键约束，与其他表的关系不明确

### 可能的用途

该表可能用于：
- 存储跨 PCAP 文件的 TCP 流比对结果
- 记录 TCP 流中的异常或不一致情况
- 支持网络流量分析和异常检测

---

## 📝 查询脚本

已创建以下查询脚本供后续使用：

1. **`query_tcp_stream_extra.py`** - 基础查询脚本
   - 查找所有包含 `tcp_stream_extra` 的表
   - 显示表结构、内容、索引和约束

2. **`detailed_tcp_stream_extra.py`** - 详细分析脚本
   - 格式化显示时间戳
   - 计算流持续时间
   - 显示统计摘要
   - 列出相关表

---

## ✅ 确认

- ✅ 已完成数据库连接测试
- ✅ 已查找到包含 `tcp_stream_extra` 的表
- ✅ 已显示完整表结构
- ✅ 已显示所有数据内容
- ✅ **未对数据库做任何修改**（只读查询）

---

*报告生成完毕*

