# Compare Plugin 使用示例

## 基本用法

### 1. 简单比较（不写入数据库）

```bash
capmaster compare \
  --file1 cases/TC-001-1-20160407/TC-001-1-20160407-A.pcap \
  --file1-pcapid 0 \
  --file2 cases/TC-001-1-20160407/TC-001-1-20160407-B.pcap \
  --file2-pcapid 1 \
  --show-flow-hash
```

**输出示例**:
```
============================================================================================================================================
Matched TCP Connections in Baseline File (TC-001-1-20160407-A.pcap)
============================================================================================================================================
No.    Stream ID    Client IP:Port            Server IP:Port            Packets    First Time             Last Time              Flow Hash
--------------------------------------------------------------------------------------------------------------------------------------------
1      1            17.17.17.45:39765         10.30.50.101:6096         10         1459996923372072960    1459996923780258816    -3891428816203311885 (RHS>LHS)
2      3            17.17.17.45:36210         10.30.50.101:6096         10         1459997031469233920    1459997031829894912    -6586772909280826219 (RHS>LHS)
```

### 2. 单行命令格式

```bash
capmaster compare --file1 cases/dbs_20251028-Masked/B_processed.pcap --file1-pcapid 1 --file2 cases/dbs_20251028-Masked/A_processed.pcap --file2-pcapid 0 --show-flow-hash --matched-only
```

### 3. 写入数据库

```bash
capmaster compare \
  --file1 cases/dbs_20251028-Masked/B_processed.pcap \
  --file1-pcapid 1 \
  --file2 cases/dbs_20251028-Masked/A_processed.pcap \
  --file2-pcapid 0 \
  --show-flow-hash \
  --matched-only \
  --db-connection "postgresql://postgres:password@172.16.200.156:5433/r2" \
  --kase-id 133
```

**数据库记录示例**:
```
pcap_id | flow_hash            | first_time          | last_time           | tcp_flags_different_cnt
--------|----------------------|---------------------|---------------------|------------------------
1       | -3891428816203311885 | 1459996923372072960 | 1459996923780258816 | 5
```

## 高级用法

### 4. 反向映射（交换 baseline 和 compare）

```bash
capmaster compare \
  --file1 cases/TC-001-1-20160407/TC-001-1-20160407-B.pcap \
  --file1-pcapid 1 \
  --file2 cases/TC-001-1-20160407/TC-001-1-20160407-A.pcap \
  --file2-pcapid 0 \
  --show-flow-hash
```

**说明**: 
- B.pcap 作为 baseline（file1），pcap_id=1
- A.pcap 作为 compare（file2），pcap_id=0
- 数据库中写入的 pcap_id 为 1（来自 file1）

### 5. 只比较匹配的数据包

```bash
capmaster compare \
  --file1 a.pcap \
  --file1-pcapid 0 \
  --file2 b.pcap \
  --file2-pcapid 1 \
  --show-flow-hash \
  --matched-only
```

**说明**: `--matched-only` 参数只比较在两个文件中都存在且 IPID 匹配的数据包

### 6. 传统方式（向后兼容）

```bash
capmaster compare \
  -i "cases/TC-001-1-20160407/TC-001-1-20160407-A.pcap,cases/TC-001-1-20160407/TC-001-1-20160407-B.pcap" \
  --show-flow-hash
```

**说明**: 
- 使用传统的 `-i` 参数
- 数据库中写入的 pcap_id 默认为 0
- first_time 和 last_time 来自第一个文件

## 数据库查询示例

### 查看最近写入的记录

```sql
SELECT 
    pcap_id, 
    flow_hash, 
    first_time, 
    last_time, 
    tcp_flags_different_cnt,
    seq_num_different_cnt
FROM public.kase_133_tcp_stream_extra 
ORDER BY id DESC 
LIMIT 10;
```

### 转换时间戳为可读格式

```sql
SELECT 
    pcap_id,
    flow_hash,
    to_timestamp(first_time / 1000000000.0) as first_time_readable,
    to_timestamp(last_time / 1000000000.0) as last_time_readable,
    (last_time - first_time) / 1000000000.0 as duration_seconds,
    tcp_flags_different_cnt
FROM public.kase_133_tcp_stream_extra
ORDER BY id DESC 
LIMIT 10;
```

**输出示例**:
```
pcap_id | flow_hash            | first_time_readable      | last_time_readable       | duration_seconds | tcp_flags_different_cnt
--------|----------------------|--------------------------|--------------------------|------------------|------------------------
1       | -3891428816203311885 | 2016-04-07 10:42:03.372  | 2016-04-07 10:42:03.780  | 0.408            | 5
```

### 按 pcap_id 分组统计

```sql
SELECT 
    pcap_id, 
    COUNT(*) as connection_count,
    SUM(tcp_flags_different_cnt) as total_tcp_flags_diffs,
    SUM(seq_num_different_cnt) as total_seq_num_diffs
FROM public.kase_133_tcp_stream_extra
GROUP BY pcap_id
ORDER BY pcap_id;
```

### 查找特定时间范围的连接

```sql
SELECT 
    pcap_id,
    flow_hash,
    to_timestamp(first_time / 1000000000.0) as first_time_readable,
    tcp_flags_different_cnt
FROM public.kase_133_tcp_stream_extra
WHERE first_time >= 1459996900000000000  -- 2016-04-07 10:41:40
  AND first_time <= 1459997000000000000  -- 2016-04-07 10:43:20
ORDER BY first_time;
```

### 查找持续时间最长的连接

```sql
SELECT 
    pcap_id,
    flow_hash,
    (last_time - first_time) / 1000000000.0 as duration_seconds,
    to_timestamp(first_time / 1000000000.0) as first_time_readable,
    tcp_flags_different_cnt
FROM public.kase_133_tcp_stream_extra
ORDER BY duration_seconds DESC
LIMIT 10;
```

## 参数说明

### 必需参数组合

#### 方式 1: 使用 --file1/--file2
- `--file1`: 第一个 PCAP 文件（baseline）
- `--file1-pcapid`: file1 的 pcap_id（0 或 1）
- `--file2`: 第二个 PCAP 文件（compare）
- `--file2-pcapid`: file2 的 pcap_id（0 或 1）

#### 方式 2: 使用 -i（传统方式）
- `-i` 或 `--input`: 逗号分隔的两个 PCAP 文件

**注意**: 不能同时使用两种方式

### 可选参数

- `--show-flow-hash`: 显示和计算 flow hash（写入数据库时必需）
- `--matched-only`: 只比较匹配的数据包
- `--db-connection`: 数据库连接字符串
- `--kase-id`: 案例 ID（用于数据库表名）

### 数据库参数要求

写入数据库时必须同时提供：
1. `--show-flow-hash`
2. `--db-connection`
3. `--kase-id`

## 常见场景

### 场景 1: 网络设备前后抓包对比

```bash
# 设备前抓包 pcap_id=0，设备后抓包 pcap_id=1
capmaster compare \
  --file1 before_device.pcap \
  --file1-pcapid 0 \
  --file2 after_device.pcap \
  --file2-pcapid 1 \
  --show-flow-hash \
  --db-connection "postgresql://postgres:password@172.16.200.156:5433/r2" \
  --kase-id 133
```

### 场景 2: 不同时间段的流量对比

```bash
# 正常时段 pcap_id=0，异常时段 pcap_id=1
capmaster compare \
  --file1 normal_traffic.pcap \
  --file1-pcapid 0 \
  --file2 abnormal_traffic.pcap \
  --file2-pcapid 1 \
  --show-flow-hash \
  --matched-only \
  --db-connection "postgresql://postgres:password@172.16.200.156:5433/r2" \
  --kase-id 134
```

### 场景 3: 快速查看差异（不写数据库）

```bash
capmaster compare \
  --file1 a.pcap \
  --file1-pcapid 0 \
  --file2 b.pcap \
  --file2-pcapid 1 \
  --show-flow-hash
```

## 时间戳说明

### 格式
- **类型**: 64 位整数
- **单位**: 纳秒（nanoseconds）
- **长度**: 19 位数字
- **示例**: `1459996923372072960`

### 转换方法

#### Python
```python
timestamp_ns = 1459996923372072960
timestamp_s = timestamp_ns / 1_000_000_000

from datetime import datetime
dt = datetime.fromtimestamp(timestamp_s)
print(dt)  # 2016-04-07 10:42:03.372073
```

#### PostgreSQL
```sql
SELECT to_timestamp(1459996923372072960 / 1000000000.0);
-- 结果: 2016-04-07 10:42:03.372073+00
```

## 故障排查

### 错误: "Both --file1-pcapid and --file2-pcapid must be provided"

**原因**: 使用了 --file1/--file2 但没有提供 pcapid

**解决**: 同时提供所有四个参数
```bash
--file1 a.pcap --file1-pcapid 0 --file2 b.pcap --file2-pcapid 1
```

### 错误: "--file1-pcapid must be 0 or 1"

**原因**: pcapid 值不是 0 或 1

**解决**: 使用正确的值
```bash
--file1-pcapid 0  # 或 1
```

### 错误: "Cannot use both -i/--input and --file1/--file2"

**原因**: 同时使用了两种输入方式

**解决**: 只使用一种方式
```bash
# 方式 1
--file1 a.pcap --file1-pcapid 0 --file2 b.pcap --file2-pcapid 1

# 或方式 2
-i "a.pcap,b.pcap"
```

## 总结

compare 插件现在支持：
- ✅ 灵活的 pcap_id 映射
- ✅ 纳秒级时间戳提取和显示
- ✅ 数据库集成（pcap_id + 时间戳）
- ✅ 向后兼容传统用法
- ✅ 完善的参数验证

