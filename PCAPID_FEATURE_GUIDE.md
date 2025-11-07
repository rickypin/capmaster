# Compare Plugin - PCAP ID 功能使用指南

## 概述

compare 插件已增强，支持在连接数据库时为每个 PCAP 文件指定 `pcap_id`。这个功能允许用户在写入数据库时，根据文件与 `pcap_id` 的映射关系，将正确的 `pcap_id` 值写入数据库表中。

## 新增参数

### 命令行参数

- `--file1` - 第一个 PCAP 文件路径（baseline 文件）
- `--file1-pcapid` - file1 对应的 pcap_id（必须是 0 或 1）
- `--file2` - 第二个 PCAP 文件路径（compare 文件）
- `--file2-pcapid` - file2 对应的 pcap_id（必须是 0 或 1）

### 参数规则

1. **互斥性**: 不能同时使用 `-i/--input` 和 `--file1/--file2` 参数
2. **完整性**: 使用 `--file1/--file2` 时，必须同时提供所有四个参数（file1, file1-pcapid, file2, file2-pcapid）
3. **取值范围**: `pcap_id` 的值必须是 0 或 1
4. **向后兼容**: 原有的 `-i/--input` 参数仍然可用，默认使用 `pcap_id=0`

## 使用示例

### 示例 1: 基本用法

```bash
capmaster compare \
  --file1 a.pcap \
  --file1-pcapid 0 \
  --file2 b.pcap \
  --file2-pcapid 1 \
  --show-flow-hash
```

**说明**: 
- `a.pcap` 作为 baseline 文件，pcap_id 为 0
- `b.pcap` 作为 compare 文件，pcap_id 为 1
- 写入数据库时，使用 file1 的 pcap_id（即 0）

### 示例 2: 反向映射

```bash
capmaster compare \
  --file1 b.pcap \
  --file1-pcapid 1 \
  --file2 a.pcap \
  --file2-pcapid 0 \
  --show-flow-hash
```

**说明**:
- `b.pcap` 作为 baseline 文件，pcap_id 为 1
- `a.pcap` 作为 compare 文件，pcap_id 为 0
- 写入数据库时，使用 file1 的 pcap_id（即 1）

### 示例 3: 写入数据库

```bash
capmaster compare \
  --file1 a.pcap \
  --file1-pcapid 0 \
  --file2 b.pcap \
  --file2-pcapid 1 \
  --show-flow-hash \
  --db-connection "postgresql://postgres:password@172.16.200.156:5433/r2" \
  --kase-id 133
```

**说明**:
- 比较结果会写入数据库表 `public.kase_133_tcp_stream_extra`
- 每条记录的 `pcap_id` 字段值为 0（来自 file1）

### 示例 4: 传统方式（向后兼容）

```bash
capmaster compare \
  -i "a.pcap,b.pcap" \
  --show-flow-hash \
  --db-connection "postgresql://postgres:password@172.16.200.156:5433/r2" \
  --kase-id 133
```

**说明**:
- 使用传统的 `-i` 参数
- 写入数据库时，默认使用 `pcap_id=0`

## 数据库写入逻辑

### PCAP ID 的确定

1. **使用新参数时**: 使用 `--file1-pcapid` 的值
2. **使用传统参数时**: 默认使用 0

### 时间戳的提取

1. **first_time**: TCP 连接的首包时间戳（来自 file1 的第一个数据包）
2. **last_time**: TCP 连接的尾包时间戳（来自 file1 的最后一个数据包）
3. **格式**: Unix 时间戳，纳秒级精度（19 位数字）
4. **示例**: `1459996923372072960` 表示 2016-04-07 10:42:03.372072960

### 数据库表结构

写入的表结构为 `public.kase_{kase_id}_tcp_stream_extra`，包含以下字段：

```sql
CREATE TABLE public.kase_133_tcp_stream_extra (
    pcap_id integer,                        -- 来自 file1 的 pcap_id
    flow_hash bigint,                       -- 流哈希值
    first_time bigint,                      -- 首包时间戳（纳秒），来自 file1
    last_time bigint,                       -- 末包时间戳（纳秒），来自 file1
    tcp_flags_different_cnt bigint,         -- TCP flags 差异数量
    tcp_flags_different_type text,          -- TCP flags 变化类型
    tcp_flags_different_text text[],        -- TCP flags 差异详情
    seq_num_different_cnt bigint,           -- 序列号差异数量
    seq_num_different_text text[],          -- 序列号差异详情
    id integer NOT NULL PRIMARY KEY         -- 自增主键
);
```

### 验证数据

写入数据库后，可以使用以下 SQL 查询验证：

```sql
-- 查看最近写入的记录（包含时间戳）
SELECT pcap_id, flow_hash, first_time, last_time, tcp_flags_different_cnt, seq_num_different_cnt
FROM public.kase_133_tcp_stream_extra
ORDER BY id DESC
LIMIT 5;

-- 按 pcap_id 分组统计
SELECT pcap_id, COUNT(*) as record_count
FROM public.kase_133_tcp_stream_extra
GROUP BY pcap_id;

-- 验证时间戳格式（转换为可读格式）
SELECT
    pcap_id,
    flow_hash,
    first_time,
    last_time,
    to_timestamp(first_time / 1000000000.0) as first_time_readable,
    to_timestamp(last_time / 1000000000.0) as last_time_readable,
    (last_time - first_time) / 1000000000.0 as duration_seconds
FROM public.kase_133_tcp_stream_extra
ORDER BY id DESC
LIMIT 5;
```

## 参数验证

插件会进行以下验证：

1. ✅ 不能同时使用 `-i` 和 `--file1/--file2`
2. ✅ 使用 `--file1/--file2` 时，必须提供所有四个参数
3. ✅ `pcap_id` 必须是 0 或 1
4. ✅ 使用数据库输出时，必须同时提供 `--db-connection` 和 `--kase-id`
5. ✅ 使用数据库输出时，必须启用 `--show-flow-hash`

### 错误示例

```bash
# 错误：缺少 pcap_id
capmaster compare --file1 a.pcap --file2 b.pcap --show-flow-hash
# Error: Both --file1-pcapid and --file2-pcapid must be provided when using --file1/--file2

# 错误：pcap_id 值无效
capmaster compare --file1 a.pcap --file1-pcapid 2 --file2 b.pcap --file2-pcapid 0
# Error: --file1-pcapid must be 0 or 1

# 错误：同时使用两种输入方式
capmaster compare -i "a.pcap,b.pcap" --file1 a.pcap --file1-pcapid 0
# Error: Cannot use both -i/--input and --file1/--file2 at the same time
```

## 日志输出

使用新参数时，日志会显示 PCAP ID 映射信息：

```
INFO     Baseline file: a.pcap
INFO     Compare file: b.pcap
INFO     Comparison direction: b.pcap relative to a.pcap
INFO     PCAP ID mapping: a.pcap -> 0, b.pcap -> 1
INFO     Writing results to database (kase_id=133)...
INFO     Using pcap_id=0 from file1 (a.pcap)
```

## 测试

运行测试脚本验证功能：

```bash
python test_pcapid_feature.py
```

测试脚本会验证：
- ✅ 新参数的基本功能
- ✅ 反向映射功能
- ✅ 向后兼容性
- ✅ 参数验证逻辑

## 总结

新的 PCAP ID 功能提供了更灵活的方式来指定文件与 pcap_id 的映射关系，特别适用于需要将比较结果写入数据库的场景。同时，该功能完全向后兼容，不影响现有的使用方式。

### 关键要点

1. **file1 决定 pcap_id**: 写入数据库时，使用 file1 的 pcap_id 值
2. **灵活映射**: 可以根据需要自由指定哪个文件对应哪个 pcap_id
3. **向后兼容**: 原有的 `-i` 参数仍然可用
4. **严格验证**: 参数验证确保使用正确

