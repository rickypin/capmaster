# first_time 和 last_time 时间戳数据流程

## 📊 数据流程概览

```
PCAP 文件 
    ↓
tshark 提取 (frame.time_epoch)
    ↓
TcpPacket.timestamp (float, 秒)
    ↓
packets_a[0].timestamp / packets_a[-1].timestamp
    ↓
to_nanoseconds() 转换
    ↓
first_time / last_time (int, 纳秒)
    ↓
数据库 (bigint)
```

---

## 🔍 详细数据流程

### 1️⃣ 源头：PCAP 文件

时间戳存储在 PCAP 文件的每个数据包头部中。

**PCAP 文件格式：**
- 每个数据包都有一个时间戳
- 精度：微秒级或纳秒级（取决于 PCAP 格式）
- 格式：Unix epoch 时间戳

---

### 2️⃣ 提取：tshark 工具

**位置：** `capmaster/plugins/compare/packet_extractor.py`

<augment_code_snippet path="capmaster/plugins/compare/packet_extractor.py" mode="EXCERPT">
```python
FIELDS = [
    "frame.number",      # Frame number
    "ip.id",            # IP identification
    "tcp.flags",        # TCP flags (hex)
    "tcp.seq",          # TCP sequence number (absolute)
    "tcp.ack",          # TCP acknowledgment number (absolute)
    "frame.time_epoch", # Timestamp ← 关键字段
]
```
</augment_code_snippet>

**tshark 命令：**
```bash
tshark -r input.pcap \
    -Y "tcp.stream==123" \
    -T fields \
    -e frame.time_epoch \
    ...
```

**frame.time_epoch 说明：**
- **格式：** 浮点数字符串
- **单位：** 秒（Unix epoch）
- **精度：** 取决于 PCAP 文件格式
  - 传统 PCAP：微秒精度（6 位小数）
  - PCAP-NG：纳秒精度（9 位小数）
- **示例：** `"1757441703.689601024"`

---

### 3️⃣ 解析：TcpPacket 对象

**位置：** `capmaster/plugins/compare/packet_extractor.py`

<augment_code_snippet path="capmaster/plugins/compare/packet_extractor.py" mode="EXCERPT">
```python
# 解析 tshark 输出
timestamp_str = fields[5].strip('"')  # 第 6 个字段

packet = TcpPacket(
    frame_number=frame_number,
    ip_id=int(ip_id_str, 16) if ip_id_str else 0,
    tcp_flags=tcp_flags,
    seq=int(seq_str) if seq_str else 0,
    ack=int(ack_str) if ack_str else 0,
    timestamp=Decimal(timestamp_str) if timestamp_str else Decimal('0'),  # ← 转换为 Decimal
)
```
</augment_code_snippet>

**TcpPacket.timestamp 字段：**
- **类型：** `Decimal` (修复后，原为 `float`)
- **单位：** 秒
- **精度：** 完整保留 tshark 提取的纳秒精度（使用 Decimal 避免浮点数精度丢失）
- **示例：** `Decimal('1757441703.689601150')`

---

### 4️⃣ 提取：获取第一个和最后一个数据包的时间戳

**位置：** `capmaster/plugins/compare/plugin.py`

<augment_code_snippet path="capmaster/plugins/compare/plugin.py" mode="EXCERPT">
```python
# Extract first_time and last_time from baseline packets (file1)
if packets_a:
    first_timestamp = packets_a[0].timestamp   # ← 第一个数据包的时间戳
    last_timestamp = packets_a[-1].timestamp   # ← 最后一个数据包的时间戳
```
</augment_code_snippet>

**说明：**
- `packets_a` 是一个 `TcpPacket` 列表，按时间顺序排列
- `packets_a[0]` 是该 TCP 流的第一个数据包
- `packets_a[-1]` 是该 TCP 流的最后一个数据包

---

### 5️⃣ 转换：秒 → 纳秒

**位置：** `capmaster/plugins/compare/plugin.py`

<augment_code_snippet path="capmaster/plugins/compare/plugin.py" mode="EXCERPT">
```python
first_time_ns = to_nanoseconds(first_timestamp)  # ← 转换为纳秒
last_time_ns = to_nanoseconds(last_timestamp)    # ← 转换为纳秒
```
</augment_code_snippet>

**to_nanoseconds() 函数：**
```python
def to_nanoseconds(timestamp_seconds: Decimal) -> int:
    """Convert timestamp from seconds to nanoseconds with full precision."""
    # 使用 Decimal 算术确保乘法过程中不丢失精度
    timestamp_nanoseconds = int(timestamp_seconds * Decimal('1000000000'))
    return timestamp_nanoseconds
```

**转换示例：**
- 输入：`Decimal('1757441703.689601150')` 秒
- 计算：`Decimal('1757441703.689601150') × Decimal('1000000000')`
- 输出：`1757441703689601150` 纳秒（完整保留精度）

---

### 6️⃣ 聚合：更新时间范围

**位置：** `capmaster/plugins/compare/plugin.py`

<augment_code_snippet path="capmaster/plugins/compare/plugin.py" mode="EXCERPT">
```python
# Update group's time range
if group['first_time'] is None or first_time_ns < group['first_time']:
    group['first_time'] = first_time_ns  # ← 取最早时间
if group['last_time'] is None or last_time_ns > group['last_time']:
    group['last_time'] = last_time_ns    # ← 取最晚时间
```
</augment_code_snippet>

**说明：**
- 如果一个 baseline stream 匹配了多个 compare streams
- 需要合并所有匹配的时间范围
- `first_time` 取所有匹配中最早的时间
- `last_time` 取所有匹配中最晚的时间

---

### 7️⃣ 存储：写入数据库

**位置：** `capmaster/plugins/compare/db_writer.py`

**数据库表结构：**
```sql
CREATE TABLE kase_XXX_tcp_stream_extra (
    pcap_id integer,
    flow_hash bigint,
    first_time bigint,  -- ← 纳秒时间戳
    last_time bigint,   -- ← 纳秒时间戳
    tcp_flags_different_cnt bigint,
    tcp_flags_different_type text,
    tcp_flags_different_text text,
    seq_num_different_cnt bigint,
    seq_num_different_text text,
    id integer NOT NULL
);
```

**插入数据：**
```python
batch_data.append((
    record['pcap_id'],
    record['flow_hash'],
    record.get('first_time'),   # ← int, 纳秒
    record.get('last_time'),    # ← int, 纳秒
    record.get('tcp_flags_different_cnt', 0),
    record.get('tcp_flags_different_type'),
    tcp_flags_text,
    record.get('seq_num_different_cnt', 0),
    seq_num_text,
))
```

---

## 📝 完整示例

### 示例数据流

假设有一个 TCP 流包含 3 个数据包：

```
Packet 1: frame.time_epoch = "1757441703.689601024"
Packet 2: frame.time_epoch = "1757441703.689602048"
Packet 3: frame.time_epoch = "1757441703.689603072"
```

**处理流程：**

1. **tshark 提取：**
   ```
   "1757441703.689601024"
   "1757441703.689602048"
   "1757441703.689603072"
   ```

2. **解析为 TcpPacket：**
   ```python
   packets_a[0].timestamp = 1757441703.689601024  # float
   packets_a[1].timestamp = 1757441703.689602048
   packets_a[2].timestamp = 1757441703.689603072
   ```

3. **提取首尾时间戳：**
   ```python
   first_timestamp = 1757441703.689601024  # packets_a[0]
   last_timestamp  = 1757441703.689603072  # packets_a[-1]
   ```

4. **转换为纳秒：**
   ```python
   first_time_ns = 1757441703689601024  # int
   last_time_ns  = 1757441703689603072  # int
   ```

5. **写入数据库：**
   ```sql
   INSERT INTO kase_XXX_tcp_stream_extra 
   VALUES (..., 1757441703689601024, 1757441703689603072, ...);
   ```

---

## 🎯 关键要点

### 时间戳来源

✅ **源头：** PCAP 文件中每个数据包的时间戳  
✅ **提取工具：** tshark 的 `frame.time_epoch` 字段  
✅ **原始格式：** 浮点数秒（Unix epoch）  
✅ **原始精度：** 取决于 PCAP 格式（微秒或纳秒）

### first_time 和 last_time 的含义

- **first_time：** TCP 流中**第一个数据包**的时间戳
- **last_time：** TCP 流中**最后一个数据包**的时间戳
- **时间范围：** `[first_time, last_time]` 表示该 TCP 流的持续时间

### 数据类型转换

```
PCAP 文件 → tshark → TcpPacket → to_nanoseconds() → 数据库
  (二进制)   (字符串)   (Decimal秒)    (int纳秒)      (bigint)
```

### 精度保证

- **修复前问题：** 使用 float 类型导致精度丢失（浮点数无法精确表示纳秒级精度）
- **修复后方案：** 使用 Decimal 类型保持完整纳秒精度
- **精度来源：** 取决于 PCAP 文件本身的精度（通常为纳秒级）
- **关键改进：** 从字符串解析时直接使用 Decimal，避免 float 的精度限制

---

## 🔧 验证方法

### 1. 查看 tshark 原始输出

```bash
tshark -r input.pcap -Y "tcp.stream==0" -T fields -e frame.time_epoch
```

### 2. 检查数据库中的时间戳

```sql
SELECT 
    first_time,
    last_time,
    first_time % 1000 as first_ns_digits,
    last_time % 1000 as last_ns_digits,
    (last_time - first_time) / 1000000000.0 as duration_seconds
FROM kase_XXX_tcp_stream_extra
LIMIT 10;
```

### 3. 验证精度

- 如果 `first_ns_digits` 和 `last_ns_digits` 不全是 0，说明保留了纳秒精度
- 如果全是 0，说明原始 PCAP 文件只有微秒精度

---

**文档创建日期：** 2025-11-12  
**相关文档：** TIMESTAMP_PRECISION_CHANGE.md

