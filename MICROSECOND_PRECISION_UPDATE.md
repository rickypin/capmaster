# Compare Plugin 时间戳精度调整

## 修改概述

对 compare 插件的 first time 和 last time 机制进行了精度调整，将时间戳从纳秒精度四舍五入到微秒精度。

## 修改详情

### 精度变化

- **之前**: 纳秒精度（19位数字，最后3位可能是任意值）
- **之后**: 微秒精度（19位数字，最后3位固定为000）

### 示例

```
修改前: 1757441703689601024
修改后: 1757441703689601000

修改前: 1757445296366606848
修改后: 1757445296366607000
```

### 关键特性

✅ **输出格式不变**: 仍然是19位数字  
✅ **位数不变**: 保持与之前相同的位数  
✅ **四舍五入**: 使用标准的四舍五入规则到微秒  
✅ **精度**: 微秒级精度（最后3位为000）  

## 实现方式

### 新增函数

在 `capmaster/plugins/compare/plugin.py` 中添加了 `round_to_microseconds()` 函数：

```python
def round_to_microseconds(timestamp_seconds: float) -> int:
    """
    Convert timestamp from seconds to nanoseconds and round to microsecond precision.
    
    Args:
        timestamp_seconds: Unix timestamp in seconds (float)
    
    Returns:
        Timestamp in nanoseconds (int), rounded to microsecond precision
        
    Example:
        Input:  1.757441703689601024 seconds
        Output: 1757441703689601000 nanoseconds (rounded to nearest microsecond)
    """
    # Convert to microseconds first, round, then convert to nanoseconds
    timestamp_microseconds = round(timestamp_seconds * 1_000_000)
    timestamp_nanoseconds = timestamp_microseconds * 1_000
    return timestamp_nanoseconds
```

### 修改位置

该函数在以下三个位置被使用：

1. **控制台输出 - Baseline packets** (第 578-585 行)
   ```python
   if packets_a:
       first_time_ns = round_to_microseconds(packets_a[0].timestamp)
       last_time_ns = round_to_microseconds(packets_a[-1].timestamp)
   ```

2. **控制台输出 - Compare packets** (第 623-630 行)
   ```python
   if packets_b:
       first_time_ns = round_to_microseconds(packets_b[0].timestamp)
       last_time_ns = round_to_microseconds(packets_b[-1].timestamp)
   ```

3. **数据库写入** (第 821-832 行)
   ```python
   if packets_a:
       first_time = round_to_microseconds(first_timestamp)
       last_time = round_to_microseconds(last_timestamp)
   ```

## 四舍五入逻辑

### 算法

1. 将秒级时间戳转换为微秒：`timestamp_seconds * 1_000_000`
2. 对微秒值进行四舍五入：`round(timestamp_microseconds)`
3. 将微秒转换为纳秒：`timestamp_microseconds * 1_000`

### 示例计算

```python
# 示例 1
原始纳秒: 1757441703689601024
原始秒:   1757441703.689601024
微秒:     1757441703689601.024
四舍五入: 1757441703689601 (舍去 .024)
结果纳秒: 1757441703689601000

# 示例 2
原始纳秒: 1757445296366606848
原始秒:   1757445296.366606848
微秒:     1757445296366606.848
四舍五入: 1757445296366607 (进位 .848 → 1)
结果纳秒: 1757445296366607000
```

## 测试验证

### 单元测试

创建了 `test_microsecond_rounding.py` 测试脚本，验证：

- ✅ 用户提供的示例值正确转换
- ✅ 向下舍入场景（< 0.5 纳秒）
- ✅ 向上舍入场景（≥ 0.5 纳秒）
- ✅ 精确微秒值保持不变
- ✅ 输出格式保持19位数字

### 集成测试

更新了 `test_timestamp_feature.py`，增加了微秒精度验证：

```python
# 检查所有时间戳的最后3位是否为000
for ts in timestamps:
    ts_int = int(ts)
    if ts_int % 1000 == 0:
        microsecond_precision_count += 1
```

## 影响范围

### 受影响的功能

1. **控制台输出**: First Time 和 Last Time 列显示的值
2. **数据库写入**: `first_time` 和 `last_time` 字段的值
3. **时间戳精度**: 从纳秒级降低到微秒级

### 不受影响的功能

1. **输出格式**: 仍然是19位数字
2. **数据类型**: 仍然是 bigint
3. **时间范围**: 仍然可以表示相同的时间范围
4. **兼容性**: 与现有数据库查询完全兼容

## 使用示例

### 基本用法

```bash
python -m capmaster compare \
  --file1 cases/TC-001-1-20160407/TC-001-1-20160407-A.pcap \
  --file1-pcapid 0 \
  --file2 cases/TC-001-1-20160407/TC-001-1-20160407-B.pcap \
  --file2-pcapid 1 \
  --show-flow-hash
```

输出示例：
```
First Time           Last Time
1459996923372072000  1459996923372073000
```

注意最后3位都是 `000`。

### 数据库查询

```sql
-- 查看时间戳（微秒精度）
SELECT 
    pcap_id,
    flow_hash,
    first_time,
    last_time,
    first_time % 1000 as first_time_last_3_digits,  -- 应该是 0
    last_time % 1000 as last_time_last_3_digits     -- 应该是 0
FROM public.kase_133_tcp_stream_extra
ORDER BY id DESC LIMIT 5;

-- 转换为可读格式（精度仍然正确）
SELECT 
    pcap_id,
    flow_hash,
    to_timestamp(first_time / 1000000000.0) as first_time_readable,
    to_timestamp(last_time / 1000000000.0) as last_time_readable,
    (last_time - first_time) / 1000000.0 as duration_microseconds
FROM public.kase_133_tcp_stream_extra
ORDER BY id DESC LIMIT 5;
```

## 技术细节

### 精度损失

- **最大误差**: ±500 纳秒
- **相对误差**: 对于典型的时间戳值（秒级），相对误差 < 0.0000001%
- **实际影响**: 对于网络数据包分析，微秒级精度已经足够

### 性能影响

- **计算开销**: 可忽略不计（仅增加一次乘法和一次四舍五入）
- **存储空间**: 无变化（仍然是 bigint）
- **查询性能**: 无变化

## 向后兼容性

### 数据库

- ✅ 与现有数据库表结构完全兼容
- ✅ 现有查询无需修改
- ✅ 可以与旧数据混合存储

### 代码

- ✅ 不影响其他插件
- ✅ 不影响现有的时间戳处理逻辑
- ✅ 测试用例已更新

## 总结

成功将 compare 插件的时间戳精度从纳秒调整到微秒：

✅ 输出格式和位数保持不变（19位数字）  
✅ 使用标准四舍五入到微秒精度  
✅ 最后3位固定为000  
✅ 通过了所有测试验证  
✅ 完全向后兼容  
✅ 对性能无明显影响  

该修改已经可以投入生产使用。

