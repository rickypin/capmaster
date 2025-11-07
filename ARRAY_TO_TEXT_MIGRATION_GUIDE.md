# 数组字段改为文本字段迁移指南

## 📋 概述

本次修改将 `kase_***_tcp_stream_extra` 表中的两个字段从数组类型改为文本类型：

- `tcp_flags_different_text`: `text[]` → `text`
- `seq_num_different_text`: `text[]` → `text`

## 🎯 修改原因

将数组字段改为文本字段，使用分号（`;`）作为分隔符连接多个值，简化数据存储和查询。

## 📝 修改内容

### 1. 数据库表结构修改

**修改前：**
```sql
tcp_flags_different_text text[]
seq_num_different_text text[]
```

**修改后：**
```sql
tcp_flags_different_text text
seq_num_different_text text
```

### 2. 代码修改

#### 2.1 `capmaster/plugins/compare/db_writer.py`

**修改点：**
- 表创建 SQL：将 `text[]` 改为 `text`
- 文档注释：更新字段说明
- 数据处理：将 `None` 转换为空字符串而不是空列表

**关键修改：**
```python
# 修改前
tcp_flags_different_text text[]
seq_num_different_text text[]

# 修改后
tcp_flags_different_text text
seq_num_different_text text
```

```python
# 修改前
if tcp_flags_different_text is None:
    tcp_flags_different_text = []
if seq_num_different_text is None:
    seq_num_different_text = []

# 修改后
if tcp_flags_different_text is None:
    tcp_flags_different_text = ""
if seq_num_different_text is None:
    seq_num_different_text = ""
```

#### 2.2 `capmaster/plugins/compare/plugin.py`

**修改点：**
- 将数组转换为分号分隔的字符串
- 使用 `"; "` 作为分隔符

**关键修改：**
```python
# TCP flags 差异文本
# 修改前
tcp_flags_text_array = []
for pair, frames in flags_pairs.items():
    tcp_flags_text_array.append(f"{pair} ({len(frames)} occurrences)")

# 修改后
tcp_flags_text_list = []
for pair, frames in flags_pairs.items():
    tcp_flags_text_list.append(f"{pair} ({len(frames)} occurrences)")
tcp_flags_text_string = "; ".join(tcp_flags_text_list) if tcp_flags_text_list else ""
```

```python
# 序列号差异文本
# 修改前
seq_num_text_array = []
for i, diff in enumerate(seq_num_diffs[:max_examples]):
    seq_num_text_array.append(f"Frame {diff.frame_a}→{diff.frame_b}: {diff.value_a}→{diff.value_b}")

# 修改后
seq_num_text_list = []
for i, diff in enumerate(seq_num_diffs[:max_examples]):
    seq_num_text_list.append(f"Frame {diff.frame_a}→{diff.frame_b}: {diff.value_a}→{diff.value_b}")
seq_num_text_string = "; ".join(seq_num_text_list) if seq_num_text_list else ""
```

### 3. 数据格式示例

**修改前（数组）：**
```python
tcp_flags_different_text = [
    "0x0002→0x0010 (69 occurrences)",
    "0x0010→0x0018 (5 occurrences)"
]

seq_num_different_text = [
    "Frame 135→136: 2146467067→903860268",
    "Frame 136→137: 2146467067→1531293805",
    "... and 59 more"
]
```

**修改后（字符串）：**
```python
tcp_flags_different_text = "0x0002→0x0010 (69 occurrences); 0x0010→0x0018 (5 occurrences)"

seq_num_different_text = "Frame 135→136: 2146467067→903860268; Frame 136→137: 2146467067→1531293805; ... and 59 more"
```

## 🚀 迁移步骤

### 步骤 1：备份数据（可选但推荐）

```bash
# 备份整个数据库
pg_dump -h localhost -U postgres -d capmaster > capmaster_backup.sql

# 或只备份特定表
pg_dump -h localhost -U postgres -d capmaster -t kase_133_tcp_stream_extra > kase_133_backup.sql
```

### 步骤 2：运行迁移脚本

```bash
# 运行迁移脚本（会提示确认）
python migrate_table_to_text.py
```

迁移脚本会：
1. 检查表是否存在
2. 显示当前字段类型
3. 显示示例数据
4. 请求确认
5. 执行字段类型转换（使用 `array_to_string` 函数）
6. 验证修改结果

### 步骤 3：验证修改

```bash
# 运行测试脚本
python test_text_fields.py
```

测试脚本会：
1. 检查字段类型是否正确
2. 插入测试数据
3. 读取并验证数据
4. 清理测试数据

### 步骤 4：手动验证（可选）

```sql
-- 查看字段类型
SELECT 
    column_name, 
    data_type, 
    udt_name
FROM information_schema.columns 
WHERE table_schema = 'public' 
  AND table_name = 'kase_133_tcp_stream_extra'
  AND column_name IN ('tcp_flags_different_text', 'seq_num_different_text');

-- 查看数据示例
SELECT 
    id,
    tcp_flags_different_text,
    seq_num_different_text
FROM public.kase_133_tcp_stream_extra
ORDER BY id DESC
LIMIT 5;
```

## 📊 SQL 迁移语句

如果需要手动执行迁移，可以使用以下 SQL：

```sql
-- 修改 tcp_flags_different_text 字段
ALTER TABLE public.kase_133_tcp_stream_extra 
ALTER COLUMN tcp_flags_different_text TYPE text 
USING array_to_string(tcp_flags_different_text, '; ');

-- 修改 seq_num_different_text 字段
ALTER TABLE public.kase_133_tcp_stream_extra 
ALTER COLUMN seq_num_different_text TYPE text 
USING array_to_string(seq_num_different_text, '; ');
```

**说明：**
- `USING array_to_string(column_name, '; ')` 会将现有的数组数据转换为分号分隔的字符串
- 如果数组为空或 NULL，会转换为空字符串或 NULL

## ⚠️ 注意事项

1. **数据转换**：现有的数组数据会自动转换为分号分隔的字符串
2. **分隔符**：使用 `"; "` （分号+空格）作为分隔符
3. **空值处理**：
   - 空数组 `[]` → 空字符串 `""`
   - `NULL` → `NULL`
4. **新数据写入**：修改后的代码会直接写入字符串，不再使用数组
5. **向后兼容**：如果需要将字符串拆分回数组，可以使用 `string_to_array(column_name, '; ')`

## 🔄 回滚方案

如果需要回滚到数组类型：

```sql
-- 回滚 tcp_flags_different_text 字段
ALTER TABLE public.kase_133_tcp_stream_extra 
ALTER COLUMN tcp_flags_different_text TYPE text[] 
USING string_to_array(tcp_flags_different_text, '; ');

-- 回滚 seq_num_different_text 字段
ALTER TABLE public.kase_133_tcp_stream_extra 
ALTER COLUMN seq_num_different_text TYPE text[] 
USING string_to_array(seq_num_different_text, '; ');
```

## 📁 相关文件

- `migrate_table_to_text.py` - 迁移脚本
- `test_text_fields.py` - 测试脚本
- `alter_table_to_text.sql` - SQL 迁移语句
- `capmaster/plugins/compare/db_writer.py` - 数据库写入代码
- `capmaster/plugins/compare/plugin.py` - 插件主代码

## ✅ 验证清单

- [ ] 数据库表字段类型已修改为 `text`
- [ ] 现有数据已正确转换为字符串格式
- [ ] 代码修改已完成（db_writer.py 和 plugin.py）
- [ ] 测试脚本运行成功
- [ ] 新数据可以正常写入
- [ ] 数据格式符合预期（分号分隔）

## 🎉 完成

修改完成后，所有新写入的数据都会使用字符串格式，现有数据也已转换为字符串格式。

