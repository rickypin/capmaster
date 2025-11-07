# 数组字段改为文本字段 - 修改总结

## 📋 修改概述

将 `kase_***_tcp_stream_extra` 表中的两个字段从数组类型改为文本类型：
- `tcp_flags_different_text`: `text[]` → `text`
- `seq_num_different_text`: `text[]` → `text`

使用分号（`; `）作为分隔符连接多个值。

---

## ✅ 已完成的修改

### 1. 代码文件修改

#### 1.1 `capmaster/plugins/compare/db_writer.py`

**修改内容：**
- ✅ 更新表创建 SQL：`text[]` → `text`
- ✅ 更新文档注释：说明字段为字符串类型
- ✅ 更新数据处理逻辑：`None` → `""` (空字符串)

**关键代码：**
```python
# 表创建 SQL
tcp_flags_different_text text,  # 原来是 text[]
seq_num_different_text text,    # 原来是 text[]

# 数据处理
if tcp_flags_different_text is None:
    tcp_flags_different_text = ""  # 原来是 []
if seq_num_different_text is None:
    seq_num_different_text = ""    # 原来是 []
```

#### 1.2 `capmaster/plugins/compare/plugin.py`

**修改内容：**
- ✅ 将数组转换为分号分隔的字符串
- ✅ 使用 `"; "` 作为分隔符
- ✅ 更新变量名：`_array` → `_list` → `_string`

**关键代码：**
```python
# TCP flags 差异文本
tcp_flags_text_list = []
for pair, frames in flags_pairs.items():
    tcp_flags_text_list.append(f"{pair} ({len(frames)} occurrences)")
tcp_flags_text_string = "; ".join(tcp_flags_text_list) if tcp_flags_text_list else ""

# 序列号差异文本
seq_num_text_list = []
for i, diff in enumerate(seq_num_diffs[:max_examples]):
    seq_num_text_list.append(f"Frame {diff.frame_a}→{diff.frame_b}: {diff.value_a}→{diff.value_b}")
seq_num_text_string = "; ".join(seq_num_text_list) if seq_num_text_list else ""

# 插入数据库
db.insert_flow_hash(
    ...
    tcp_flags_different_text=tcp_flags_text_string,  # 原来是 tcp_flags_text_array
    seq_num_different_text=seq_num_text_string,      # 原来是 seq_num_text_array
)
```

### 2. 数据库迁移脚本

#### 2.1 `migrate_table_to_text.py`

**功能：**
- ✅ 检查表是否存在
- ✅ 显示当前字段类型
- ✅ 显示示例数据（修改前）
- ✅ 请求用户确认
- ✅ 执行字段类型转换
- ✅ 验证修改结果
- ✅ 显示示例数据（修改后）

**使用方法：**
```bash
python migrate_table_to_text.py
```

#### 2.2 `alter_table_to_text.sql`

**功能：**
- ✅ SQL 迁移语句
- ✅ 使用 `array_to_string()` 函数转换数据
- ✅ 验证查询

**使用方法：**
```bash
psql -h localhost -U postgres -d capmaster -f alter_table_to_text.sql
```

### 3. 测试脚本

#### 3.1 `test_text_fields.py`

**功能：**
- ✅ 检查字段类型是否正确
- ✅ 插入测试数据
- ✅ 读取并验证数据
- ✅ 验证数据类型和内容
- ✅ 清理测试数据

**使用方法：**
```bash
python test_text_fields.py
```

### 4. 文档

#### 4.1 `ARRAY_TO_TEXT_MIGRATION_GUIDE.md`

**内容：**
- ✅ 修改概述
- ✅ 修改原因
- ✅ 详细的修改内容
- ✅ 数据格式示例
- ✅ 迁移步骤
- ✅ SQL 迁移语句
- ✅ 注意事项
- ✅ 回滚方案
- ✅ 验证清单

---

## 📊 数据格式对比

### 修改前（数组）

**数据库存储：**
```sql
tcp_flags_different_text = ARRAY['0x0002→0x0010 (69 occurrences)', '0x0010→0x0018 (5 occurrences)']
seq_num_different_text = ARRAY['Frame 135→136: 2146467067→903860268', 'Frame 136→137: 2146467067→1531293805']
```

**Python 读取：**
```python
tcp_flags_different_text = ['0x0002→0x0010 (69 occurrences)', '0x0010→0x0018 (5 occurrences)']
seq_num_different_text = ['Frame 135→136: 2146467067→903860268', 'Frame 136→137: 2146467067→1531293805']
```

### 修改后（字符串）

**数据库存储：**
```sql
tcp_flags_different_text = '0x0002→0x0010 (69 occurrences); 0x0010→0x0018 (5 occurrences)'
seq_num_different_text = 'Frame 135→136: 2146467067→903860268; Frame 136→137: 2146467067→1531293805'
```

**Python 读取：**
```python
tcp_flags_different_text = '0x0002→0x0010 (69 occurrences); 0x0010→0x0018 (5 occurrences)'
seq_num_different_text = 'Frame 135→136: 2146467067→903860268; Frame 136→137: 2146467067→1531293805'
```

**如需拆分：**
```python
tcp_flags_list = tcp_flags_different_text.split('; ')
seq_num_list = seq_num_different_text.split('; ')
```

---

## 🚀 执行步骤

### 步骤 1：备份数据（推荐）

```bash
# 备份整个数据库
pg_dump -h localhost -U postgres -d capmaster > capmaster_backup_$(date +%Y%m%d_%H%M%S).sql

# 或只备份特定表
pg_dump -h localhost -U postgres -d capmaster -t kase_133_tcp_stream_extra > kase_133_backup_$(date +%Y%m%d_%H%M%S).sql
```

### 步骤 2：运行迁移脚本

```bash
# 方式 1：使用 Python 脚本（推荐，有交互确认）
python migrate_table_to_text.py

# 方式 2：直接执行 SQL
psql -h localhost -U postgres -d capmaster -f alter_table_to_text.sql
```

### 步骤 3：验证修改

```bash
# 运行测试脚本
python test_text_fields.py
```

### 步骤 4：测试新代码

```bash
# 使用 compare 插件测试数据写入
capmaster compare \
  --file1 /path/to/file1.pcap \
  --file2 /path/to/file2.pcap \
  --show-flow-hash \
  --db-connection "postgresql://postgres:postgres@localhost:5432/capmaster" \
  --kase-id 133
```

---

## ⚠️ 重要注意事项

1. **数据转换是自动的**
   - 使用 `array_to_string()` 函数自动转换现有数据
   - 空数组 `[]` 会转换为空字符串 `""`
   - `NULL` 值保持为 `NULL`

2. **分隔符选择**
   - 使用 `"; "` （分号+空格）作为分隔符
   - 确保数据中不包含 `"; "` 字符串（当前数据格式不会包含）

3. **向后兼容**
   - 如需将字符串拆分回数组：`string_to_array(column_name, '; ')`
   - 如需回滚到数组类型，参考 `ARRAY_TO_TEXT_MIGRATION_GUIDE.md` 中的回滚方案

4. **新表创建**
   - 修改后的代码会自动创建正确的表结构（text 类型）
   - 不需要手动修改新表的结构

---

## 📁 修改的文件清单

### 代码文件
- ✅ `capmaster/plugins/compare/db_writer.py`
- ✅ `capmaster/plugins/compare/plugin.py`

### 脚本文件
- ✅ `migrate_table_to_text.py` (新建)
- ✅ `test_text_fields.py` (新建)
- ✅ `alter_table_to_text.sql` (新建)

### 文档文件
- ✅ `ARRAY_TO_TEXT_MIGRATION_GUIDE.md` (新建)
- ✅ `MODIFICATION_SUMMARY.md` (本文件，新建)

### 需要更新的文档（可选）
- ⚠️ `DATABASE_INTEGRATION_SUMMARY.md` - 提到 text[] 类型
- ⚠️ `FEATURE_COMPLETE_SUMMARY.md` - 提到 text[] 类型
- ⚠️ `PCAPID_FEATURE_GUIDE.md` - 提到 text[] 类型
- ⚠️ `FINAL_VERIFICATION_REPORT.md` - 提到 text[] 类型
- ⚠️ `TCP_STREAM_EXTRA_REPORT.md` - 提到 ARRAY 类型

**注意：** 这些文档是历史记录，可以选择不更新，或者添加注释说明已改为 text 类型。

---

## ✅ 验证清单

执行迁移后，请确认以下项目：

- [ ] 数据库表字段类型已修改为 `text`
- [ ] 现有数据已正确转换为字符串格式（使用分号分隔）
- [ ] 代码修改已完成（db_writer.py 和 plugin.py）
- [ ] 测试脚本运行成功
- [ ] 新数据可以正常写入
- [ ] 数据格式符合预期（分号分隔的字符串）
- [ ] 查询数据时返回的是字符串类型，不是数组

---

## 🎉 完成

所有修改已完成！现在 `tcp_flags_different_text` 和 `seq_num_different_text` 字段使用字符串类型存储，多个值使用分号分隔。

