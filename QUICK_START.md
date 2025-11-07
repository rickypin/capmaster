# 快速开始 - 数组字段改为文本字段

## 🎯 一句话总结

将 `kase_133_tcp_stream_extra` 表的 `tcp_flags_different_text` 和 `seq_num_different_text` 字段从数组（`text[]`）改为字符串（`text`），使用分号分隔多个值。

---

## ⚡ 快速执行（3 步）

### 1️⃣ 备份数据（可选但推荐）

```bash
pg_dump -h localhost -U postgres -d capmaster -t kase_133_tcp_stream_extra > backup.sql
```

### 2️⃣ 运行迁移脚本

```bash
python migrate_table_to_text.py
```

脚本会提示确认，输入 `yes` 继续。

### 3️⃣ 验证修改

```bash
python test_text_fields.py
```

测试成功后，可以选择删除测试数据。

---

## 📊 修改前后对比

| 项目 | 修改前 | 修改后 |
|------|--------|--------|
| **字段类型** | `text[]` (数组) | `text` (字符串) |
| **数据示例** | `['item1', 'item2']` | `'item1; item2'` |
| **Python 类型** | `list` | `str` |
| **分隔符** | N/A | `'; '` (分号+空格) |

---

## 🔍 验证命令

### 检查字段类型

```sql
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'kase_133_tcp_stream_extra'
  AND column_name IN ('tcp_flags_different_text', 'seq_num_different_text');
```

**期望结果：** 两个字段的 `data_type` 都应该是 `text`

### 查看数据示例

```sql
SELECT id, tcp_flags_different_text, seq_num_different_text
FROM kase_133_tcp_stream_extra
ORDER BY id DESC
LIMIT 3;
```

**期望结果：** 数据应该是字符串格式，多个值用 `; ` 分隔

---

## 🔄 如果需要回滚

```sql
-- 回滚到数组类型
ALTER TABLE public.kase_133_tcp_stream_extra 
ALTER COLUMN tcp_flags_different_text TYPE text[] 
USING string_to_array(tcp_flags_different_text, '; ');

ALTER TABLE public.kase_133_tcp_stream_extra 
ALTER COLUMN seq_num_different_text TYPE text[] 
USING string_to_array(seq_num_different_text, '; ');
```

---

## 📚 详细文档

- **完整迁移指南**: `ARRAY_TO_TEXT_MIGRATION_GUIDE.md`
- **修改总结**: `MODIFICATION_SUMMARY.md`
- **SQL 脚本**: `alter_table_to_text.sql`

---

## ❓ 常见问题

### Q1: 现有数据会丢失吗？
**A:** 不会。迁移脚本使用 `array_to_string()` 函数自动转换数据，所有数据都会保留。

### Q2: 空数组会变成什么？
**A:** 空数组 `[]` 会转换为空字符串 `""`，`NULL` 保持为 `NULL`。

### Q3: 如何在 Python 中拆分字符串？
**A:** 使用 `text.split('; ')` 即可拆分为列表。

### Q4: 新创建的表会自动使用新类型吗？
**A:** 是的。修改后的代码会自动创建 `text` 类型的字段。

### Q5: 需要修改查询代码吗？
**A:** 如果之前的代码期望数组类型，需要修改为处理字符串。如果只是显示数据，通常不需要修改。

---

## ✅ 完成检查

- [ ] 运行了迁移脚本
- [ ] 字段类型已改为 `text`
- [ ] 测试脚本运行成功
- [ ] 数据格式正确（分号分隔）
- [ ] 新数据可以正常写入

---

**🎉 完成！** 现在可以使用新的字符串格式了。

