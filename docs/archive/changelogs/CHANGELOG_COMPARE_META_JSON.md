# Compare 命令 Meta.json 和 Markdown 格式化更新

## 概述

为 `compare` 命令添加了 meta.json 文件输出功能，并调整了输出格式，使其与 `match` 和 `comparative-analysis` 命令保持一致。

## 修改内容

### 1. 输出格式调整

将输出格式从纯文本格式调整为 Markdown 格式：

**之前的格式：**
```text
====================================================================================================
TCP Connection Packet-Level Comparison Report
====================================================================================================
Baseline File: B_processed.pcap
Compare File:  A_processed.pcap
...
```

**现在的格式：**
```markdown
## TCP Connection Packet-Level Comparison Report

```text
Baseline File: B_processed.pcap
Compare File:  A_processed.pcap
...
```
```

### 2. Meta.json 文件生成

在输出主文件的同时，自动生成同名的 `meta.json` 文件。

**示例：**
```bash
capmaster compare \
  --file1 cases/dbs_20251028-Masked/B_processed.pcap \
  --file1-pcapid 1 \
  --file2 cases/dbs_20251028-Masked/A_processed.pcap \
  --file2-pcapid 0 \
  --show-flow-hash \
  --matched-only \
  --match-mode one-to-many \
  -o tmp/packet_differences.md
```

生成文件：
- `tmp/packet_differences.md` - 主输出文件
- `tmp/packet_differences.meta.json` - 元数据文件

**meta.json 内容：**
```json
{
  "id": "packet_differences",
  "source": "basic"
}
```

## 修改的文件

### capmaster/plugins/compare/plugin.py

在 `_output_results()` 方法中进行了以下修改：

1. **添加 Markdown 标题**（第 770-772 行）：
   ```python
   lines.append("## TCP Connection Packet-Level Comparison Report")
   lines.append("")
   ```

2. **添加代码块开始标记**（第 775 行）：
   ```python
   lines.append("```text")
   ```

3. **调整各部分格式**：
   - 移除了多余的 `=` 分隔线
   - 使用 `-` 分隔线替代
   - 在各部分之间添加空行以提高可读性

4. **添加代码块结束标记**（第 1012 行）：
   ```python
   lines.append("```")
   ```

5. **添加 meta.json 生成**（第 1023-1029 行）：
   ```python
   # Write meta.json file
   from capmaster.plugins.match.meta_writer import write_meta_json
   write_meta_json(
       output_file=output_file,
       command_id="packet_differences",
       source="basic",
   )
   ```

## 格式化细节

### 标题和分隔符

- **Markdown 标题**：使用 `## ` 开头
- **主要分隔符**：使用 `-` 字符（140 个字符宽）
- **次要分隔符**：使用 `─` 字符（用于 Stream Pair 部分）

### 代码块

- **开始标记**：` ```text `
- **结束标记**：` ``` `
- **内容**：所有报告内容都包含在代码块中

### 各部分结构

1. **Markdown 标题**
2. **空行**
3. **代码块开始**
4. **文件信息**
5. **空行**
6. **Baseline 文件连接列表**
7. **空行**
8. **Compare 文件连接列表**
9. **空行**
10. **Overall Summary**
11. **空行**
12. **Per-Stream-Pair Statistics**（如果有）
13. **代码块结束**

## 与其他命令的一致性

现在 `compare` 命令的输出格式与以下命令保持一致：

1. **match 命令**：
   - 使用 `## ` 标题
   - 使用 ` ```text ``` ` 代码块
   - 生成 `meta.json` 文件

2. **comparative-analysis 命令**：
   - 使用 `## ` 标题
   - 使用 ` ```text ``` ` 代码块
   - 生成 `meta.json` 文件

## 测试

使用 `test_compare_meta.py` 脚本测试功能：

```bash
python test_compare_meta.py
```

测试内容：
1. ✓ 命令执行成功
2. ✓ 输出文件生成
3. ✓ Meta.json 文件生成
4. ✓ Meta.json 内容正确
5. ✓ 输出文件使用 Markdown 标题
6. ✓ 输出文件包含代码块标记
7. ✓ 输出文件正确关闭代码块

## 向后兼容性

- 输出文件的内容结构保持不变，只是添加了 Markdown 格式化
- 不影响现有的数据库写入功能
- 不影响现有的命令行参数

## 未来扩展

meta.json 文件可以在未来添加更多字段，例如：
- `timestamp`: 生成时间戳
- `input_files`: 输入文件列表
- `parameters`: 命令参数
- `statistics`: 统计信息摘要

