# Compare 命令 Meta.json 快速参考

## 命令及其 meta.json

| 命令 | 输出文件 | meta.json id | 说明 |
|------|---------|--------------|------|
| `capmaster compare --file1 <file1> --file2 <file2> -o <output>` | `<output>` | `"packet_differences"` | 数据包级别对比 |

## Meta.json 格式

```json
{
  "id": "packet_differences",
  "source": "basic"
}
```

## 输出格式

### Markdown 格式

输出文件使用 Markdown 格式，包含：
- 标题：`## TCP Connection Packet-Level Comparison Report`
- 代码块：` ```text ... ``` `

### 示例

```markdown
## TCP Connection Packet-Level Comparison Report

```text
Baseline File: B_processed.pcap
Compare File:  A_processed.pcap
Comparison Direction: A_processed.pcap relative to B_processed.pcap
Matched Connections: 11
Mode: Matched-only (only comparing packets with matching IPID in both files)

Matched TCP Connections in Baseline File (B_processed.pcap)
--------------------------------------------------------------------------------------------------------------------------------------------
No.    Stream ID    Client IP:Port            Server IP:Port            Packets    First Time             Last Time              Flow Hash                     
--------------------------------------------------------------------------------------------------------------------------------------------
1      0            8.42.96.45:35101          8.67.2.125:26302          162        1757441703700765000    1757444371567114000    -1173584886679544929 (RHS>LHS)
--------------------------------------------------------------------------------------------------------------------------------------------
Total: 1 connections

...
```
```

## 使用示例

```bash
# 基本用法
capmaster compare \
  --file1 cases/dbs_20251028-Masked/B_processed.pcap \
  --file1-pcapid 1 \
  --file2 cases/dbs_20251028-Masked/A_processed.pcap \
  --file2-pcapid 0 \
  -o tmp/packet_differences.md

# 带 flow hash 和 matched-only 模式
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

## 核心代码

**文件**: `capmaster/plugins/compare/plugin.py`

在 `_output_results()` 方法中：

```python
# Markdown title
lines.append("## TCP Connection Packet-Level Comparison Report")
lines.append("")

# Content in code block
lines.append("```text")
# ... report content ...
lines.append("```")

# Write meta.json file
from capmaster.plugins.match.meta_writer import write_meta_json
write_meta_json(
    output_file=output_file,
    command_id="packet_differences",
    source="basic",
)
```

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

## 与其他命令的一致性

现在所有主要命令都使用相同的格式：

| 命令 | Markdown 标题 | 代码块 | meta.json |
|------|--------------|--------|-----------|
| `match` | ✓ | ✓ | ✓ |
| `match --topology` | ✓ | ✓ | ✓ |
| `comparative-analysis --service` | ✓ | ✓ | ✓ |
| `comparative-analysis --matched-connections` | ✓ | ✓ | ✓ |
| `compare` | ✓ | ✓ | ✓ |

## 未来扩展

meta.json 文件可以在未来添加更多字段，例如：
- `timestamp`: 生成时间戳
- `input_files`: 输入文件列表
- `parameters`: 命令参数
- `statistics`: 统计信息摘要

