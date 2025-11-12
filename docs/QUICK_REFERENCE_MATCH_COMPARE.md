# Match & Compare 一致性快速参考

## 问题
Match 和 Compare 命令可能产生不一致的匹配结果。

## 解决方案
使用 `--match-json` 和 `--match-file` 选项确保一致性。

## 快速开始

### 两步工作流程

```bash
# 步骤 1: Match（保存 JSON）
capmaster match -i /path/to/pcaps/ --match-json matches.json

# 步骤 2: Compare（使用 JSON）
capmaster compare -i /path/to/pcaps/ --match-file matches.json
```

## 命令选项

### Match 命令

```bash
capmaster match [OPTIONS] --match-json <FILE>
```

**新增选项**：
- `--match-json PATH` - 保存匹配结果到 JSON 文件

**示例**：
```bash
# 基本用法
capmaster match -i /path/to/pcaps/ --match-json matches.json

# 同时输出文本和 JSON
capmaster match -i /path/to/pcaps/ \
  -o matches.txt \
  --match-json matches.json

# 使用显式文件指定
capmaster match \
  --file1 baseline.pcap --file1-pcapid 0 \
  --file2 compare.pcap --file2-pcapid 1 \
  --match-json matches.json
```

### Compare 命令

```bash
capmaster compare [OPTIONS] --match-file <FILE>
```

**新增选项**：
- `--match-file PATH` - 从 JSON 文件加载匹配结果

**示例**：
```bash
# 基本用法
capmaster compare -i /path/to/pcaps/ --match-file matches.json

# 输出到文件
capmaster compare -i /path/to/pcaps/ \
  --match-file matches.json \
  -o comparison.txt

# 写入数据库
capmaster compare -i /path/to/pcaps/ \
  --match-file matches.json \
  --show-flow-hash \
  --db-connection "postgresql://user:pass@host:port/db" \
  --kase-id 133

# 只比对匹配的包
capmaster compare -i /path/to/pcaps/ \
  --match-file matches.json \
  --matched-only
```

## 验证一致性

```bash
# 运行验证脚本
python3 scripts/verify_match_compare_consistency.py /path/to/pcaps/
```

**预期输出**：
```
✓ SUCCESS: All match and compare pairs are consistent!
```

## JSON 文件结构

```json
{
  "version": "1.0",
  "file1": "/path/to/baseline.pcap",
  "file2": "/path/to/compare.pcap",
  "metadata": {
    "total_connections_1": 12,
    "matched_pairs": 12,
    "average_score": 0.58,
    ...
  },
  "matches": [
    {
      "conn1": { "stream_id": 9, ... },
      "conn2": { "stream_id": 1722, ... },
      "score": { "normalized_score": 0.57, ... }
    }
  ]
}
```

## 常见用例

### 用例 1: 基本匹配和比对
```bash
capmaster match -i /path/to/pcaps/ --match-json m.json
capmaster compare -i /path/to/pcaps/ --match-file m.json
```

### 用例 2: 保存所有结果
```bash
capmaster match -i /path/to/pcaps/ \
  -o match_results.txt \
  --match-json matches.json

capmaster compare -i /path/to/pcaps/ \
  --match-file matches.json \
  -o compare_results.txt
```

### 用例 3: 数据库工作流程
```bash
# 1. Match 并保存
capmaster match -i /path/to/pcaps/ --match-json m.json

# 2. Compare 并写入数据库
capmaster compare -i /path/to/pcaps/ \
  --match-file m.json \
  --show-flow-hash \
  --db-connection "postgresql://user:pass@localhost/db" \
  --kase-id 133
```

### 用例 4: 重复使用匹配结果
```bash
# 一次 match
capmaster match -i /path/to/pcaps/ --match-json m.json

# 多次 compare（使用相同的匹配）
capmaster compare -i /path/to/pcaps/ --match-file m.json --matched-only
capmaster compare -i /path/to/pcaps/ --match-file m.json --show-flow-hash
capmaster compare -i /path/to/pcaps/ --match-file m.json -o detailed.txt
```

## 故障排除

### 问题：No valid matches found

**原因**：JSON 文件中的 stream ID 在当前 PCAP 文件中不存在

**解决**：
1. 确认使用的是相同的 PCAP 文件
2. 重新运行 match 命令生成新的 JSON 文件

### 问题：文件名不匹配警告

**警告示例**：
```
WARNING: Match file was created for different files:
  Expected: baseline.pcap, compare.pcap
  Actual:   old_baseline.pcap, old_compare.pcap
```

**解决**：
- 如果只是路径变化（文件名相同），可以忽略
- 如果文件名也变化了，建议重新运行 match

### 问题：TypeError: MatchScore.__init__() missing arguments

**原因**：使用了旧版本的 JSON 文件

**解决**：重新运行 match 命令生成新的 JSON 文件

## 优势总结

| 特性 | 无 --match-file | 有 --match-file |
|------|----------------|----------------|
| 一致性 | ❌ 可能不一致 | ✅ 保证一致 |
| 可重现性 | ❌ 可能不同 | ✅ 完全相同 |
| 性能 | 需要重新匹配 | ✅ 跳过匹配 |
| 调试 | ❌ 难以追踪 | ✅ 可查看 JSON |
| 审计 | ❌ 无记录 | ✅ 有完整记录 |

## 更多信息

- **详细文档**：`docs/MATCH_COMPARE_CONSISTENCY.md`
- **更新日志**：`CHANGELOG_MATCH_COMPARE.md`
- **验证脚本**：`scripts/verify_match_compare_consistency.py`

## 向后兼容性

✅ 完全向后兼容 - 不使用新选项时行为不变

