# Meta.json 快速参考

## 四个命令及其 meta.json

| 命令 | 输出文件 | meta.json id | 说明 |
|------|---------|--------------|------|
| `capmaster match -i <input> -o <output>` | `<output>` | `"matched_connections"` | 普通匹配 |
| `capmaster match -i <input> --topology -o <output>` | `<output>` | `"topology"` | 拓扑分析 |
| `capmaster comparative-analysis -i <input> --service --topology <topology> -o <output>` | `<output>` | `"comparative-analysis-service"` | 服务级别对比 |
| `capmaster comparative-analysis -i <input> --matched-connections <matched> -o <output>` | `<output>` | `"poor-quality-connections"` | 连接对级别对比 |

## Meta.json 格式

```json
{
  "id": "<command_id>",
  "source": "basic"
}
```

## 实际示例

### 命令 1
```bash
capmaster match -i /Users/ricky/Downloads/2hops/dbs_1112_2/ -o tmp/matched_connections.txt
```
生成：
- `tmp/matched_connections.txt`
- `tmp/matched_connections.meta.json` → `{"id": "matched_connections", "source": "basic"}`

### 命令 2
```bash
capmaster match -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --topology -o tmp/topology.txt
```
生成：
- `tmp/topology.txt`
- `tmp/topology.meta.json` → `{"id": "topology", "source": "basic"}`

### 命令 3
```bash
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --service --topology tmp/topology.txt -o tmp/service-network-quality.txt
```
生成：
- `tmp/service-network-quality.txt`
- `tmp/service-network-quality.meta.json` → `{"id": "comparative-analysis-service", "source": "basic"}`

### 命令 4
```bash
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --matched-connections tmp/matched_connections.txt --top-n 10 -o tmp/top10-poor-network-quality-session-pairs.txt
```
生成：
- `tmp/top10-poor-network-quality-session-pairs.txt`
- `tmp/top10-poor-network-quality-session-pairs.meta.json` → `{"id": "poor-quality-connections", "source": "basic"}`

## 测试

```bash
# 运行测试脚本
python test_meta_json.py

# 或运行示例脚本
bash examples/run_match_commands_with_meta.sh
```

## 核心代码

**文件**: `capmaster/plugins/match/meta_writer.py`

```python
def write_meta_json(
    output_file: Path,
    command_id: str,
    source: str = "match",
    additional_fields: dict[str, Any] | None = None,
) -> None:
    """Write a meta.json file alongside the output file."""
    meta_path = output_file.parent / f"{output_file.stem}.meta.json"
    meta_content = {"id": command_id, "source": source}
    if additional_fields:
        meta_content.update(additional_fields)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta_content, f, indent=2, ensure_ascii=False)
```

## 修改的位置

**文件**: `capmaster/plugins/match/plugin.py`

1. **导入** (line ~19):
   ```python
   from capmaster.plugins.match.meta_writer import write_meta_json
   ```

2. **_output_results()** (line ~1002-1018):
   ```python
   if output_file:
       output_file.write_text(output_text)
       write_meta_json(output_file, "matched_connections", "basic")
   ```

3. **_output_topology()** (line ~1140-1156):
   ```python
   if output_file:
       output_file.write_text(output_text)
       write_meta_json(output_file, "topology", "basic")
   ```

4. **execute_comparative_analysis()** (line ~1584-1610):
   ```python
   if output_file:
       with open(output_file, 'w') as f:
           f.write(report)
       # For connections type, use "poor-quality-connections"
       command_id = "poor-quality-connections" if analysis_type == "connections" else f"comparative-analysis-{analysis_type}"
       write_meta_json(output_file, command_id, "basic")
   ```

