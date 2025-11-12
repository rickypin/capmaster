# Changelog - Meta.json 输出功能

## 修改日期
2025-11-12

## 修改概述
为 `match` 插件的四个主要命令添加了自动生成 `meta.json` 文件的功能，与 `analyze` 模块保持一致。

## 修改的文件

### 新增文件

1. **capmaster/plugins/match/meta_writer.py**
   - 新增辅助模块，提供 `write_meta_json()` 函数
   - 用于生成 meta.json 文件
   - 支持自定义字段扩展

2. **docs/META_JSON_OUTPUT.md**
   - 详细文档，说明 meta.json 功能
   - 包含所有支持命令的示例
   - 字段说明和实现细节

3. **test_meta_json.py**
   - 测试脚本，验证 meta.json 生成功能
   - 自动化测试所有命令

4. **examples/run_match_commands_with_meta.sh**
   - 示例脚本，演示如何使用这些命令
   - 展示生成的 meta.json 文件内容

5. **CHANGELOG_META_JSON.md**
   - 本文件，记录所有修改

### 修改的文件

1. **capmaster/plugins/match/plugin.py**
   - 导入 `write_meta_json` 函数
   - 在 `_output_results()` 方法中添加 meta.json 生成（match 命令）
   - 在 `_output_topology()` 方法中添加 meta.json 生成（topology 命令）
   - 在 `execute_comparative_analysis()` 方法中添加 meta.json 生成（comparative-analysis 命令）

## 功能详情

### 支持的命令

1. **Match 命令（普通匹配）**
   ```bash
   capmaster match -i <input_dir> -o <output_file>
   ```
   - 生成 `<output_file>.meta.json`
   - id: "matched_connections"
   - source: "basic"

2. **Match 命令（拓扑分析）**
   ```bash
   capmaster match -i <input_dir> --topology -o <output_file>
   ```
   - 生成 `<output_file>.meta.json`
   - id: "topology"
   - source: "basic"

3. **Comparative Analysis（服务级别）**
   ```bash
   capmaster comparative-analysis -i <input_dir> --service --topology <topology_file> -o <output_file>
   ```
   - 生成 `<output_file>.meta.json`
   - id: "comparative-analysis-service"
   - source: "basic"

4. **Comparative Analysis（连接对级别）**
   ```bash
   capmaster comparative-analysis -i <input_dir> --matched-connections <matched_file> --top-n 10 -o <output_file>
   ```
   - 生成 `<output_file>.meta.json`
   - id: "poor-quality-connections"
   - source: "basic"

### Meta.json 格式

基本格式（保底字段）：
```json
{
  "id": "<command_id>",
  "source": "basic"
}
```

未来可扩展字段：
- `tags`: 标签列表
- `timestamp`: 生成时间戳
- `input_files`: 输入文件列表
- `parameters`: 命令参数

## 实现细节

### 核心函数

```python
def write_meta_json(
    output_file: Path,
    command_id: str,
    source: str = "match",
    additional_fields: dict[str, Any] | None = None,
) -> None:
    """
    Write a meta.json file alongside the output file.
    
    Args:
        output_file: Path to the output file
        command_id: Identifier for the command
        source: Source module name (default: "match")
        additional_fields: Additional fields to include
    """
```

### 调用位置

1. **_output_results()** (line ~1002-1018)
   - 在写入匹配结果文件后调用
   - 生成 match 命令的 meta.json

2. **_output_topology()** (line ~1140-1156)
   - 在写入拓扑分析文件后调用
   - 生成 topology 命令的 meta.json

3. **execute_comparative_analysis()** (line ~1584-1610)
   - 在写入对比分析报告后调用
   - 根据 analysis_type 生成不同的 command_id
   - 支持三种类型：service、connections、both

## 测试方法

### 自动化测试
```bash
python test_meta_json.py
```

### 手动测试
```bash
bash examples/run_match_commands_with_meta.sh
```

### 验证步骤
1. 运行命令
2. 检查输出文件是否生成
3. 检查 meta.json 文件是否存在
4. 验证 meta.json 内容是否正确（包含 id 和 source 字段）

## 与 Analyze 模块的对比

### Analyze 模块
```json
{
  "id": "tcp_conversations",
  "source": "basic",
  "tags": [],
  "source_pcap": "example.pcap",
  "tshark_args": [...],
  "protocols": ["tcp"]
}
```

### Match 模块（当前实现）
```json
{
  "id": "match",
  "source": "match"
}
```

Match 模块的 meta.json 更简洁，只包含必需的字段，未来可以根据需要扩展。

## 注意事项

1. **只在输出到文件时生成 meta.json**
   - 如果输出到 stdout，不会生成 meta.json 文件

2. **文件命名规则**
   - meta.json 文件名与输出文件同名，扩展名为 `.meta.json`
   - 例如：`matched_connections.txt` → `matched_connections.meta.json`

3. **目录创建**
   - meta.json 文件会自动创建在输出文件的同一目录下
   - 目录会自动创建（如果不存在）

## 未来扩展

可以考虑添加以下字段：
- `timestamp`: 生成时间戳
- `input_files`: 输入文件列表
- `parameters`: 命令参数（如 threshold、bucket 等）
- `statistics`: 统计信息（如匹配数量、匹配率等）
- `version`: 工具版本号

