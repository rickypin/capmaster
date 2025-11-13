# Meta.json 输出功能

## 概述

为了与 `analyze` 模块保持一致，`match` 和 `compare` 插件的主要命令现在会自动生成同名的 `meta.json` 文件，用于记录输出文件的元数据信息。

## 支持的命令

以下五个命令会自动生成 `meta.json` 文件：

### 1. Match 命令（普通匹配）

```bash
capmaster match -i /Users/ricky/Downloads/2hops/dbs_1112_2/ -o tmp/matched_connections.txt
```

生成文件：
- `tmp/matched_connections.txt` - 匹配结果
- `tmp/matched_connections.meta.json` - 元数据文件

meta.json 内容示例：
```json
{
  "id": "matched_connections",
  "source": "basic"
}
```

### 2. Match 命令（拓扑分析）

```bash
capmaster match -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --topology -o tmp/topology.txt
```

生成文件：
- `tmp/topology.txt` - 拓扑分析结果
- `tmp/topology.meta.json` - 元数据文件

meta.json 内容示例：
```json
{
  "id": "topology",
  "source": "basic"
}
```

### 3. Comparative Analysis 命令（服务级别）

```bash
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --service --topology tmp/topology.txt -o tmp/service-network-quality.txt
```

生成文件：
- `tmp/service-network-quality.txt` - 服务级别网络质量分析结果
- `tmp/service-network-quality.meta.json` - 元数据文件

meta.json 内容示例：
```json
{
  "id": "comparative-analysis-service",
  "source": "basic"
}
```

### 4. Comparative Analysis 命令（连接对级别）

```bash
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --matched-connections tmp/matched_connections.txt --top-n 10 -o tmp/top10-poor-network-quality-session-pairs.txt
```

生成文件：
- `tmp/top10-poor-network-quality-session-pairs.txt` - 连接对网络质量分析结果
- `tmp/top10-poor-network-quality-session-pairs.meta.json` - 元数据文件

meta.json 内容示例：
```json
{
  "id": "poor-quality-connections",
  "source": "basic"
}
```

### 5. Compare 命令（数据包级别对比）

```bash
capmaster compare --file1 cases/dbs_20251028-Masked/B_processed.pcap --file1-pcapid 1 --file2 cases/dbs_20251028-Masked/A_processed.pcap --file2-pcapid 0 --show-flow-hash --matched-only --match-mode one-to-many -o tmp/packet_differences.md
```

生成文件：
- `tmp/packet_differences.md` - 数据包级别对比结果
- `tmp/packet_differences.meta.json` - 元数据文件

meta.json 内容示例：
```json
{
  "id": "packet_differences",
  "source": "basic"
}
```

## Meta.json 字段说明

### 必需字段

- **id**: 命令标识符，用于区分不同的命令类型
  - `"matched_connections"` - 匹配命令
  - `"topology"` - 拓扑分析命令
  - `"comparative-analysis-service"` - 服务级别对比分析
  - `"poor-quality-connections"` - 连接对级别对比分析
  - `"comparative-analysis-both"` - 同时进行服务和连接对分析
  - `"packet_differences"` - 数据包级别对比命令

- **source**: 源模块名称，固定为 `"basic"`

### 可选字段

未来可以根据需要添加更多字段，例如：
- `tags`: 标签列表
- `timestamp`: 生成时间戳
- `input_files`: 输入文件列表
- `parameters`: 命令参数

## 实现细节

### 核心模块

`capmaster/plugins/match/meta_writer.py` 提供了 `write_meta_json()` 函数，用于生成 meta.json 文件。

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

meta.json 文件在以下位置生成：

**Match 插件：**
1. `_output_results()` - 匹配结果输出时
2. `_output_topology()` - 拓扑分析输出时
3. `execute_comparative_analysis()` - 对比分析输出时

**Compare 插件：**
4. `_output_results()` - 数据包级别对比结果输出时

## 与 Analyze 模块的对比

Analyze 模块的 meta.json 示例：
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

Match 模块的 meta.json 更简洁，只包含必需的 `id` 和 `source` 字段，未来可以根据需要扩展。

## 测试

使用 `test_meta_json.py` 脚本测试 meta.json 生成功能：

```bash
python test_meta_json.py
```

该脚本会：
1. 运行各个命令
2. 检查输出文件是否生成
3. 验证 meta.json 文件是否存在
4. 验证 meta.json 内容是否正确

