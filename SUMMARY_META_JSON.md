# Meta.json 功能实现总结

## 任务完成情况 ✅

已成功为以下四个命令添加 meta.json 文件输出功能：

1. ✅ `capmaster match -i <input> -o <output>` - 普通匹配
2. ✅ `capmaster match -i <input> --topology -o <output>` - 拓扑分析
3. ✅ `capmaster comparative-analysis -i <input> --service --topology <topology> -o <output>` - 服务级别对比分析
4. ✅ `capmaster comparative-analysis -i <input> --matched-connections <matched> --top-n 10 -o <output>` - 连接对级别对比分析

## 实现方式

### 1. 创建辅助模块
- **文件**: `capmaster/plugins/match/meta_writer.py`
- **功能**: 提供 `write_meta_json()` 函数，用于生成 meta.json 文件
- **特点**: 
  - 简洁易用
  - 支持扩展字段
  - 与 analyze 模块保持一致的设计理念

### 2. 修改 plugin.py
- **导入**: 添加 `from capmaster.plugins.match.meta_writer import write_meta_json`
- **修改位置**:
  1. `_output_results()` - 匹配结果输出
  2. `_output_topology()` - 拓扑分析输出
  3. `execute_comparative_analysis()` - 对比分析输出

### 3. Meta.json 内容

所有 meta.json 文件都包含以下必需字段：
- `id`: 命令标识符
- `source`: 固定为 "basic"

命令标识符（id）：
- `"matched_connections"` - 普通匹配命令
- `"topology"` - 拓扑分析命令
- `"comparative-analysis-service"` - 服务级别对比分析
- `"poor-quality-connections"` - 连接对级别对比分析
- `"comparative-analysis-both"` - 同时进行服务和连接对分析

## 使用示例

### 示例 1: 普通匹配
```bash
capmaster match -i /Users/ricky/Downloads/2hops/dbs_1112_2/ -o tmp/matched_connections.txt
```

生成文件：
- `tmp/matched_connections.txt`
- `tmp/matched_connections.meta.json`

meta.json 内容：
```json
{
  "id": "matched_connections",
  "source": "basic"
}
```

### 示例 2: 拓扑分析
```bash
capmaster match -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --topology -o tmp/topology.txt
```

生成文件：
- `tmp/topology.txt`
- `tmp/topology.meta.json`

meta.json 内容：
```json
{
  "id": "topology",
  "source": "basic"
}
```

### 示例 3: 服务级别对比分析
```bash
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --service --topology tmp/topology.txt -o tmp/service-network-quality.txt
```

生成文件：
- `tmp/service-network-quality.txt`
- `tmp/service-network-quality.meta.json`

meta.json 内容：
```json
{
  "id": "comparative-analysis-service",
  "source": "basic"
}
```

### 示例 4: 连接对级别对比分析
```bash
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --matched-connections tmp/matched_connections.txt --top-n 10 -o tmp/top10-poor-network-quality-session-pairs.txt
```

生成文件：
- `tmp/top10-poor-network-quality-session-pairs.txt`
- `tmp/top10-poor-network-quality-session-pairs.meta.json`

meta.json 内容：
```json
{
  "id": "poor-quality-connections",
  "source": "basic"
}
```

## 测试方法

### 方法 1: 使用测试脚本
```bash
python test_meta_json.py
```

### 方法 2: 使用示例脚本
```bash
bash examples/run_match_commands_with_meta.sh
```

### 方法 3: 手动测试
运行任意一个命令，检查是否生成了对应的 meta.json 文件。

## 文件清单

### 新增文件
1. `capmaster/plugins/match/meta_writer.py` - 核心实现
2. `docs/META_JSON_OUTPUT.md` - 详细文档
3. `test_meta_json.py` - 测试脚本
4. `examples/run_match_commands_with_meta.sh` - 示例脚本
5. `CHANGELOG_META_JSON.md` - 修改日志
6. `SUMMARY_META_JSON.md` - 本文件

### 修改文件
1. `capmaster/plugins/match/plugin.py` - 添加 meta.json 生成逻辑

## 设计特点

1. **最小化修改**: 只修改必要的文件，不影响现有功能
2. **保持一致**: 与 analyze 模块的设计保持一致
3. **易于扩展**: 支持通过 `additional_fields` 参数添加更多字段
4. **向后兼容**: 不影响现有命令的使用方式
5. **自动化**: 无需用户手动操作，自动生成 meta.json

## 注意事项

1. **只在输出到文件时生成**: 如果输出到 stdout，不会生成 meta.json
2. **文件命名**: meta.json 文件名与输出文件同名，扩展名为 `.meta.json`
3. **目录自动创建**: 如果输出目录不存在，会自动创建

## 下一步建议

如果需要进一步扩展功能，可以考虑：
1. 添加时间戳字段
2. 添加输入文件信息
3. 添加命令参数信息
4. 添加统计信息（如匹配数量、匹配率等）
5. 添加工具版本号

这些扩展可以通过修改 `write_meta_json()` 函数的调用，传入 `additional_fields` 参数来实现。

