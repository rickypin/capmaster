# Changelog - Markdown 格式优化

## 日期
2024-11-12

## 变更概述
将四个命令的输出格式统一改为 Markdown 格式，使用 `## 标题` 和 ` ```text ``` ` 代码块包裹正文内容。

## 影响的命令

### 1. `capmaster match -i <input> -o <output>`
- **变更**：输出文件格式改为 Markdown
- **标题**：`## TCP Connection Matching Results`
- **内容**：统计信息和匹配连接表格包裹在 ` ```text ``` ` 代码块中

### 2. `capmaster match -i <input> --topology -o <output>`
- **变更**：输出文件格式改为 Markdown
- **标题**：`## Network Topology`
- **内容**：拓扑信息包裹在 ` ```text ``` ` 代码块中

### 3. `capmaster comparative-analysis -i <input> --service --topology <topology> -o <output>`
- **变更**：输出文件格式改为 Markdown
- **标题**：`## Network Quality Analysis Report`
- **内容**：服务质量分析表格包裹在 ` ```text ``` ` 代码块中

### 4. `capmaster comparative-analysis -i <input> --matched-connections <matched> --top-n N -o <output>`
- **变更**：输出文件格式改为 Markdown
- **标题**：`## Connection Pair Quality Analysis Report`
- **内容**：连接对质量分析表格包裹在 ` ```text ``` ` 代码块中

## 修改的文件

### 1. `capmaster/plugins/match/plugin.py`
- **函数**：`_output_results()`
- **变更**：
  - 移除原有的 `=` 分隔线标题
  - 添加 Markdown 标题 `## TCP Connection Matching Results`
  - 在内容前后添加 ` ```text ` 和 ` ``` ` 标记

### 2. `capmaster/plugins/match/topology.py`
- **函数**：`format_topology()`
- **变更**：
  - 移除原有的 `=` 分隔线标题
  - 添加 Markdown 标题 `## Network Topology`
  - 在内容前后添加 ` ```text ` 和 ` ``` ` 标记

### 3. `capmaster/plugins/match/quality_analyzer.py`
- **函数**：`format_quality_report()`
- **变更**：
  - 移除原有的 `=` 分隔线标题
  - 添加 Markdown 标题 `## Network Quality Analysis Report`
  - 在内容前后添加 ` ```text ` 和 ` ``` ` 标记

- **函数**：`format_connection_pair_report()`
- **变更**：
  - 移除原有的 `=` 分隔线标题
  - 添加 Markdown 标题 `## Connection Pair Quality Analysis Report`
  - 在内容前后添加 ` ```text ` 和 ` ``` ` 标记

- **函数**：`parse_matched_connections()`
- **变更**：
  - 更新解析逻辑以跳过 Markdown 标记（`##` 和 ` ``` `）
  - 保持对旧格式的兼容性

## 向后兼容性

### 解析兼容性
- `parse_matched_connections()` 函数已更新，支持解析 Markdown 格式的文件
- 跳过 Markdown 标记：`##`、` ``` `
- 保持对旧格式文件的支持

### 依赖关系
所有命令之间的输入输出依赖关系保持不变：
1. `match` → `matched_connections.md` → `comparative-analysis --matched-connections`
2. `match --topology` → `topology.md` → `comparative-analysis --service --topology`

## 测试结果

所有测试均通过：

```bash
# 测试 1: 生成匹配连接（Markdown 格式）
capmaster match -i /Users/ricky/Downloads/2hops/dbs_1112_2/ -o tmp/matched_connections.md
✅ 成功生成 Markdown 格式输出

# 测试 2: 生成拓扑分析（Markdown 格式）
capmaster match -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --topology -o tmp/topology.md
✅ 成功生成 Markdown 格式输出

# 测试 3: 服务级别分析（使用 Markdown 输入）
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --service --topology tmp/topology.md -o tmp/service-network-quality.md
✅ 成功解析 Markdown 输入并生成 Markdown 格式输出

# 测试 4: 连接对级别分析（使用 Markdown 输入）
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --matched-connections tmp/matched_connections.md --top-n 10 -o tmp/poor-quality-connections.md
✅ 成功解析 Markdown 输入并生成 Markdown 格式输出

# 测试 5: 验证 Markdown 格式可被正确解析
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --matched-connections tmp/matched_connections.md --top-n 3 -o tmp/test-parse-markdown.md
✅ 成功解析 Markdown 格式文件
```

## 优势

1. **更好的可读性**
   - Markdown 格式在各种编辑器和查看器中都有良好的渲染效果
   - 代码块中的文本保持原有的对齐和格式

2. **统一的格式**
   - 所有命令输出使用相同的 Markdown 格式规范
   - 便于文档管理和版本控制

3. **易于集成**
   - Markdown 格式可以直接嵌入到文档中
   - 支持在 GitHub、GitLab 等平台上直接预览

4. **保持兼容**
   - 不影响现有的解析逻辑
   - 命令之间的依赖关系保持不变
   - 支持旧格式文件的解析

## 注意事项

- 输出文件建议使用 `.md` 扩展名（如 `matched_connections.md`）
- 所有文本内容仍然保持原有的表格格式和对齐
- Markdown 标记不影响文件的解析和处理

