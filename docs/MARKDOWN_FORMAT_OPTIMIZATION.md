# Markdown 格式优化

## 概述

将四个命令的输出格式统一改为 Markdown 格式，使用 `## 标题` 和 ` ```text ``` ` 代码块包裹正文内容。

## 优化的命令

### 1. Match 命令（普通匹配）
```bash
capmaster match -i /Users/ricky/Downloads/2hops/dbs_1112_2/ -o tmp/matched_connections.md
```

**输出格式：**
```markdown
## TCP Connection Matching Results

```text
Statistics:
  Total connections (file 1): 212
  Total connections (file 2): 214
  ...

Matched Connections:
----------------------------------------------------
No.    Stream A   Client A   ...
----------------------------------------------------
1      7          10.93...   ...
...
```
```

### 2. Match 命令（拓扑分析）
```bash
capmaster match -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --topology -o tmp/topology.md
```

**输出格式：**
```markdown
## Network Topology

```text
Capture Point A: 10.93.75.130_SNAT.pcap
Capture Point B: 10.93.75.130_VIP.pcap

Client(...) -> Capture Point B -> (...) Network Device(...) -> Capture Point A -> Server (...)
```
```

### 3. Comparative Analysis（服务级别）
```bash
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --service --topology tmp/topology.md -o tmp/service-network-quality.md
```

**输出格式：**
```markdown
## Network Quality Analysis Report

```text
File A: 10.93.75.130_SNAT.pcap
File B: 10.93.75.130_VIP.pcap

Summary:
----------------------------------------------------
Total services analyzed: 2

Service Quality Metrics:
----------------------------------------------------
Service                File   Direction       Packets    Retrans      Dup ACK      Lost Seg    
----------------------------------------------------
...
```
```

### 4. Comparative Analysis（连接对级别）
```bash
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --matched-connections tmp/matched_connections.md --top-n 10 -o tmp/poor-quality-connections.md
```

**输出格式：**
```markdown
## Connection Pair Quality Analysis Report

```text
File A: 10.93.75.130_SNAT.pcap
File B: 10.93.75.130_VIP.pcap

Summary:
------------------------------------------------------------------------
Total connection pairs analyzed: 139
Showing top 10 worst performing connection pairs

Top 10 Worst Performing Connection Pairs:
------------------------------------------------------------------------
Pair#   Stream   Connection   File   Dir   Pkts   Retrans   DupACK   LostSeg   Score   Conf  
------------------------------------------------------------------------
...
```
```

## 技术实现

### 修改的文件

1. **capmaster/plugins/match/plugin.py**
   - `_output_results()` 方法：添加 Markdown 标题和代码块

2. **capmaster/plugins/match/topology.py**
   - `format_topology()` 函数：添加 Markdown 标题和代码块

3. **capmaster/plugins/match/quality_analyzer.py**
   - `format_quality_report()` 函数：添加 Markdown 标题和代码块
   - `format_connection_pair_report()` 函数：添加 Markdown 标题和代码块

### 关键变更

所有格式化函数都遵循相同的模式：

1. 开头添加 `## 标题`
2. 空行
3. 开始代码块 ` ```text `
4. 原有的文本内容（保持不变）
5. 结束代码块 ` ``` `

## 兼容性

### 向后兼容
- 新格式的 Markdown 文件可以被后续命令正确解析
- `parse_matched_connections()` 函数已支持解析 Markdown 格式的文件
- 所有命令之间的输入输出依赖关系保持不变

### 依赖关系
1. `match` → `matched_connections.md` → `comparative-analysis --matched-connections`
2. `match --topology` → `topology.md` → `comparative-analysis --service --topology`

## 测试验证

所有四个命令已通过测试：

```bash
# 测试 1: 匹配连接
capmaster match -i /Users/ricky/Downloads/2hops/dbs_1112_2/ -o tmp/matched_connections.md

# 测试 2: 拓扑分析
capmaster match -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --topology -o tmp/topology.md

# 测试 3: 服务级别分析
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --service --topology tmp/topology.md -o tmp/service-network-quality.md

# 测试 4: 连接对级别分析
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --matched-connections tmp/matched_connections.md --top-n 10 -o tmp/poor-quality-connections.md

# 测试 5: 验证新格式可被解析
capmaster comparative-analysis -i /Users/ricky/Downloads/2hops/dbs_1112_2/ --matched-connections tmp/matched_connections.md --top-n 5 -o tmp/test-new-format.md
```

所有测试均成功通过，新格式输出正确且可被后续命令正确解析。

## 优势

1. **更好的可读性**：Markdown 格式在各种编辑器和查看器中都有良好的渲染效果
2. **统一的格式**：所有命令输出使用相同的格式规范
3. **代码高亮**：文本内容在代码块中，便于复制和查看
4. **保持兼容**：不影响现有的解析逻辑和命令依赖关系

