# analyze_pcap.sh - PCAP 分析脚本文档

## 概述

`analyze_pcap.sh` 是一个灵活的 pcap/pcapng 文件分析工具，通过配置文件驱动，自动执行多个 tshark 统计命令并生成分析报告。

## 核心功能

1. **批量分析**: 支持单个文件、多个文件、目录扫描
2. **协议检测**: 自动检测 pcap 中的协议，仅执行相关分析命令
3. **配置驱动**: 通过外部配置文件定义分析命令
4. **智能输出**: 默认输出到输入文件所在目录的 `statistics/` 子目录

## 输入输出

### 输入

- **必需参数**: `-i <input>` 输入文件或目录
  - 单个文件: `-i test.pcap`
  - 多个文件（逗号分隔）: `-i file1.pcap,file2.pcapng`
  - 目录: `-i cases/test/` (自动扫描 pcap/pcapng 文件)
  - 可多次使用 `-i` 参数

- **可选参数**:
  - `-c <config>`: 配置文件路径（默认: `tshark_commands.conf`）
  - `-o <path>`: 输出目录路径
  - `-h`: 显示帮助信息

### 输出

- **输出位置**:
  - 默认: `<输入文件目录>/statistics/`
  - 指定 `-o`: 统一输出到指定目录

- **输出文件命名**: `<文件名>-<序号>-<后缀>`
  - 例如: `example-1-protocol-hierarchy.md`

## 配置文件格式

配置文件 `tshark_commands.conf` 每行一条命令，格式：

```
命令模板::输出文件后缀::协议依赖
```

### 字段说明

1. **命令模板**: tshark 命令，使用 `{INPUT}` 作为输入文件占位符
2. **输出文件后缀**: 生成文件的后缀名
3. **协议依赖**（可选）: 逗号分隔的协议列表
   - 留空或 `all`: 总是执行
   - 单个协议: `dns`, `tcp`, `http` 等
   - 多个协议（OR 关系）: `dns,mdns`

### 配置示例

```bash
# 总是执行
tshark -r {INPUT} -q -z io,phs::protocol-hierarchy.md

# 仅当检测到 DNS 协议时执行
tshark -r {INPUT} -q -z dns,tree::dns-general.md::dns

# 检测到 TCP 协议时执行
tshark -r {INPUT} -q -z conv,tcp::tcp-conversations.md::tcp

# 检测到 DNS 或 MDNS 任一协议时执行
tshark -r {INPUT} -q -z dns,tree::dns-stats.md::dns,mdns
```

## 核心函数

### 1. `detect_protocols()`
- **功能**: 检测 pcap 文件中包含的协议
- **实现**: 使用 `tshark -q -z io,phs` 分析协议层次
- **输出**: 填充全局数组 `DETECTED_PROTOCOLS`

### 2. `protocol_exists()`
- **功能**: 检查协议依赖是否满足
- **逻辑**: 
  - 空或 `all` → 返回成功
  - 检查协议列表中是否至少有一个存在

### 3. `load_config_file()`
- **功能**: 加载配置文件中的 tshark 命令
- **解析**: 按 `::` 分割，提取命令、后缀、协议依赖
- **验证**: 检查格式正确性，跳过注释和空行

### 4. `execute_tshark_command()`
- **功能**: 执行单个 tshark 命令
- **流程**:
  1. 检查协议依赖
  2. 替换 `{INPUT}` 占位符
  3. 构建输出文件路径（带序号前缀）
  4. 执行命令并捕获输出
  5. 返回执行状态

### 5. `process_single_file()`
- **功能**: 处理单个 pcap 文件
- **流程**:
  1. 验证文件格式
  2. 检测协议
  3. 遍历配置命令
  4. 执行匹配的命令
  5. 统计成功/失败/跳过数量

## 关键逻辑

### 协议检测机制

```bash
# 1. 执行协议层次统计
tshark -r "$input_file" -q -z io,phs

# 2. 解析输出，提取协议名称
# 格式: "  tcp                                frames:184 bytes:27279"
# 提取: tcp

# 3. 存储到 DETECTED_PROTOCOLS 数组
```

### 命令过滤逻辑

```bash
# 对每条配置命令:
if protocol_exists "$required_protocol"; then
    execute_tshark_command ...
else
    echo "跳过: 所需协议 [$required_protocol] 不存在"
fi
```

### 输出文件命名

```bash
# 格式: <文件名>-<序号>-<后缀>
output_file="${output_dir}/${base_name}-${sequence_num}-${output_suffix}"

# 例如: example-1-protocol-hierarchy.md
```

## 依赖关系

### 外部依赖

- **tshark**: Wireshark 命令行工具（必需）
- **标准 Unix 工具**: file, basename, mkdir, find 等

### 内部依赖

- **配置文件**: `tshark_commands.conf`（必需）
- **输入文件**: pcap/pcapng 格式

## 错误处理

脚本使用 `set -euo pipefail` 严格模式，处理以下错误：

1. 输入文件不存在或格式错误
2. 配置文件不存在或格式错误
3. 输出目录无法创建或不可写
4. tshark 命令未安装或执行失败

## 使用示例

```bash
# 1. 分析单个文件
./analyze_pcap.sh -i test.pcap

# 2. 分析目录中的所有文件
./analyze_pcap.sh -i cases/test/

# 3. 使用自定义配置文件
./analyze_pcap.sh -i test.pcap -c custom.conf

# 4. 指定输出目录
./analyze_pcap.sh -i test.pcap -o output/

# 5. 批量分析多个案例
./analyze_pcap.sh -i cases/case-001/ -i cases/case-002/ -o batch_results/
```

## 重构建议

### 数据结构

```python
class PcapAnalyzer:
    def __init__(self, config_file):
        self.commands = []  # 分析命令列表
        self.detected_protocols = set()  # 检测到的协议
        
class AnalysisCommand:
    def __init__(self, template, suffix, protocols):
        self.template = template  # 命令模板
        self.suffix = suffix      # 输出后缀
        self.protocols = protocols  # 协议依赖列表
```

### 核心接口

```python
def detect_protocols(pcap_file: str) -> Set[str]:
    """检测 pcap 文件中的协议"""
    
def load_config(config_file: str) -> List[AnalysisCommand]:
    """加载配置文件"""
    
def execute_command(pcap_file: str, command: AnalysisCommand, 
                   output_dir: str, sequence: int) -> bool:
    """执行单个分析命令"""
    
def analyze_pcap(pcap_file: str, config_file: str, 
                output_dir: str) -> Dict[str, Any]:
    """分析单个 pcap 文件"""
```

### 关键考虑

1. **并发执行**: 多个命令可以并行执行
2. **进度报告**: 提供实时进度反馈
3. **结果缓存**: 避免重复检测协议
4. **错误恢复**: 单个命令失败不影响其他命令
5. **配置验证**: 启动时验证配置文件格式

## 性能特性

- **批量处理**: 支持一次处理多个文件
- **智能过滤**: 仅执行相关协议的命令
- **错误容忍**: 单个文件失败不影响其他文件
- **输出覆盖**: 自动覆盖已存在的输出文件

## 限制和注意事项

1. **配置文件查找顺序**: 脚本所在目录 → 当前工作目录
2. **文件覆盖**: 输出文件已存在时会直接覆盖
3. **协议检测**: 基于 `io,phs` 统计，可能遗漏某些协议
4. **命令执行**: 使用 `eval` 执行，需确保配置文件可信

