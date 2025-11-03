# remove_one_way_tcp.sh - 单向 TCP 连接过滤工具文档

## 概述

`remove_one_way_tcp.sh` 是一个用于去除 pcap/pcapng 文件中因捕获丢失导致的单向 TCP 连接噪音的工具。这些连接实际上是双向传输，但由于捕获点位置或配置问题，只捕获到了一个方向的流量。

## 核心功能

1. **单向连接识别**: 基于启发式规则识别仅捕获单方向的 TCP 连接
2. **批量处理**: 支持单个文件、多个文件、目录扫描
3. **智能过滤**: 仅过滤识别到的单向连接，保留正常连接
4. **性能优化**: 使用 AWK 批量处理，避免逐个流调用 tshark

## 输入输出

### 输入

- **必需参数**: `-i <input>` 输入文件或目录
  - 单个文件: `-i test.pcap`
  - 多个文件（逗号分隔）: `-i file1.pcap,file2.pcapng`
  - 目录: `-i cases/test/` (自动扫描目录及子目录下的 pcap/pcapng 文件)
  - 可多次使用 `-i` 参数

- **可选参数**:
  - `-o <path>`: 输出目录路径（默认: 原文件所在目录）
  - `-t <num>`: ACK 增量阈值（默认: 20，建议 ≥ 20）
  - `-h`: 显示帮助信息

### 输出

- **输出文件命名**: `<原文件名>-OWTR.<扩展名>`
  - 例如: `capture.pcap` → `capture-OWTR.pcap`

- **输出行为**:
  - 发现单向连接: 创建过滤后的文件
  - 未发现单向连接: 不创建输出文件

## 识别逻辑

脚本使用以下逻辑识别单向 TCP 连接（实际为双向传输）:

### 判定条件

1. **方向性检查**: 仅存在 A→B（或仅 B→A）报文，反向计数为 0
2. **ACK 增量计算**: 
   - 取该方向第一个与最后一个报文的 ACK
   - 计算 32 位无符号差 `ack_delta`
   - 处理 ACK 序号回绕
3. **形态学证据**: 存在 ≥1 个纯 ACK（tcp.len==0）且 ACK 上升的报文
4. **阈值判断**: `ack_delta > threshold`（默认阈值为 20）
5. **命中判定**: 满足以上所有条件即判为"仅捕获单方向"

### 识别原理

```
正常双向连接:
  A → B: SYN
  B → A: SYN-ACK
  A → B: ACK
  A → B: Data
  B → A: ACK
  ...

单向捕获（实际为双向）:
  A → B: SYN
  A → B: ACK (ACK 值增加，说明收到了 B→A 的 SYN-ACK，但未捕获)
  A → B: Data
  A → B: ACK (ACK 值增加，说明收到了 B→A 的 ACK，但未捕获)
  ...
```

## 核心函数

### 1. `identify_one_way_tcp_streams()`
- **功能**: 识别单向 TCP 连接
- **输入**: pcap 文件路径, ACK 增量阈值
- **输出**: 单向 TCP 流的 stream ID 列表
- **实现**:
  1. 一次性提取所有 TCP 报文信息
  2. 使用 AWK 批量分析
  3. 统计每个流的方向报文数
  4. 计算 ACK 增量
  5. 检查纯 ACK 报文
  6. 应用阈值判断

### 2. `process_single_file()`
- **功能**: 处理单个 pcap 文件
- **输入**: pcap 文件路径, 输出目录, ACK 阈值
- **输出**: 过滤后的 pcap 文件
- **流程**:
  1. 验证文件格式
  2. 识别单向 TCP 流
  3. 构建过滤表达式
  4. 执行 tshark 过滤
  5. 保存过滤后的文件

## 关键逻辑

### AWK 批量分析

```awk
# 1. 统计方向报文数
direction = src_ip ":" src_port "->" dst_ip ":" dst_port
dir_count[stream ":" direction]++

# 2. 记录 ACK 信息
if (ack != "" && ack != "0"):
    if (!(key in first_ack)):
        first_ack[key] = ack
    last_ack[key] = ack
    
    # 检查纯 ACK
    if (tcp_len == "0"):
        if (key in prev_ack && ack > prev_ack[key]):
            has_pure_ack[key] = 1

# 3. 分析每个流
for (stream in stream_first_dir):
    forward_count = dir_count[forward_key]
    reverse_count = dir_count[reverse_key]
    
    # 检查是否为单向流
    if (forward_count == 0 || reverse_count == 0):
        # 计算 ACK 增量
        ack_delta = last_ack - first_ack
        
        # 检查阈值和纯 ACK
        if (ack_delta > threshold && has_pure_ack):
            print stream
```

### ACK 回绕处理

```awk
# 处理 32 位无符号整数回绕
if (l_ack >= f_ack):
    ack_delta = l_ack - f_ack
else:
    ack_delta = 4294967296 + l_ack - f_ack
```

### 过滤表达式构建

```bash
# 构建 tshark 过滤表达式
filter=""
for stream_id in one_way_streams:
    if [ -z "$filter" ]:
        filter="tcp.stream != $stream_id"
    else:
        filter="$filter and tcp.stream != $stream_id"

# 执行过滤
tshark -r input.pcap -Y "$filter" -w output.pcap
```

## 依赖关系

### 外部依赖

- **tshark**: Wireshark 命令行工具（必需）
- **bash**: 版本 3.2+（macOS 默认版本）
- **awk**: 标准 AWK 或 GNU AWK

### 内部依赖

- **临时目录**: 使用 `mktemp -d` 创建
- **临时文件**: 存储中间分析结果

## 使用示例

```bash
# 1. 处理单个文件
./remove_one_way_tcp.sh -i test.pcap

# 2. 处理单个文件并指定输出目录
./remove_one_way_tcp.sh -i test.pcap -o output/

# 3. 处理多个文件
./remove_one_way_tcp.sh -i file1.pcap,file2.pcapng

# 4. 处理目录中的所有文件
./remove_one_way_tcp.sh -i cases/test/

# 5. 使用自定义阈值
./remove_one_way_tcp.sh -i test.pcap -t 100

# 6. 批量处理多个案例
./remove_one_way_tcp.sh -i cases/case-001/ -i cases/case-002/ -o results/
```

## 重构建议

### 数据结构

```python
class TcpStream:
    def __init__(self):
        self.stream_id = 0
        self.forward_count = 0
        self.reverse_count = 0
        self.first_ack = 0
        self.last_ack = 0
        self.has_pure_ack = False
        self.direction = ""  # "src_ip:src_port -> dst_ip:dst_port"

class OneWayDetector:
    def __init__(self, threshold=20):
        self.threshold = threshold
        self.streams = {}  # stream_id -> TcpStream
```

### 核心接口

```python
def extract_tcp_packets(pcap_file: str) -> List[Dict]:
    """提取 TCP 报文信息"""
    
def analyze_stream_directions(packets: List[Dict]) -> Dict[int, TcpStream]:
    """分析 TCP 流的方向性"""
    
def identify_one_way_streams(streams: Dict[int, TcpStream], 
                            threshold: int) -> List[int]:
    """识别单向 TCP 流"""
    
def filter_pcap(input_file: str, output_file: str, 
               exclude_streams: List[int]) -> bool:
    """过滤 pcap 文件"""
```

### 关键考虑

1. **准确性**: 阈值设置需根据实际场景调整
2. **性能**: 使用批量处理避免多次调用 tshark
3. **兼容性**: 处理 ACK 序号回绕
4. **错误处理**: 处理无 TCP 报文的情况
5. **输出控制**: 仅在发现单向连接时创建输出文件

## 性能特性

- **批量处理**: 一次性提取所有 TCP 报文信息
- **AWK 优化**: 使用 AWK 进行高效数据处理
- **内存效率**: 仅存储必要的统计信息
- **适用规模**: 适用于包含数千个 TCP 流的大型 pcap 文件

## 限制和注意事项

1. **阈值设置**: 
   - 默认阈值 20 适用于大多数场景
   - 高流量环境可适当提高阈值（如 100）

2. **准确性**:
   - 基于启发式规则，可能存在误判
   - 建议在测试数据上验证

3. **文件覆盖**: 
   - 输出文件已存在时会被覆盖
   - 建议使用不同的输出目录或备份原文件

4. **性能考虑**:
   - 处理大文件（> 1GB）可能需要较长时间
   - 建议在性能较好的机器上运行

5. **依赖版本**:
   - 支持 bash 3.2+（macOS 默认版本）
   - 需要 tshark 命令行工具

## 典型应用场景

1. **防火墙捕获**: 仅捕获单方向流量的防火墙
2. **镜像端口**: 配置不当的镜像端口
3. **单向链路**: 物理上的单向链路
4. **捕获丢失**: 捕获过程中丢失部分报文

## 输出示例

```
========================================
处理文件: test.pcap
========================================
分析 TCP 连接...
发现单向 TCP 流: stream=5 (192.168.1.10:12345->10.0.0.1:80) ack_delta=1500
发现单向 TCP 流: stream=12 (192.168.1.20:54321->10.0.0.2:443) ack_delta=2000
总计发现 2 个单向 TCP 流
过滤并保存到: test-OWTR.pcap
✓ 成功创建过滤后的文件

========================================
执行总结
========================================
总文件数: 1
成功处理: 1
已过滤: 1
处理失败: 0
========================================
```

