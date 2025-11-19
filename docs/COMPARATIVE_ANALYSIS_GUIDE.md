# 对比分析功能 (Comparative Analysis)

## 概述

对比分析功能用于对比分析两个 PCAP 文件之间的差异和网络质量指标。支持两种分析模式：
- **服务级别对比** (`--service`): 按服务聚合统计网络质量
- **连接对对比** (`--matched-connections`): 为每一对匹配的连接统计网络质量

> **Scope（范围）**：说明对比分析子命令的外部行为、主要参数及输出结构。
> **Contract（契约）**：约定输入/输出格式和关键指标含义（丢包率、重传率等），不保证在此维护完整实现细节。
> **Implementation Pointers**：需要精确逻辑时，请查看 comparative-analysis 插件的实现代码以及相应测试用例。
> **Maintenance**：当新增/移除参数或调整输出字段时，更新示例命令和指标说明；协议/模块列表以代码为准，不在文档重复维护。

## 功能特性

- **对比分析**: 同时分析两个 PCAP 文件，识别差异和质量指标
- **服务级别对比** (`--service`):
  - 按照 serverIP:serverPort 聚合统计数据
  - 区分客户端→服务器和服务器→客户端两个方向
  - 统计多种质量指标：
    - 丢包率 (Packet Loss Rate)
    - 重传率 (Retransmission Rate)
    - 重复确认率 (Duplicate ACK Rate)
- **连接对对比** (`--matched-connections`):
  - 为每一对匹配的连接单独统计质量指标
  - 支持从 `capmaster match` 命令生成的匹配连接文件
  - 显示每对连接的详细质量对比
- **组合分析**: 可同时使用 `--service` 和 `--matched-connections` 生成综合报告
- **智能输出**: 只显示有实际流量的 PCAP 文件的统计信息
- **灵活输入**: 支持目录、文件列表或显式指定文件
- **格式化报告**: 清晰的报告输出，支持保存到文件或标准输出

## 使用方法

### 服务级别对比分析

```bash
# 使用目录输入（推荐）
capmaster comparative-analysis \
    -i <directory_with_2_pcap_files> \
    --service \
    --topology <topology_file>

# 使用显式文件指定
capmaster comparative-analysis \
    --file1 <pcap_file_1> \
    --file2 <pcap_file_2> \
    --service \
    --topology <topology_file>
```

### 连接对对比分析

```bash
# 使用匹配连接文件
capmaster comparative-analysis \
    -i <directory_with_2_pcap_files> \
    --matched-connections <matched_connections_file>

# 先生成匹配连接文件，再进行分析
capmaster match -i /path/to/pcaps/ -o matched_connections.txt
capmaster comparative-analysis \
    -i /path/to/pcaps/ \
    --matched-connections matched_connections.txt

# 只显示性能最差的 Top N 连接对
capmaster comparative-analysis \
    -i /path/to/pcaps/ \
    --matched-connections matched_connections.txt \
    --top-n 10
```

### 组合分析（服务 + 连接对）

```bash
# 同时进行服务级别和连接对级别的对比分析
capmaster comparative-analysis \
    -i /path/to/pcaps/ \
    --service \
    --topology topology.txt \
    --matched-connections matched_connections.txt \
    -o combined_report.txt
```

### 保存结果到文件

```bash
capmaster comparative-analysis \
    -i /path/to/pcaps/ \
    --service \
    --topology topology.txt \
    -o report.txt
```

## 参数说明

- `-i, --input`: 输入目录或逗号分隔的 PCAP 文件列表（包含恰好 2 个文件）
- `--file1`: 第一个 PCAP 文件路径（与 `-i` 二选一）
- `--file2`: 第二个 PCAP 文件路径（与 `-i` 二选一）
- `--service`: 执行服务级别的对比分析（需要配合 `--topology`）
- `--matched-connections`: 匹配连接文件路径，用于连接对级别的对比分析
- `--top-n`: 显示性能最差的 Top N 连接对（仅与 `--matched-connections` 一起使用）
- `--topology`: 拓扑文件路径，包含服务信息（`--service` 分析时必需）
- `-o, --output`: 输出文件路径（可选，默认输出到标准输出）

## 生成拓扑文件

`--service` 模式需要一个拓扑文件，可通过以下流程生成：

```bash
# Step 1: 匹配连接，产出 matched_connections.txt
capmaster match -i /path/to/pcaps/ -o matched_connections.txt

# Step 2: 读取匹配结果并生成 topology.txt
capmaster topology \
    -i /path/to/pcaps/ \
    --matched-connections matched_connections.txt \
    -o topology.txt
```

对于只有单个抓包点的排障场景，可直接执行：

```bash
capmaster topology --single-file single_capture.pcap -o single_topology.txt
```

## 拓扑文件格式

拓扑文件应包含服务的 IP 地址和端口信息。程序会自动提取所有符合 `IP:Port` 格式的服务。

示例拓扑文件 (`topology.txt`):

```
================================================================================
Network Topology
================================================================================

Capture Point A: capture_a.pcap
Capture Point B: capture_b.pcap

Client -> Capture Point A -> Network Device(10.93.137.244) -> Capture Point B -> Server (10.93.75.130:8443)
Client -> Capture Point A -> Network Device(10.93.136.244:443) -> Capture Point B -> Server (192.168.1.100:80)

================================================================================
```

程序会自动提取以下服务：
- 10.93.75.130:8443
- 10.93.136.244:443
- 192.168.1.100:80

## 输出格式

输出报告包含以下信息：

1. **摘要信息**
   - 分析的 PCAP 文件名
   - 分析的服务总数

2. **每个服务的详细指标**
   - 服务标识 (IP:Port)
   - 两个 PCAP 文件的分别统计
   - 每个方向的指标：
     - 总数据包数
     - 重传数量和比率
     - 重复 ACK 数量和比率
     - 丢包数量和比率

### 输出示例

```
============================================================================================================================================
Network Quality Analysis Report
============================================================================================================================================

File A: capture_point_a.pcap
File B: capture_point_b.pcap

Summary:
--------------------------------------------------------------------------------------------------------------------------------------------
Total services analyzed: 2

Per-Service Quality Metrics:
============================================================================================================================================

Service: 10.93.75.130:8443
--------------------------------------------------------------------------------------------------------------------------------------------

  File A (capture_point_a.pcap):
    Client -> Server:
      Total Packets:        1,000
      Retransmissions:      10 (1.00%)
      Duplicate ACKs:       5 (0.50%)
      Lost Segments:        3 (0.30%)

    Server -> Client:
      Total Packets:        1,000
      Retransmissions:      8 (0.80%)
      Duplicate ACKs:       4 (0.40%)
      Lost Segments:        2 (0.20%)

  File B (capture_point_b.pcap):
    Client -> Server:
      Total Packets:        1,200
      Retransmissions:      15 (1.25%)
      Duplicate ACKs:       7 (0.58%)
      Lost Segments:        4 (0.33%)

    Server -> Client:
      Total Packets:        1,200
      Retransmissions:      12 (1.00%)
      Duplicate ACKs:       6 (0.50%)
      Lost Segments:        3 (0.25%)

============================================================================================================================================
```

## 技术实现

### TCP 分析字段

程序使用 tshark 提取以下 TCP 分析字段：

- `tcp.analysis.retransmission`: TCP 重传
- `tcp.analysis.duplicate_ack`: 重复 ACK
- `tcp.analysis.lost_segment`: 丢失的数据段

### 方向判断

- **客户端→服务器**: 目标 IP:Port 匹配服务定义
- **服务器→客户端**: 源 IP:Port 匹配服务定义

### 指标计算

所有比率按以下公式计算：

```
Rate (%) = (Event Count / Total Packets) × 100
```

### 性能评分

在连接对分析中，系统会为每个连接对计算性能评分（0-100 分）：

- **评分算法**: 基于重传率、重复 ACK 率和丢包率的加权平均
  - 重传率权重: 40%
  - 重复 ACK 率权重: 30%
  - 丢包率权重: 30%
- **评分含义**:
  - 100 分: 完美性能，无任何网络质量问题
  - 90-99 分: 优秀性能，偶尔有轻微问题
  - 80-89 分: 良好性能，有一定的网络质量问题
  - 70-79 分: 一般性能，网络质量问题较明显
  - < 70 分: 较差性能，存在严重的网络质量问题
- **Top-N 排序**: 使用 `--top-n` 参数时，按性能评分从低到高排序，显示最差的 N 个连接对

## 使用场景

1. **网络故障诊断**: 识别网络中的丢包和重传问题
2. **性能对比**: 对比不同抓包点的网络质量
3. **服务质量监控**: 监控特定服务的网络健康状况
4. **容量规划**: 评估网络负载和质量趋势

## 注意事项

1. 确保 PCAP 文件包含完整的 TCP 会话
2. 拓扑文件中的服务必须在 PCAP 文件中存在
3. 如果所有指标都是 0%，可能表示：
   - 网络质量非常好（无丢包、重传）
   - 服务定义不正确
   - PCAP 文件不包含相关流量
