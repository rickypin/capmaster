# match_tcp_conns.sh - TCP 连接跨捕获点匹配工具文档

## 概述

`match_tcp_conns.sh` 是一个高级 TCP 连接匹配工具，用于在两个不同捕获点的 pcap 文件中识别同一 TCP 连接。支持 NAT 场景、header-only 截断 pcap，基于 TCP/IP 层多维度指纹进行连接匹配。

## 核心功能

1. **跨捕获点匹配**: 识别两个 pcap 文件中的相同 TCP 连接
2. **NAT 场景支持**: 自动检测并适配 NAT/负载均衡场景
3. **Header-only 检测**: 自动识别仅包含头部的 pcap 文件
4. **智能采样**: 大规模连接时自动采样以提升性能
5. **多维度指纹**: 基于 TCP/IP 层多个特征进行匹配

## 输入输出

### 输入

- **必需参数**: `-i <input>` 输入目录（必须包含有且只有 2 个 pcap/pcapng 文件）
- **可选参数**:
  - `-o <path>`: 输出目录路径（默认: `<输入目录>/statistics/`）
  - `--mode auto|full|header`: 匹配模式（默认: auto）
  - `--bucket auto|server|port`: 分桶策略（默认: auto）
  - `--sample auto|off|N`: 采样策略（默认: auto）
  - `--topN N`: 长度形状签名的包数量（默认: 20）
  - `--len-sig N`: 长度形状签名 token 数上限（默认: 12）
  - `--min-score N`: 最低匹配分数阈值（默认: 0.60）

### 输出

- **输出文件**: `<输出目录>/correlations.txt`
- **输出格式**:
  ```
  [1] A: 192.168.1.10:12345 <-> 10.0.0.1:80
      B: 172.16.0.5:54321 <-> 10.0.0.1:80
      置信度: 0.95 | 证据: synopt isnC dataC ipid
  ```

## 匹配特征权重（v3.0）

| 特征 | 权重 | 说明 |
|------|------|------|
| **IPID 匹配** | 16% | **必要条件**，无 IPID 直接拒绝 |
| SYN 选项序列 | 25% | MSS, WScale, SACK, Timestamp |
| 客户端 ISN | 12% | 初始序列号 |
| 服务器 ISN | 6% | 初始序列号 |
| TCP 时间戳 | 10% | TSval/TSecr |
| 客户端首包负载 | 15% | MD5 哈希（前 256 字节） |
| 服务器首包负载 | 8% | MD5 哈希（前 256 字节） |
| 长度形状签名 | 8% | 前 N 个包的长度序列 |

**总权重**: 1.00

## 核心函数

### 1. `extract_fields()`
- **功能**: 提取 TCP 报文字段
- **输入**: pcap 文件路径, 输出 TSV 文件路径
- **输出**: TSV 格式的报文字段（25+ 字段）
- **关键字段**:
  - `tcp.stream`: TCP 流编号
  - `frame.time_epoch`: 时间戳
  - `ip.src/ip.dst`: IP 地址
  - `tcp.srcport/dstport`: 端口
  - `tcp.flags.syn/ack`: TCP 标志
  - `tcp.seq/ack`: 序列号
  - `tcp.options.*`: TCP 选项
  - `ip.id`: IP 标识符（IPID）
  - `frame.cap_len/len`: 捕获/实际长度
  - `data.data`: 负载数据（十六进制）

### 2. `build_conn_table()`
- **功能**: 构建连接特征表
- **输入**: TSV 报文数据, 侧标识(A/B), 输出文件, topN, lenSig
- **输出**: 连接特征表（每行一个连接）
- **主要逻辑**:
  1. 按 `tcp.stream` 分组
  2. 识别握手（SYN, SYN-ACK）
  3. 提取客户端/服务器 IP:端口
  4. 计算各维度指纹
  5. 检测 header-only
  6. 输出连接特征

### 3. `sample_connections()`
- **功能**: 时间分层采样 + 异常连接保护
- **输入**: 连接表, 侧标识, 输出文件, 目标数量
- **输出**: 采样后的连接表
- **采样策略**:
  1. 识别异常连接（报文数 ≤3 或 ≥500）
  2. 将正常连接按时间分成 20 个桶
  3. 每个桶按比例随机采样
  4. 保留所有异常连接

### 4. `score_pair()`
- **功能**: 计算两个连接的相似度分数
- **输入**: A 侧连接, B 侧连接
- **输出**: "分数\t可用权重\t证据"
- **评分逻辑**:
  1. **IPID 必要条件检查**: 没有 IPID 匹配直接返回 0 分
  2. 计算各特征分数
  3. 置信度 = 匹配分数 / 可用权重
  4. 返回分数、可用权重、证据列表

## 自动检测策略

### 1. Header-only 检测

```awk
header_only = (cap_bad_cnt > 0 && cap_bad_cnt * 1.0 / total_cnt >= 0.80) ? 1 : 0
```

- 统计 `frame.cap_len < frame.len` 的报文比例
- 超过 80% 判定为 header-only

### 2. 分桶策略检测

```bash
if 服务器IP完全相同:
    BUCKET="server"  # 高精度
elif 有共同端口:
    BUCKET="port"    # NAT/LB友好
else:
    BUCKET="server"  # 警告
```

### 3. 采样策略

```bash
if 连接数 > 1000:
    启用时间分层采样（10%，最多3000个）
    保护异常连接（报文数<=3 或 >=500）
```

## 关键逻辑

### 连接特征提取

```awk
# 1. 识别握手
if (SYN && !ACK):
    client_ip = src_ip
    server_ip = dst_ip
    synopt = "mss=1460;ws=7;sack=1;ts=1"
    isn_c = seq

if (SYN && ACK):
    isn_s = seq

# 2. 计算负载哈希
if (tcp.len > 0 && data != ""):
    data_md5 = md5(data[0:256])

# 3. 长度形状签名
lensig = "C:100 S:200 C:50 S:150 ..."

# 4. IPID 和 TTL
ipid0 = first_packet.ip.id
ttl0 = first_packet.ip.ttl
```

### 匹配评分

```awk
# 1. IPID 必要条件
if (!ipid_match):
    return "0\t0\tno-ipid"

# 2. 计算各特征分数
raw = 0
avail = 0

if (synopt_A == synopt_B):
    raw += 0.25
    avail += 0.25

if (isn_c_A == isn_c_B):
    raw += 0.12
    avail += 0.12

# ... 其他特征

# 3. 计算置信度
score = raw / avail
```

### 贪心匹配

```awk
# 1. 计算所有候选对的评分
for (i in A_conns):
    for (j in B_conns):
        score = score_pair(A[i], B[j])
        if (score >= MIN_SCORE):
            candidates.add((i, j, score))

# 2. 按分数降序排序
candidates.sort(by=score, desc=True)

# 3. 贪心一一匹配
for (i, j, score) in candidates:
    if (!used_A[i] && !used_B[j]):
        output_match(A[i], B[j], score)
        used_A[i] = True
        used_B[j] = True
```

## 依赖关系

### 外部依赖

- **tshark**: >= 4.2（推荐）
- **awk**: GNU awk 或兼容版本
- **sort**: 标准 Unix 工具
- **xxd**: 十六进制转换工具
- **md5sum**: MD5 哈希工具

### 内部依赖

- **临时目录**: 使用 `mktemp -d` 创建
- **trap 清理**: 自动清理临时文件

## 使用示例

```bash
# 1. 基本用法（自动检测所有策略）
./match_tcp_conns.sh -i cases/test/

# 2. 指定输出目录
./match_tcp_conns.sh -i cases/test/ -o output/

# 3. 仅使用 header 特征
./match_tcp_conns.sh -i cases/test/ --mode header

# 4. 使用 port 分桶（NAT 场景）
./match_tcp_conns.sh -i cases/test/ --bucket port

# 5. 强制采样到 1000 个连接
./match_tcp_conns.sh -i cases/test/ --sample 1000

# 6. 提高最低分数阈值
./match_tcp_conns.sh -i cases/test/ --min-score 0.70
```

## 重构建议

### 数据结构

```python
class TcpConnection:
    def __init__(self):
        self.stream_id = 0
        self.five_tuple = ""  # "client_ip:client_port <-> server_ip:server_port"
        self.synopt = ""      # SYN 选项序列
        self.isn_c = 0        # 客户端 ISN
        self.isn_s = 0        # 服务器 ISN
        self.ts0 = 0          # TCP 时间戳
        self.data_c_md5 = ""  # 客户端首包负载 MD5
        self.data_s_md5 = ""  # 服务器首包负载 MD5
        self.lensig = ""      # 长度形状签名
        self.ipid0 = 0        # 首包 IPID
        self.ttl0 = 0         # 首包 TTL
        self.header_only = False  # 是否为 header-only

class ConnectionMatcher:
    def __init__(self, mode, bucket, sample, min_score):
        self.mode = mode
        self.bucket = bucket
        self.sample = sample
        self.min_score = min_score
```

### 核心接口

```python
def extract_tcp_fields(pcap_file: str) -> List[Dict]:
    """提取 TCP 报文字段"""
    
def build_connection_table(packets: List[Dict]) -> List[TcpConnection]:
    """构建连接特征表"""
    
def sample_connections(conns: List[TcpConnection], 
                      target: int) -> List[TcpConnection]:
    """时间分层采样"""
    
def score_pair(conn_a: TcpConnection, 
              conn_b: TcpConnection) -> Tuple[float, str]:
    """计算相似度分数"""
    
def match_connections(conns_a: List[TcpConnection], 
                     conns_b: List[TcpConnection],
                     min_score: float) -> List[Tuple]:
    """匹配连接"""
```

### 关键考虑

1. **性能优化**: 大规模连接时的采样和分桶策略
2. **准确性**: IPID 作为必要条件，权重调整
3. **可扩展性**: 易于添加新的匹配特征
4. **可调试性**: 提供详细的匹配证据和中间结果
5. **容错性**: 处理 header-only、NAT 等特殊场景

## 性能特性

| 场景 | 连接数 | 处理时间 | 内存占用 | 优化策略 |
|------|--------|----------|----------|----------|
| 小规模 | < 100 | < 5秒 | < 50MB | 无需优化 |
| 中规模 | 100-1000 | 5-30秒 | 50-200MB | 默认设置 |
| 大规模 | 1000-10000 | 30-300秒 | 200MB-1GB | 自动采样 |
| 超大规模 | > 10000 | > 300秒 | > 1GB | 强制采样 |

## 限制和注意事项

1. **输入限制**: 必须有且只有 2 个 pcap 文件
2. **IPID 依赖**: IPID 是必要条件，无 IPID 无法匹配
3. **NAT 场景**: 需使用 `--bucket port` 或 `auto`
4. **性能**: 大规模连接建议启用采样
5. **准确性**: 基于启发式规则，可能存在误判

