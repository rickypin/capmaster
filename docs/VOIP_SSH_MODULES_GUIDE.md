# VoIP 和 SSH 分析模块使用指南

本文档介绍新增的三个优先级1协议分析模块：SIP、RTP 和 SSH 统计分析模块。

---

## 概述

根据 `PROTOCOL_COVERAGE_REPORT.md` 中的优先级1协议，我们实现了以下三个分析模块：

| 模块 | 协议 | 用途 | 测试案例 |
|------|------|------|---------|
| `sip_stats.py` | SIP | SIP 会话统计，识别 SIP 错误码 | V-001 |
| `rtp_stats.py` | RTP | RTP 流质量分析，识别 VoIP 质量问题 | V-001 |
| `ssh_stats.py` | SSH | SSH 连接统计，安全分析 | V-001 |

---

## 1. SIP 统计模块 (sip_stats.py)

### 功能

分析 SIP (Session Initiation Protocol) 消息，提取：
- **SIP 方法**：INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER 等
- **SIP 响应码**：1xx, 2xx, 3xx, 4xx, 5xx, 6xx
- **连接信息**：源/目标 IP 和端口

### 错误识别

SIP 响应码分类：
- **1xx (临时响应)**：100 Trying, 180 Ringing, 183 Session Progress
- **2xx (成功)**：200 OK
- **3xx (重定向)**：300 Multiple Choices, 301 Moved Permanently
- **4xx (客户端错误)**：⚠ 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 408 Request Timeout
- **5xx (服务器错误)**：⚠ 500 Server Internal Error, 503 Service Unavailable
- **6xx (全局失败)**：⚠ 600 Busy Everywhere, 603 Decline

### 输出示例

```
======================================================================
SIP Statistics
======================================================================

SIP Methods (Requests):
----------------------------------------------------------------------
Method                    Count
----------------------------------------------------------------------
OPTIONS                      10
INVITE                        5
BYE                          5

SIP Response Codes:
----------------------------------------------------------------------
Status Code               Count
----------------------------------------------------------------------
200                          15
404                           2  ⚠ Client Error
503                           1  ⚠ Server Error

======================================================================
Summary:
  Total SIP Requests:  20
  Total SIP Responses: 18
  Unique Methods:      3
  Unique Status Codes: 3
======================================================================
```

### 使用方法

```bash
# 分析包含 SIP 流量的 PCAP 文件
capmaster analyze -i voip_traffic.pcap

# 查看 SIP 统计结果
cat statistics/voip_traffic-1-sip-stats.txt
```

### 错误诊断

- **404 Not Found**：目标用户不存在或无法找到
- **408 Request Timeout**：请求超时，可能网络延迟过高
- **480 Temporarily Unavailable**：被叫方暂时不可用
- **486 Busy Here**：被叫方忙
- **503 Service Unavailable**：服务器过载或维护中
- **603 Decline**：被叫方拒绝呼叫

---

## 2. RTP 统计模块 (rtp_stats.py)

### 功能

分析 RTP (Real-time Transport Protocol) 流，提取：
- **流信息**：SSRC, 负载类型, 数据包数量
- **质量指标**：
  - 丢包率 (Packet Loss)
  - 抖动 (Jitter)
  - 时间间隔 (Delta timing)
- **端点信息**：源/目标 IP 和端口

### 质量评估标准

| 指标 | 良好 | 一般 | 差 |
|------|------|------|-----|
| 丢包率 | < 1% | 1-5% | > 5% |
| 平均抖动 | < 20ms | 20-30ms | > 30ms |
| 最大抖动 | < 50ms | 50-100ms | > 100ms |

### 输出示例

```
====================================================================================================
RTP Stream Statistics
====================================================================================================

Quality Analysis:
----------------------------------------------------------------------------------------------------

Stream 1: 10.135.65.10:16676 -> 10.128.131.17:19490
  Packets: 2776, Lost: 0 (0.0%)
  Mean Jitter: 0.021 ms, Max Jitter: 0.389 ms
  ✓ Quality: Good

Stream 2: 192.168.1.10:8000 -> 192.168.1.20:8000
  Packets: 1500, Lost: 75 (5.0%)
  Mean Jitter: 35.5 ms, Max Jitter: 120.3 ms
  ⚠ Quality Issues: HIGH packet loss (5.0%), HIGH jitter (35.5 ms), HIGH max jitter (120.3 ms)

====================================================================================================
Summary:
  Total RTP Streams:   2
  Total Packets:       4276
  Total Lost Packets:  75
  Overall Packet Loss: 1.75%
  Maximum Jitter:      120.300 ms

  Overall Quality: ⚠ FAIR - Some quality issues detected
====================================================================================================
```

### 使用方法

```bash
# 分析 VoIP 通话质量
capmaster analyze -i voip_call.pcap

# 查看 RTP 质量分析
cat statistics/voip_call-1-rtp-stats.txt
```

### 问题诊断

**高丢包率 (> 5%)**：
- 网络拥塞
- 路由器/交换机性能问题
- 无线网络信号弱

**高抖动 (> 30ms)**：
- 网络路径不稳定
- QoS 配置不当
- 带宽不足

**建议**：
- 丢包率 > 1%：检查网络设备和链路
- 抖动 > 20ms：启用 QoS，优先处理 VoIP 流量
- 同时出现高丢包和高抖动：严重网络问题，需立即处理

---

## 3. SSH 统计模块 (ssh_stats.py)

### 功能

分析 SSH (Secure Shell) 连接，提取：
- **SSH 协议版本**：SSH-1.x, SSH-2.0
- **连接端点**：源/目标 IP 和端口
- **TCP 流信息**：流 ID，数据包数量
- **连接模式**：识别连接数量和频率

### 输出示例

```
================================================================================
SSH Statistics
================================================================================

SSH Protocol Versions:
--------------------------------------------------------------------------------
Protocol Version                          Count
--------------------------------------------------------------------------------
SSH-2.0-OpenSSH_8.0                          1

SSH Connections (by TCP Stream):
--------------------------------------------------------------------------------
Stream     Frames     Source                    Destination               Protocol            
--------------------------------------------------------------------------------
0          48         10.135.65.10:22           10.145.51.215:53473       SSH-2.0-OpenSSH_8.0

Connection Packet Counts:
--------------------------------------------------------------------------------
Connection                                                      Packets
--------------------------------------------------------------------------------
10.135.65.10:22 <-> 10.145.51.215:53473                              48

================================================================================
Summary:
  Total SSH Streams:       1
  Total SSH Packets:       48
  Unique Connections:      1
  Protocol Versions Found: 1
================================================================================
```

### 使用方法

```bash
# 分析 SSH 流量
capmaster analyze -i network_traffic.pcap

# 查看 SSH 统计
cat statistics/network_traffic-1-ssh-stats.txt
```

### 安全分析

**异常模式检测**：
- **大量短连接**：可能是暴力破解攻击
- **多个源 IP 连接同一目标**：可能是分布式攻击
- **SSH-1.x 协议**：⚠ 不安全，应升级到 SSH-2.0
- **非标准端口**：可能是隐蔽通道或后门

---

## 测试验证

### 使用 V-001 测试案例

```bash
# 运行分析
capmaster analyze -i cases_02/V-001/VOIP.pcap

# 查看生成的统计文件
ls -lh statistics/

# 检查 SIP 统计
cat statistics/VOIP-1-sip-stats.txt

# 检查 RTP 质量
cat statistics/VOIP-1-rtp-stats.txt

# 检查 SSH 连接
cat statistics/VOIP-1-ssh-stats.txt
```

### 运行单元测试

```bash
# 运行 VoIP 和 SSH 模块测试
pytest tests/test_plugins/test_analyze/test_voip_modules.py -v

# 运行所有分析模块测试
pytest tests/test_plugins/test_analyze/ -v
```

---

## 模块架构

所有三个模块都遵循标准的 `AnalysisModule` 接口：

```python
@register_module
class SipStatsModule(AnalysisModule):
    @property
    def name(self) -> str:
        return "sip_stats"
    
    @property
    def output_suffix(self) -> str:
        return "sip-stats.txt"
    
    @property
    def required_protocols(self) -> set[str]:
        return {"sip"}
    
    def build_tshark_args(self, input_file: Path) -> list[str]:
        # 构建 tshark 命令参数
        ...
    
    def post_process(self, tshark_output: str) -> str:
        # 后处理和格式化输出
        ...
```

---

## 扩展建议

基于当前实现，未来可以扩展：

### 优先级 2 模块（下一阶段）

1. **MGCP 统计** (`mgcp_stats.py`)
   - 媒体网关控制协议分析
   - 命令和响应码统计

2. **RTCP 统计** (`rtcp_stats.py`)
   - RTP 控制协议分析
   - 发送者/接收者报告

3. **SDP 分析** (`sdp_stats.py`)
   - 会话描述协议解析
   - 媒体能力协商分析

### 增强功能

- **SIP 模块**：添加呼叫流程追踪（INVITE -> 200 OK -> ACK）
- **RTP 模块**：添加 MOS (Mean Opinion Score) 计算
- **SSH 模块**：添加加密算法统计和安全评分

---

## 参考资料

- **开发指南**：`docs/AI_PLUGIN_EXTENSION_GUIDE.md`
- **协议覆盖报告**：`PROTOCOL_COVERAGE_REPORT.md`
- **项目规范**：`PROJECT_SPEC.md`

---

**创建日期**：2025-11-02  
**版本**：1.0.0  
**作者**：CapMaster Development Team

