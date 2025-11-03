# Protocol Coverage Report - cases_02

**分析日期**: 2025-11-02
**分析文件**: 45 个 PCAP 文件（29 个案例）
**发现协议**: 37 种

## 🎉 重要进展

**优先级 1 & 2 协议已全部覆盖！**

自上次报告以来，已成功开发并实现以下 10 个高价值协议分析模块：

✅ **VoIP 协议栈** (6个模块):
- sip_stats.py - SIP 会话统计
- sdp_stats.py - SDP 会话描述
- rtp_stats.py - RTP 流分析
- rtcp_stats.py - RTCP 控制协议
- mgcp_stats.py - MGCP 媒体网关控制
- voip_quality.py - VoIP 质量评估 (MOS)

✅ **安全协议** (1个模块):
- ssh_stats.py - SSH 连接分析

✅ **应用层协议** (2个模块):
- json_stats.py - JSON API 统计
- xml_stats.py - XML/SOAP 消息统计

✅ **企业协议** (2个模块):
- mq_stats.py - IBM MQ 消息队列
- ftp_data_stats.py - FTP 数据传输

**协议覆盖率提升**: 从 21.6% (8/37) → **48.6% (18/37)**
**分析模块数量**: 从 17 个 → **28 个**

---

## 统计概览

| 指标 | 数值 |
|------|------|
| 已覆盖协议 | 18 种 (48.6%) |
| 未覆盖协议 | 19 种 (51.4%) |
| 现有分析模块 | 28 个 |

---

## 已覆盖协议 (18种)

| 协议 | 出现次数 | 相关模块 |
|------|---------|---------|
| **ip** | 45 (100%) | ipv4_conversations, ipv4_source_ttls, ipv4_destinations, ipv4_hosts |
| **tcp** | 43 (95.6%) | tcp_conversations, tcp_completeness, tcp_duration, tcp_zero_window |
| **http** | 13 (28.9%) | http_stats, http_response |
| **tls** | 11 (24.4%) | tls_alert |
| **udp** | 6 (13.3%) | udp_conversations |
| **icmp** | 6 (13.3%) | icmp_stats |
| **dns** | 5 (11.1%) | dns_stats, dns_qr_stats |
| **ftp** | 5 (11.1%) | ftp_stats |
| **xml** | 4 (8.9%) | xml_stats |
| **json** | 2 (4.4%) | json_stats |
| **ftp-data** | 2 (4.4%) | ftp_data_stats |
| **sip** | 1 (2.2%) | sip_stats |
| **sdp** | 1 (2.2%) | sdp_stats |
| **rtp** | 1 (2.2%) | rtp_stats, voip_quality |
| **rtcp** | 1 (2.2%) | rtcp_stats |
| **mgcp** | 1 (2.2%) | mgcp_stats |
| **ssh** | 1 (2.2%) | ssh_stats |
| **mq** | 1 (2.2%) | mq_stats |

---

## 未覆盖协议 (19种)

### 高价值协议 - 建议开发模块

#### VoIP 协议 (1种) - 优先级 1

| 协议 | 出现次数 | 建议模块 | 测试案例 | 状态 |
|------|---------|---------|---------|------|
| **skinny** | 1 | skinny_stats.py | V-001 | ⚠️ 待开发 |

**已覆盖的 VoIP 协议**:
- ✅ **sip** - sip_stats.py (已实现)
- ✅ **sdp** - sdp_stats.py (已实现)
- ✅ **rtp** - rtp_stats.py, voip_quality.py (已实现)
- ✅ **rtcp** - rtcp_stats.py (已实现)
- ✅ **mgcp** - mgcp_stats.py (已实现)

#### 其他应用协议 (7种) - 优先级 3

| 协议 | 出现次数 | 案例 |
|------|---------|------|
| **tftp** | 1 | V-001 |
| **x11** | 1 | TC-032-8-20240603-O |
| **msrcp** | 1 | TC-027-05-20221115 |
| **h1** | 1 | TC-032-8-20240603-O |
| **urlencoded-form** | 1 | TC-053-7-20180126 |
| **media** | 1 | TC-056-1-20190614-O |
| **image-gif** | 1 | TC-053-7-20180126 |
| **image-jfif** | 1 | TC-053-7-20180126 |

### 低优先级协议 - 无需开发模块

#### 基础设施协议 (5种)

| 协议 | 出现次数 | 说明 |
|------|---------|------|
| eth | 45 (100%) | 以太网帧 |
| frame | 45 (100%) | 帧结构 |
| vlan | 23 (51.1%) | VLAN 标签 |
| ppp | 1 | PPP 协议 |
| pppoes | 1 | PPPoE 会话 |

#### Wireshark 元数据标记 (5种)

| 协议 | 出现次数 | 说明 |
|------|---------|------|
| data | 8 | 未识别数据 |
| data-text-lines | 8 | 文本行数据 |
| _ws.short | 4 | 截断的数据包 |
| _ws.malformed | 3 | 格式错误的数据包 |
| ..._ws.malformed | 1 | 格式错误的数据包 |

---

## 未覆盖协议的案例对应关系

### 按协议分组

**skinny** (1 case) - ⚠️ 待开发
- V-001

**tftp** (1 case)
- V-001

**x11** (1 case)
- TC-032-8-20240603-O

**msrcp** (1 case)
- TC-027-05-20221115

**h1** (1 case)
- TC-032-8-20240603-O

**urlencoded-form** (1 case)
- TC-053-7-20180126

**media** (1 case)
- TC-056-1-20190614-O

**image-gif, image-jfif** (1 case)
- TC-053-7-20180126

### 按案例分组（仅列出包含未覆盖高价值协议的案例）

**V-001** ⭐⭐⭐ (VoIP 完整协议栈)
```
已覆盖协议: sip, sdp, rtp, rtcp, mgcp, ssh ✅
未覆盖协议: skinny, tftp
PCAP 文件: VOIP.pcap
已实现模块: sip_stats.py, sdp_stats.py, rtp_stats.py, rtcp_stats.py, mgcp_stats.py, voip_quality.py, ssh_stats.py
建议开发: skinny_stats.py (低优先级)
```

**TC-032-8-20240603-O** ⭐⭐ (复杂应用环境)
```
已覆盖协议: json, mq ✅
未覆盖协议: x11, h1
PCAP 文件: TC-032-8-20240603-O.pcap
已实现模块: json_stats.py, mq_stats.py
```

**TC-034-9-20230222-O-1** (XML/SOAP)
```
已覆盖协议: xml ✅
PCAP 文件: TC-034-9-20230222-O-A-nginx.pcap
已实现模块: xml_stats.py
```

**TC-034-9-20230222-O-2** (XML/SOAP)
```
已覆盖协议: xml ✅
PCAP 文件: TC-034-9-20230222-O-A-nginx.pcap, TC-034-9-20230222-O-B-server.pcap
已实现模块: xml_stats.py
```

**TC-034-9-20230222-S-1** (XML/SOAP)
```
已覆盖协议: xml ✅
PCAP 文件: TC-034-9-20230222-S-A-nginx.pcap
已实现模块: xml_stats.py
```

**TC-034-9-20230222-S-2** (XML/SOAP)
```
已覆盖协议: xml ✅
PCAP 文件: TC-034-9-20230222-S-A-nginx.pcap, TC-034-9-20230222-S-B-server.pcap
已实现模块: xml_stats.py
```

**TC-001-5-20190905** (JSON API)
```
已覆盖协议: json ✅
PCAP 文件: TC-001-5-20190905-Dev.pcapng
已实现模块: json_stats.py
```

**TC-032-3-20230329** (FTP 数据传输)
```
已覆盖协议: ftp-data ✅
PCAP 文件:
  - TC-032-3-20230329-O-core-switch-abnormal-flow.pcapng
  - TC-032-3-20230329-O-edge-router-abnormal-flow.pcapng
  - TC-032-3-20230329-O-recovered-core-switch-normal-flow.pcapng
  - TC-032-3-20230329-O-recovered-edge-router-normal-flow.pcapng
已实现模块: ftp_data_stats.py
```

**TC-045-1-20240219** (FTP 数据传输)
```
已覆盖协议: ftp-data ✅
PCAP 文件:
  - TC-045-1-20240219-abnormal-sessions.pcap
  - TC-045-1-20240219-all.pcap
  - TC-045-1-20240219-normal-control-session.pcap
  - TC-045-1-20240219-normal-data-session.pcap
已实现模块: ftp_data_stats.py
```

---

## 开发优先级建议

### ✅ 已完成 - 优先级 1 & 2 协议全部覆盖

**VoIP 分析模块组** (测试案例: V-001) - ✅ 已实现
- ✅ `sip_stats.py` - SIP 会话统计
- ✅ `sdp_stats.py` - SDP 会话描述统计
- ✅ `rtp_stats.py` - RTP 流分析 (jitter, packet loss)
- ✅ `rtcp_stats.py` - RTCP 控制协议统计
- ✅ `mgcp_stats.py` - MGCP 媒体网关控制统计
- ✅ `voip_quality.py` - VoIP 质量评估 (MOS score)

**SSH 分析模块** (测试案例: V-001) - ✅ 已实现
- ✅ `ssh_stats.py` - SSH 连接、版本、加密算法统计

**应用层协议扩展** - ✅ 已实现
- ✅ `json_stats.py` - JSON API 统计 (测试: TC-001-5, TC-032-8-O)
- ✅ `xml_stats.py` - XML/SOAP 消息统计 (测试: TC-034-9 系列)

**企业协议** - ✅ 已实现
- ✅ `mq_stats.py` - 消息队列统计 (测试: TC-032-8-O)
- ✅ `ftp_data_stats.py` - FTP-DATA 传输统计 (测试: TC-032-3, TC-045-1)

### 优先级 3 - 可选（低频协议）

- `skinny_stats.py` - Cisco Skinny/SCCP 协议 (仅 1 个案例)
- `tftp_stats.py`, `x11_stats.py`, `msrcp_stats.py` 等低频协议

---

## 完整模块列表

### 当前已实现的 28 个分析模块

| # | 模块名称 | 协议 | 功能描述 | 优先级 |
|---|---------|------|---------|--------|
| 1 | protocol_hierarchy | all | 协议层次统计 | 基础 |
| 2 | ipv4_conversations | ip | IPv4 会话统计 | 高 |
| 3 | ipv4_source_ttls | ip | IPv4 源 TTL 统计 | 高 |
| 4 | ipv4_destinations | ip | IPv4 目标地址统计 | 高 |
| 5 | ipv4_hosts | ip | IPv4 主机端点统计 | 高 |
| 6 | tcp_conversations | tcp | TCP 会话统计 | 高 |
| 7 | tcp_completeness | tcp | TCP 连接完整性分析 | 高 |
| 8 | tcp_duration | tcp | TCP 连接持续时间 | 高 |
| 9 | tcp_zero_window | tcp | TCP 零窗口检测 | 高 |
| 10 | udp_conversations | udp | UDP 会话统计 | 高 |
| 11 | http_stats | http | HTTP 请求/响应统计 | 高 |
| 12 | http_response | http | HTTP 响应码分析 | 高 |
| 13 | dns_stats | dns | DNS 查询统计 | 高 |
| 14 | dns_qr_stats | dns | DNS 查询/响应统计 | 高 |
| 15 | ftp_stats | ftp | FTP 命令统计 | 中 |
| 16 | ftp_data_stats | ftp-data | FTP 数据传输统计 | 中 |
| 17 | icmp_stats | icmp | ICMP 消息统计 | 中 |
| 18 | tls_alert | tls | TLS 告警消息分析 | 高 |
| 19 | sip_stats | sip | SIP 会话统计 | 高 |
| 20 | sdp_stats | sdp | SDP 会话描述统计 | 高 |
| 21 | rtp_stats | rtp | RTP 流质量分析 | 高 |
| 22 | rtcp_stats | rtcp | RTCP 控制协议统计 | 高 |
| 23 | mgcp_stats | mgcp | MGCP 媒体网关统计 | 高 |
| 24 | voip_quality | rtp | VoIP 质量评估 (MOS) | 高 |
| 25 | ssh_stats | ssh | SSH 连接分析 | 高 |
| 26 | json_stats | json | JSON API 统计 | 高 |
| 27 | xml_stats | xml | XML/SOAP 消息统计 | 高 |
| 28 | mq_stats | mq | IBM MQ 消息队列统计 | 高 |

**模块分类统计**:
- 网络层 (IP): 4 个模块
- 传输层 (TCP/UDP): 6 个模块
- 应用层 (HTTP/DNS/FTP): 7 个模块
- 安全层 (TLS/SSH): 2 个模块
- VoIP 协议栈: 6 个模块
- 企业应用 (JSON/XML/MQ): 3 个模块
- 基础设施 (ICMP): 1 个模块
- 通用工具: 1 个模块

---

## 开发参考

**模块开发指南**: `docs/ANALYZE_MODULE_DEVELOPMENT_GUIDE.md`

**参考现有模块**:
- 简单: `protocol_hierarchy.py` (无后处理)
- 中等: `tcp_zero_window.py` (字段提取 + Counter)
- 复杂: `http_response.py` (字段提取 + defaultdict)
- 高级: `voip_quality.py` (复杂后处理 + MOS 计算)

**测试 PCAP 文件路径**: `cases_02/<案例名>/<文件名>`

---

**分析工具**: `check_protocols.py`
**生成命令**: `python check_protocols.py`

---

# 附录：完整协议覆盖分析 - 数据中心业务系统视角

**分析日期**: 2025-11-02  
**分析来源**: downloads/ 目录下所有 pcap/pcapng 文件  
**分析文件数**: 588 个  
**发现协议数**: 1047 种唯一协议  

本附录从**现代IT数据中心业务系统和支撑服务**的角度，对所有协议进行分类和排序。

---

## 分类体系说明

### 第一层：核心业务系统 (69 个协议)
面向用户的核心业务，直接支撑企业收入和价值创造：
- **Web应用与API服务** (17个) - HTTP/HTTPS、gRPC、JSON、Protobuf
- **数据库服务** (9个) - MySQL、PostgreSQL、MongoDB、Redis
- **消息队列与流处理** (7个) - Kafka、RabbitMQ、MQTT
- **容器与云原生平台** (6个) - Kubernetes网络、VXLAN、Geneve
- **对象存储与分布式存储** (30个) - S3、Ceph、NFS、SMB、iSCSI

### 第二层：基础设施与支撑服务 (185 个协议)
支撑核心业务运行的基础设施：
- **负载均衡与反向代理** (12个) - F5、Nginx、VRRP、BGP
- **身份认证与访问控制** (25个) - LDAP、Kerberos、RADIUS
- **监控与可观测性** (5个) - SNMP、Syslog、NetFlow、Zabbix
- **DNS与服务发现** (4个) - DNS、mDNS、Consul
- **网络基础设施** (130个) - TCP/IP、VLAN、MPLS、路由协议
- **DHCP与地址管理** (5个) - DHCP、DHCPv6
- **时间同步** (4个) - NTP、PTP

### 第三层：安全与防护 (24 个协议)
保障系统安全的防护体系：
- **VPN与加密隧道** (10个) - IPSec、OpenVPN、WireGuard、SSH
- **防火墙与安全网关** (4个) - Netfilter、NFLog
- **邮件系统** (5个) - SMTP、IMAP、POP3
- **文件传输** (6个) - FTP、SFTP、TFTP
- **远程管理** (8个) - SSH、RDP、VNC、Telnet

### 第四层：企业应用 (26 个协议)
企业级应用和通信系统：
- **VoIP与统一通信** (26个) - SIP、RTP、H.264/H.265

### 第五层：专用系统 (71 个协议)
特定行业和场景的专用协议：
- **工业控制系统** (12个) - Modbus、S7、Profinet、BACnet
- **电信与移动网络** (45个) - GTP、S1AP、GSM、LTE
- **物联网** (14个) - MQTT、CoAP、Zigbee、BLE

### 第六层：其他协议 (659 个协议)
低频使用的协议：
- **多媒体流** (2个)
- **P2P与文件共享** (4个)
- **游戏协议** (6个)
- **遗留协议** (28个) - X.25、Frame Relay、ATM
- **Wireshark内部协议** (6个)
- **未分类/其他** (613个)

---

## 核心业务系统协议详情

### 1. Web应用与API服务 (17 个协议)

**业务价值**: ⭐⭐⭐⭐⭐ 最高优先级
**流量占比**: 约40-60%（现代数据中心）
**说明**: 面向用户的Web应用、RESTful API、微服务通信

**协议列表**:
- **🔍 grpc** - gRPC状态码、错误详情
- **🔍 http** - HTTP状态码(200/404/500)、响应时间
- **🔍 http2** - HTTP/2状态码、Stream错误
- **🔍 json** - 应用层错误码（JSON格式）
- **🔍 protobuf** - 应用层错误码（Protobuf格式）
- **🔍 quic** - QUIC连接错误、流错误
- **🔍 spdy** - SPDY状态码、RST_STREAM错误
- **🔍 thrift** - Thrift异常、返回值
- bsslap, dtls, gquic, rtcdc, rtcfg, tls, wbxml, wtls, xml

**性能分析协议**: 8/17 个协议包含性能信息（标记为 🔍）

**典型应用场景**:
- 电商平台、企业门户、SaaS应用
- 微服务架构：gRPC、Protobuf、Thrift
- 移动App后端API：JSON、RESTful
- HTTPS加密：TLS 1.2/1.3、QUIC（HTTP/3）

---

### 2. 数据库服务 (9 个协议)

**业务价值**: ⭐⭐⭐⭐⭐ 核心数据层
**流量占比**: 约10-20%
**说明**: 关系型数据库、NoSQL、时序数据库、缓存

**协议列表**:
- **🔍 couchbase** - Couchbase状态码、错误消息
- **🔍 cql** - Cassandra错误码、一致性级别、超时
- **🔍 drda** - DRDA返回码、SQLCODE
- **🔍 elasticsearch** - ES HTTP状态码、错误类型、分片失败
- **🔍 memcache** - Memcached状态码、命中率
- **🔍 mysql** - MySQL错误码(1045/1062)、查询执行时间、慢查询
- **🔍 pgsql** - PostgreSQL错误码、SQLSTATE、错误消息
- **🔍 tds** - SQL Server错误号、严重级别、状态
- **🔍 tns** - Oracle错误码(ORA-xxxxx)、TNS错误

**性能分析协议**: 9/9 个协议全部包含性能信息（标记为 🔍）

**典型应用场景**:
- 关系型：MySQL、PostgreSQL、SQL Server（TDS）、Oracle（TNS）
- NoSQL：Couchbase、Cassandra（CQL）、Elasticsearch
- 缓存：Memcached、Redis
- 大数据：Elasticsearch、时序数据库

---

### 3. 消息队列与流处理 (7 个协议)

**业务价值**: ⭐⭐⭐⭐⭐ 异步通信核心
**流量占比**: 约5-15%
**说明**: 消息中间件、事件流、发布订阅

**协议列表**:
- **🔍 amqp** - AMQP错误码(NOT_FOUND/ACCESS_REFUSED)、通道异常
- **🔍 kafka** - Kafka错误码(OFFSET_OUT_OF_RANGE)、分区错误
- **🔍 mq** - IBM MQ返回码(MQRC_*)、队列错误
- **🔍 mqtt** - MQTT返回码(CONNACK/SUBACK)、QoS失败
- **🔍 openwire** - ActiveMQ异常、消息确认状态
- msmms, nano

**性能分析协议**: 5/7 个协议包含性能信息（标记为 🔍）

**典型应用场景**:
- 消息队列：Kafka、RabbitMQ（AMQP）、ActiveMQ（OpenWire）
- 物联网：MQTT
- 微服务异步通信、事件驱动架构
- 实时数据流处理、日志收集

---

### 4. 容器与云原生平台 (6 个协议)

**业务价值**: ⭐⭐⭐⭐⭐ 现代基础设施
**流量占比**: 约5-10%（快速增长）
**说明**: Kubernetes、Docker、服务网格、容器网络

**协议列表**:
- geneve, gre, grebonding, turbocell_aggregate, vxlan, wlan_aggregate

**性能分析协议**: 0/6 个协议（这些是纯隧道/封装协议，不包含应用层性能信息）

**典型应用场景**:
- 容器网络：VXLAN、Geneve（Kubernetes CNI）
- 隧道协议：GRE
- 服务网格：Istio、Linkerd
- 多租户网络隔离、跨主机容器通信

---

### 5. 对象存储与分布式存储 (30 个协议)

**业务价值**: ⭐⭐⭐⭐⭐ 数据持久化
**流量占比**: 约10-25%
**说明**: S3对象存储、Ceph、分布式文件系统、块存储

**协议列表**:
- **🔍 afs** - AFS错误码、卷状态
- **🔍 ceph** - Ceph操作返回码、OSD错误
- **🔍 iscsi** - iSCSI响应码、SCSI状态、任务管理响应
- **🔍 lustre** - Lustre错误码、RPC状态
- **🔍 nfs** - NFS状态码(NFS3ERR_*)、操作延迟
- **🔍 nvme-tcp** - NVMe状态码、完成队列错误
- **🔍 smb** - SMB状态码(STATUS_*)、NT_STATUS错误
- **🔍 smb2** - SMB2状态码、错误响应、操作延迟
- fc, fcct, fcdns, fcels, fcfzs, fcip, fcoe, fcoib, fcp, fcs, fcsb3, fcsp, ifcp, nfs.cb, nfsacl, nvme, pfcp, pvfs, rfc2190, smb_direct, smb_netlogon, smb_pipe

**性能分析协议**: 8/30 个协议包含性能信息（标记为 🔍）

**典型应用场景**:
- 对象存储：S3、Ceph、MinIO
- 文件存储：NFS、SMB/CIFS、Lustre、GlusterFS
- 块存储：iSCSI、FC（光纤通道）、FCoE、NVMe-oF
- 企业文件共享：Windows（SMB）、Linux（NFS）

---

## 基础设施与支撑服务协议详情

### 6. 负载均衡与反向代理 (12 个协议)

**业务价值**: ⭐⭐⭐⭐ 高可用保障
**说明**: 负载均衡器、反向代理、流量管理

**协议列表**:
- bgp, carp, ecmp, eigrp, f5ethtrailer, glbp, hsrp, ipvs, ospf, tecmp, tecmp.payload, vrrp

**性能分析协议**: 0/12 个协议（这些是网络层协议，不包含应用层性能信息）

**典型应用场景**:
- 负载均衡：F5、Nginx、HAProxy、LVS（IPVS）
- 高可用：VRRP、HSRP、CARP
- 流量工程：BGP、OSPF、EIGRP、ECMP

---

### 7. 身份认证与访问控制 (25 个协议)

**业务价值**: ⭐⭐⭐⭐ 安全基础
**说明**: SSO、LDAP、Kerberos、RADIUS、OAuth

**协议列表**:
- **🔍 diameter** - Diameter结果码(SUCCESS/AUTHENTICATION_REJECTED)
- **🔍 kerberos** - Kerberos错误码(KDC_ERR_*)
- **🔍 ldap** - LDAP结果码(success/invalidCredentials)
- **🔍 radius** - RADIUS响应码(Access-Accept/Reject)
- **🔍 tacacs** - TACACS+认证状态(PASS/FAIL)
- **🔍 tacplus** - TACACS+授权响应
- adp, adwin, armagetronad, batadv, cldap, gadu-gadu, ieee8021ad, kpasswd, krb4, lsarpc, radiotap, reload, reload-framing, samr, srvsvc, thread_bcn, winreg, winsrepl, wlan_radio

**性能分析协议**: 6/25 个协议包含性能信息（标记为 🔍）

**典型应用场景**:
- 企业目录：Active Directory（LDAP、Kerberos）
- 网络准入：RADIUS、802.1X
- 设备管理：TACACS+
- 电信认证：Diameter

---

### 8. 监控与可观测性 (5 个协议)

**业务价值**: ⭐⭐⭐⭐ 运维核心
**说明**: Metrics、Logging、Tracing、APM

**协议列表**:
- **🔍 snmp** - SNMP错误状态(noSuchName/tooBig)、Trap
- **🔍 syslog** - Syslog严重级别(Emergency/Error)、设施代码
- cflow, sflow, zabbix

**性能分析协议**: 2/5 个协议包含性能信息（标记为 🔍）

**典型应用场景**:
- 网络监控：SNMP、NetFlow/sFlow
- 日志收集：Syslog、Fluentd、Logstash
- 指标监控：Prometheus、Zabbix、Grafana
- 流量分析：NetFlow、sFlow、IPFIX

---

### 9. DNS与服务发现 (4 个协议)

**业务价值**: ⭐⭐⭐⭐ 名称解析
**说明**: DNS域名解析、mDNS、服务注册与发现

**协议列表**:
- **🔍 dns** - DNS响应码(NXDOMAIN/SERVFAIL)、查询延迟
- llmnr, mdns, nbns

**性能分析协议**: 1/4 个协议包含性能信息（标记为 🔍）

**典型应用场景**:
- 域名解析：DNS（内网/外网）
- 服务发现：Consul、Etcd、Kubernetes DNS
- 本地网络：mDNS（Bonjour）、LLMNR

---

### 10. 网络基础设施 (130 个协议)

**业务价值**: ⭐⭐⭐⭐⭐ 基础中的基础  
**流量占比**: 100%（所有流量的底层）  
**说明**: TCP/IP、路由、交换、VLAN、MPLS

<details>
<summary>点击展开完整协议列表 (130个)</summary>

- aarp, arp, atmtcp, bfd, bfd_echo, caneth, cdp, cdpcp, cesoeth, cip, cipcco, cipcls, cipcm, cipio, cipmb, cippccc, cipssupervisor, cipsvalidator, clip, cnip, dccp, dec_stp, dect_mitel_eth, doip, dvb_ipdc, enip, eth, etherip, fip, flip, gsm_ipa, hart_ip, hip, hipercontracer, hislip, icmp, icmpv6, ieee8021ah, igmp, ip, ipaccess, ipars, ipcomp, ipcp, ipdc, ipdr, iperf3, ipmb, ipmi_session, ipos, ipp, ipsictl, ipv6, ipv6.dstopts, ipv6.fraghdr, ipv6.hopopts, ipv6.routing, ipv6cp, ipx, ipxmsg, ipxrip, ipxsap, ipxwan, kip, lacp, lapbether, lbttcp, ldp, lisp-tcp, lldp, mbtcp, mbudp, mime_multipart, mip, mipv6, mndp, mpls, mpls-echo, mpls_mac, mpls_psc, mplscp, mplspmdlm, mplspmdlmdm, mplspmdm, mplspmilm, mplspmilmdm, mplstp_fm, mplstp_lock, msnip, nbipx, ndps, opensafety_udp, pcomtcp, pim, pn_ptcp, ptpip, pwethcw, r-stp, rdpudp, rip, ripng, rldp, rsip, rsvp, rtcp, rtitcp, sctp, sip, snaeth, srtcp, stp, swipe, tcp, tcpcl, tcpencap, tipc, uaudp, udld, udp, udpencap, udplite, vines_arp, vines_ip, vines_ipc, vlan, wreth, xip, xipserval, zbip_beacon, zip

</details>

**核心协议**:
- L3: IP、IPv6、ICMP、ICMPv6、ARP
- L4: TCP、UDP、SCTP、DCCP
- L2: Ethernet、VLAN、STP、LACP、LLDP、CDP
- 路由: BGP、OSPF、EIGRP、RIP、IS-IS
- MPLS: MPLS、LDP、RSVP-TE

---

### 11-17. 其他基础设施服务

<details>
<summary>点击展开查看 DHCP、时间同步、VPN、防火墙、邮件、文件传输、远程管理协议</summary>

#### 11. DHCP与地址管理 (5 个协议)
**业务价值**: ⭐⭐⭐
**协议列表**:
- **🔍 dhcp** - DHCP消息类型(ACK/NAK)
- bootparams, dhcpfo, dhcpv6, dhcpv6.bulk_leasequery

**性能分析协议**: 1/5 个协议

#### 12. 时间同步 (4 个协议)
**业务价值**: ⭐⭐⭐
**协议列表**:
- **🔍 ntp** - NTP层级(Stratum)、同步状态
- nntp, pptp, ptp

**性能分析协议**: 1/4 个协议

#### 13. VPN与加密隧道 (10 个协议)
**业务价值**: ⭐⭐⭐⭐
**协议列表**:
- **🔍 openvpn** - OpenVPN错误消息、TLS握手失败
- **🔍 sftp** - SFTP状态码(SSH_FX_OK/SSH_FX_FAILURE)
- **🔍 ssh** - SSH断开原因码、认证失败
- ah, dof.esp, esp, isakmp, l2tp, mikey, wg

**性能分析协议**: 3/10 个协议

#### 14. 防火墙与安全网关 (4 个协议)
**业务价值**: ⭐⭐⭐⭐
**协议列表**: netlink, netlink-netfilter, netlink-route, nflog

**性能分析协议**: 0/4 个协议

#### 15. 邮件系统 (5 个协议)
**业务价值**: ⭐⭐⭐
**协议列表**:
- **🔍 imap** - IMAP响应码(OK/NO/BAD)
- **🔍 pop** - POP3响应码(+OK/-ERR)
- **🔍 smtp** - SMTP状态码(250/550)、投递失败原因
- mapi, omapi

**性能分析协议**: 3/5 个协议

#### 16. 文件传输 (6 个协议)
**业务价值**: ⭐⭐⭐
**协议列表**:
- **🔍 ftp** - FTP状态码(200/550)、传输错误
- **🔍 ftp-data** - FTP数据传输状态
- **🔍 tftp** - TFTP错误码(File not found/Access violation)
- uftp, uftp4, uftp5

**性能分析协议**: 3/6 个协议

#### 17. 远程管理 (8 个协议)
**业务价值**: ⭐⭐⭐
**协议列表**:
- **🔍 rdp** - RDP断开原因、错误信息
- **🔍 telnet** - Telnet错误消息
- **🔍 vnc** - VNC认证失败、连接错误
- ardp, exec, mactelnet, rlogin, rsh

**性能分析协议**: 3/8 个协议

</details>

---

## 企业应用与专用系统协议

### 18. VoIP与统一通信 (26 个协议)

**业务价值**: ⭐⭐⭐ 企业通信
**流量占比**: 1-10%
**说明**: SIP、RTP、视频会议、统一通信

**协议列表**:
- **🔍 h323** - H.323拒绝原因、呼叫结束原因
- **🔍 megaco** - Megaco错误码、命令响应
- **🔍 mgcp** - MGCP返回码、事务响应
- **🔍 rtcp** - RTCP丢包率、抖动、往返时延
- **🔍 sccp** - SCCP消息状态、注册失败
- **🔍 sip** - SIP状态码(200/404/503)、呼叫失败原因
- btsdp, crtp, h225, h248, h261, h263, h264, h265, iax2, msdp, rtmp, rtmpt, rtp, rtpevent, rtpproxy, rtps, rtsp, sccpmg, sdp, skinny, ssdp, vines_rtp, zrtp

**性能分析协议**: 6/26 个协议包含性能信息（标记为 🔍）

**典型应用场景**:
- 企业电话：SIP、SCCP（Cisco）、Skinny
- 视频会议：H.264/H.265、RTP、RTCP
- 统一通信：Microsoft Teams、Zoom、Webex
- 流媒体：RTSP、RTMP

---

### 19-21. 专用系统协议

<details>
<summary>点击展开查看工业控制、电信、物联网协议</summary>

#### 19. 工业控制系统 (12 个协议)
**业务价值**: ⭐⭐ 特定行业
**说明**: SCADA、Modbus、OPC、Profinet
**协议列表**:
- **🔍 bacnet** - BACnet错误类别、拒绝原因
- **🔍 dnp3** - DNP3内部指示(IIN)、应用层确认
- **🔍 modbus** - Modbus异常码(01-非法功能/02-非法地址)
- **🔍 s7comm** - S7错误类别、返回码
- bacapp, can, ecat, ecatf, iec60870_104, iec60870_asdu, pn_io, pn_rt

**性能分析协议**: 4/12 个协议

**典型场景**: 工厂自动化、楼宇自控、电力SCADA、石油化工

#### 20. 电信与移动网络 (45 个协议)
**业务价值**: ⭐⭐ 电信专用
**说明**: 3G/4G/5G、SS7、GTP、核心网
**协议列表**: Filter, ansi_map, ansi_tcap, bssap, bssap_plus, camel, e1ap, e2ap, f1ap, gsm-r-uus1, gsm_a.bssmap, gsm_a.ccch, gsm_a.dtap, gsm_a.rp, gsm_a.sacch, gsm_abis_oml, gsm_abis_pgsl, gsm_abis_rsl, gsm_abis_tfp, gsm_cbch, gsm_cbs, gsm_map, gsm_rlcmac, gsm_sms, gsm_sms_ud, gsmtap, gtp, gtpprime, gtpv2, hnbap, inap, lte_rrc, m2pa, m2ua, m3ua, nbap, ngap, portmap, ranap, realtek, rnsap, s1ap, sabp, tcap, x2ap

**典型场景**: 移动核心网、基站、信令网、计费系统

#### 21. 物联网 (14 个协议)
**业务价值**: ⭐⭐ 物联网场景
**说明**: MQTT、CoAP、Zigbee、BLE
**协议列表**: 6lowpan, _ws.unreassembled, bluetooth, btle, coap, lwm2mtlv, nordic_ble, zbee_apf, zbee_aps, zbee_beacon, zbee_nwk, zbee_nwk_gp, zbee_zcl, zbee_zdp

**典型场景**: 智能家居、工业物联网、智慧城市、可穿戴设备

</details>

---

## 低频使用协议

### 22-27. 其他低频协议

<details>
<summary>点击展开查看多媒体、P2P、游戏、遗留协议等 (659个)</summary>

#### 22. 多媒体流 (2 个协议)
**协议列表**: mms, mmse

#### 23. P2P与文件共享 (4 个协议)
**协议列表**: bittorrent, bt-dht, edonkey, gnutella

#### 24. 游戏协议 (6 个协议)
**协议列表**: quake, quake2, quake3, quakeworld, steam_ihs_discovery, wow

#### 25. 遗留协议 (28 个协议)
**说明**: X.25、Frame Relay、ATM、Token Ring等已淘汰技术
**协议列表**: actrace, arcnet, ax25, ax25_nol3, ddp, dec_dna, dof.trp, extrememesh, fddi, fr, fractalgeneratorprotocol, frame, nbdgm, nbp, nbss, netbios, netrom, portcontrol, rpkirtr, tetra, tr, trill, trmac, twamp.control, vines_frp, x11, x25, x29

#### 26. Wireshark内部协议 (6 个协议)
**说明**: Wireshark元数据和诊断标记
**协议列表**: capwap.data, comp_data, data, data-text-lines, dvb_data_mpe, lisp-data

#### 27. 未分类/其他 (613 个协议)
**说明**: 其他未分类协议，包括实验性协议、罕见协议、特定厂商协议等

<details>
<summary>点击展开完整列表 (613个)</summary>

3comxns, 5co_legacy, 9p, Protocol, a11, a21, aaf, acap, acdr, acf, acse, afp, agentx, aj, ajns, alc, alcap, alp, amr, amt, ancp, ans, ansi_683, aodv, aoe, ap1394, applemidi, ar_drone, artemis, artnet, asam-cmp, asap, asf, asp, asphodel, asterix, atn-ulcs, atp, auto_rp, autosar-nm, avsp, ax4000, ayiya, bacp, bap, basicxid, bat, bat.gw, bat.vis, bcp_bpdu, bcp_ncp, beep, bicc, bitcoin, bjnp, bluecom, bofl, bpq, bpv7, brcm-tag, brdwlk, browser, bssmap-le, bssgp, bthci_acl, bthci_cmd, bthci_evt, bthci_sco, bthcrp, bthfp, bthsp, btl2cap, btmesh, btmesh.beacon, btmesh.pbadv, btmesh.proxy, btrfcomm, btsdp, btsmp, bundle, bzr, c1222, calcappprotocol, carp, cast, catapult_dct2000, cbor, cbrs-oids, ccp, ccsds, cdma2k_a11, cdma2k_a11_bcmcs, cdma2k_a11_hrpd, cdp, cdt, ceph, cfdp, cfm, cgmp, chargen, charging_ase, chdlc, cimd, cimetrics, cipencap, cisco-erspan, cisco-fp-mim, cisco-marker, cisco-oui, cisco-sm, cisco-ttag, cisco-wids, classicstun, clearcase, clique-rm, clnp, cmip, cmp, cms, coap-observe, collectd, componentstatus, componentstatusprotocol, corosync_totemnet, corosync_totemsrp, cp2179, cpha, cpfi, cql, credssp, csm_encaps, ctdb, cups, daap, daytime, db-lsp, db-lsp-disc, dbus, dccp, dcerpc, dcm, dcom, dcom-oxid, dcom-provideclassinfo, dcom-remact, dcom-remunkn, dcom-sysact, dcom-typeinfo, dcp-etsi, dcp-pft, dcp-tpl, ddtp, dec_dna, dec_stp, dect_dlc, dect_mitel_eth, dect_mitel_rfp, dect_nwk, devicenet, dhcp-failover2, dhcpv6-bulk-leasequery, diameter, diameter_3gpp, dicom, dis, distcc, dlep, dlm3, dlsw, dmp, dmx, dmx-chan, dmx-sip, dmx-test, dnp3, dns-sd, dnskey, docsis, docsis_bintrngreq, docsis_bpkmattr, docsis_bpkmreq, docsis_bpkmrsp, docsis_clk, docsis_cm_ctrl, docsis_cmstatus, docsis_dbcack, docsis_dbcreq, docsis_dbcrsp, docsis_dccack, docsis_dccreq, docsis_dccrsp, docsis_dcd, docsis_dpvreq, docsis_dpvrsp, docsis_dsaack, docsis_dsareq, docsis_dsarsp, docsis_dscack, docsis_dscreq, docsis_dscrsp, docsis_dsdreq, docsis_dsdrsp, docsis_intrngreq, docsis_macmgmt, docsis_map, docsis_mdd, docsis_mgmt, docsis_ocd, docsis_regack, docsis_regreq, docsis_regrsp, docsis_rngreq, docsis_rngrsp, docsis_sync, docsis_tlv, docsis_type29ucd, docsis_type35ucd, docsis_uccreq, docsis_uccrsp, docsis_ucd, docsis_uccreq, docsis_uccrsp, dof.dpp, dof.oap, dof.secmode, dof.session, dof.tunnel, dop, dpaux, dpnet, dplay, dpm, drb-dis, drb-pos, drb-sig, drda, drsuapi, dsi, dsp, dtcp-ip, dtn, dtpt, dtsstime_req, dte_dcm, dua, dvb-ci, dvb-s2_bb, dvb-s2_gse, dvb-s2_modeadapt, dvb-s2_table, dvb_eit, dvb_nit, dvb_sdt, dvb_tdt, dvb_tot, dvbci, dvmrp, dxl, e100, e164, e212, eap, eapol, ecat_mailbox, ecatf, ecmp, ecp, ecpri, edonkey, edsa, eero, ehdlc, eigrp, eiss, elcom, enc, enip, enrp, enttec, epl, epl_v1, epm, epon, erf, erldp, erspan, esis, esio, ess, ethercat, ethertype, etv, evrc, evs, exec, exported_pdu, extreme-mesh, f5fileinfo, f5info, fc-ct, fc-els, fc-fcs, fc-fzs, fc-gs, fc-sb3, fc-sp, fc-swils, fcgi, fcip, fcoe, fcoib, fcp, fcsb3, fddi, fefd, ff, fip, fix, flexnet, flexray, fmtp, forces, foundry, fp, fp_hint, fp_mux, fractalgeneratorprotocol, frame, frstrans, ftam, ftdi-ft, ftdi-mpsse, ftp, ftp-data, g723, gadu-gadu, gdsdb, gearman, ged125, geneve, geonw, gfp, giop, git, glbp, gluster.cli, gluster.dump, gluster.gd_mgmt, gluster.glusterd, gluster.hndsk, gluster.pmap, glusterfs, gmhdr, gmr1_bcch, gmr1_ccch, gmr1_dtap, gmr1_rach, gmr1_rr, gmrp, gnutella, goose, gopher, gpef, gprs-llc, gprs-ns, gprscdr, gre, gryphon, gsm_a.gm, gsm_a.rr, gsm_bsslap, gsm_bssmap_le, gsm_cbsp, gsm_sim, gsm_sms, gsm_um, gsmtap_log, gssapi, gtp, gtpv2, gvcp, gvsp, h1, h221, h223, h225, h235, h245, h248, h261, h263, h264, h265, h282, h283, h323, h450, h450-ros, h460, h501, haipe, hartip, hci_h1, hci_h4, hci_mon, hci_usb, hclnfsd, hcrt, hdcp, hdcp2, hdfs, hdfsdata, hip, hipercontracer, hiqnet, hislip, hnbap, homeplug, homeplug_av, hp-erm, hpext, hpfeeds, hpteam, hsr, hsr_prp_supervision, hsrp, http, http-urlencoded, http2, http3, hyperscsi, i2c, iana-oui, iapp, iax2, icap, icep, icmp, icmpv6, icp, icq, iec60870-5-101, iec60870-5-104, iec60870_asdu, ieee1722, ieee1722a, ieee1905, ieee17221, ieee802.11, ieee802.11_prism, ieee802.11_radio, ieee802.11_radiotap, ieee802.11_wlancap, ieee802.15.4, ieee802.15.4_nonask_phy, ieee802.15.4_nofcs, ieee802.1ad, ieee802.1ah, ieee802.1br, ieee802.1cb, ieee802.1q, ieee802.3, ieee802a, ieee8021ad, ieee8021ah, ieee8021ax, ieee8023_lag_marker, ifcp, igap, igmp, igrp, imap, imf, inap, infiniband, infiniband.link, infiniband.mad, infiniband.sdp, infiniband.srp, infiniband.subnet, infiniband.vendor, infiniband.vendor.mellanox, infiniband.vendor.qlogic, infiniband.vendor.voltaire, inmarsat, interlink, ios, iowarrior, ip, ip-over-fc, ip-over-ib, ipars, ipc, ipcp, ipdc, ipdr, iperf, iperf3, ipfc, ipmi, ipmi.picmg, ipmi.session, ipmi.trace, ipnet, ipoib, ipos, ipp, ipsec, ipsictl, ipv6, ipv6.hopopts, ipv6.routing, ipv6cp, ipvs, ipx, ipxmsg, ipxrip, ipxsap, ipxwan, irc, isakmp, iscsi, isdn, iser, isi, isis, isl, ismacryp, ismp, iso7816, iso8583, isobus, isobus.vt, isup, itdm, iua, iuup, iwarp-ddp, iwarp-ddp-rdmap, iwarp-mpa, ixiatrailer, ixveriwave, j1939, jdwp, jmirror, jpeg, json, jxta, jxta.udp, k12, kafka, kerberos, kingfisher, kink, kismet, klm, knet, knxip, kpasswd, krb4, krb5, krb5rpc, kt, l1-events, l2tp, lacp, lanforge, lapb, lapbether, lapd, lapdm, laplink, lapsat, lat, lbm, lbmc, lbmpdm, lbmpdm-tcp, lbmr, lbmsrs, lbtrm, lbtru, lbttcp, lcm, ldap, ldp, ldss, lg8979, lisp, lisp-data, lisp-tcp, llc, llcgprs, lldp, llmnr, llt, lltd, lmi, lmp, ln, lnet, log3gpp, logcat, logcat_text, lon, loop, lpd, lpp, lppe, lr8, lsc, lsd, lte-rrc, lte-rrc.bcch.bch, lte-rrc.bcch.dl.sch, lte-rrc.dl.ccch, lte-rrc.dl.dcch, lte-rrc.mcch, lte-rrc.pcch, lte-rrc.ul.ccch, lte-rrc.ul.dcch, ltp, lustre, lwapp, lwapp-cntl, lwapp-l3, lwm, lwm2mtlv, lwres, m2ap, m2pa, m2tp, m2ua, m3ap, m3ua, mac-lte, mac-lte-framed, mac-nr, mac-nr-framed, maccontrol, macmgmt, mactelnet, manolito, mapi, mapos, marker, mausb, mbtcp, mcast, mcpe, mdns, mdshdr, media, megaco, memcache, mesh, meta, meta_data, meth, mgcp, mikey, mime_dlt, mime_multipart, mip, mip6, miop, mka, mle, mmse, mndp, mojito, moldudp64, mongo, mount, mp2t, mp4, mp4ves, mpeg-ca, mpeg-descriptor, mpeg-dsmcc, mpeg-pat, mpeg-pmt, mpeg-sect, mpeg-pes, mpeg1, mpls, mpls-echo, mpls-pm, mpls-psc, mpls-y1711, mplscp, mplsoam, mplstp, mplstp-ach, mplstp-fm, mplstp-lock, mplstp-oam, mpp, mpshdr, mptcp, mqtt, mqtt-sn, mqttsn, mr3da, mrdisc, mrp-mmrp, mrp-msrp, mrp-mvrp, ms-mms, msn-messenger, msnip, msnlb, msnms, msproxy, msrp, msrp-tcp, msrps, mswsp, mtp2, mtp3, mtp3mg, multipart, mux27010, mysql, nano, nas-5gs, nas-eps, nb_rtpmux, nbap, nbdgm, nbipx, nbns, nbss, nbt-datagram, nbt-ns, nbt-ss, ncp, ncp2222, ncsi, ndmp, ndp, ndps, negoex, netanalyzer, netbios, netdump, netflow, netgear-ensemble, netlink, netlink-generic, netlink-netfilter, netlink-route, netlink-sock_diag, netmon_event, netmon_filter, netmon_header, netmon_network_info, netperfmeter, netrom, netsync, nettl, nfapi, nflog, nfs, nfs.cb, nfsacl, nfsauth, nhrp, nisplus, nlm, nlsp, nm, nmf, noe, nordic_ble, norm, novell_pkis, npmp, nr-rrc, nr-rrc.bcch.bch, nr-rrc.bcch.dl.sch, nr-rrc.dl.ccch, nr-rrc.dl.dcch, nr-rrc.pcch, nr-rrc.ul.ccch, nr-rrc.ul.ccch1, nr-rrc.ul.dcch, ns-ha, ns_cert, ns_diag, ns_ha, ns_mep, ns_rpc, ns_rpc_clt, ns_rpc_server, ns_trace, nsip, nsrp, ntlmssp, ntp, null, nvme, nvme-rdma, nvme-tcp, nwmtp, nwp, nx, oampdu, obex, ocfs2, ocp1, ocsp, oer, oicq, old-pflog, olsr, omapi, omron-fins, opa, opa.9b, opa.fe, opa.mad, opc-ua, opcua, openflow, openflow_v1, openflow_v4, openflow_v5, openflow_v6, opensafety, openvpn, openwire, opsi, optommp, opus, osc, oscore, ospf, ossp, p1, p22, p3, p7, p772, p_mul, packetbb, packetcable, packetlogger, pagp, paltalk, pana, pap, pathport, pbb, pcap, pcapng, pccc, pcomtcp, pcep, pcp, pdcp-lte, pdcp-lte-framed, pdcp-nr, pdcp-nr-framed, peekremote, per, pfcp, pflog, pgm, pgsql, pim, pingpongprotocol, pktap, pktc, pktgen, pmproxy, pn-cm, pn-dcp, pn-io, pn-mrp, pn-mrrt, pn-ptcp, pn-rt, pn-rtc, pnrp, pop, portcontrol, portmap, ppcap, ppi, ppp, ppp-comp, ppp-lcp, ppp-mp, ppp-mppe, ppp-mpls, ppp-mux, pppoe, pppoed, pptp, pres, prism, protobuf, proxy, ptp, ptpip, pulse, pvfs, pvfs2, pw-atm, pw-cesopsn, pw-eth-heuristic, pw-fr, pw-hdlc, pw-satop, pwach, q2931, q708, q931, q933, qllc, qnet6, qsig, quake, quake2, quake3, quakeworld, quic, r09, r3, radiotap, radius, radius-dae, ranap, raw, rcp, rdm, rdp, rdpudp, rdt, realtek, redback, redbackli, reload, reload-framing, remact, remunk, rep_proc, retix-bpdu, rfc2190, rfc2198, rfc7468, rfid, rgmp, riemann, rip, ripng, rlc, rlc-lte, rlc-lte-framed, rlc-nr, rlm, rlogin, rlp, rm, rmi, rmp, rmt-alc, rmt-fec, rmt-lct, rmt-norm, rnsap, rohc, roofnet, roverride, rpc, rpcap, rpcordma, rpkirtr, rpl, rpl-dio, rpl-dis, rpl-dao, rpl-daoack, rquota, rrc, rrlp, rs-acct, rsh, rsip, rsl, rsp, rstat, rsvp, rsync, rtacser, rtcdc, rtcfg, rtcp, rtitcp, rtls, rtmac, rtmpt, rtnet, rtp, rtp-ed137, rtp-events, rtp-midi, rtpevent, rtpproxy, rtps, rtps-proc, rtps-sm, rtps-utils, rtps-virtual, rtse, rtsp, rua, rudp, rwall, rx, s101, s1ap, s5066, s5066dts, s7comm, s7comm-plus, sabp, sadmind, sametime, samr, sap, sasp, sbc, sbccs, sccp, sccpmg, scop, scsi, scsi-mmc, scsi-osd, scsi-sbc, scsi-smc, scsi-ssc, sctp, sctp-addip, sctp-asconf, sctp-auth, sctp-chunk, sctp-data, sctp-forward-tsn, sctp-hb, sctp-init, sctp-pktdrop, sctp-sack, sctp-shutdown, sctp-stream-reset, sdh, sdlc, sdp, sebek, selfm, sep, serialization, ses, sflow, sgsap, sgsn-cdr, shdlc, sigcomp, simple, simulcrypt, sip, sipfrag, sita, skinny, skype, slarp, slimp3, sll, sm, smb, smb-direct, smb-mailslot, smb-pipe, smb-sidsnooping, smb2, smcr, smpp, smrse, sms, smtp, smux, sna, snaeth, snap, snmp, snort, socks, socks-udp, socketcan, socks, someip, someip-sd, sonmp, spdy, spice, spp, spray, sprt, spx, sqllite, srp, srt, srvloc, ss7hop, sscf-nni, sscop, ssh, ssl, sstp, starteam, statnotify, status, stt, stun, stun-tcp, stun-turn, sua, sv, svn, swils, swipe, symantec, sync, synergy, synphasor, sysdig-event, sysex, syslog, systemd_journal, t124, t125, t30, t38, tacacs, tacplus, tali, tapa, tcap, tcg-cp-oids, tcp, tcpcl, tcpencap, tcpros, tds, teamspeak2, tecmp, tecmp.payload, teimanagement, teklink, telkonet, telnet, teredo, tetra, text-lines, tfp, tftp, thread, thread_address, thread_bcn, thread_coap, thread_dg, thread_mc, thread_meshcop, thread_nwd, thrift, tibia, time, tipc, tivoconnect, tkn4int, tn3270, tn5250, tnef, tns, tpcp, tpkt, tpncp, tr, tr-064, trill, trmac, ts2, tsdns, tsp, tte, tte-pcf, ttl, turbocell, turnchannel, tuxedo, tvbuff, twamp, twamp-control, twamp-test, tzsp, u3v, ua, ua3g, uasip, uaudp, ubdp, ubertooth, ubikdisk, ubikvote, ucd, ucp, udld, udp, udpencap, udplite, udt, uftp, uftp4, uftp5, uhd, ulp, uma, umts_fp, umts_mac, umts_rlc, usb, usb-audio, usb-com, usb-dfu, usb-hid, usb-hub, usb-masstorage, usb-video, usbip, user_dlt, user_encap, v120, v150fw, v5dl, v5ef, v5ua, vcdu, vdp, vines, vines_arp, vines_echo, vines_frp, vines_icp, vines_ipc, vines_llc, vines_rtp, vines_spp, viperdb, vlan, vmlab, vnc, vntag, vp8, vpp, vrrp, vrt, vsip, vsock, vssmonitoring, vtp, vuze-dht, vxi11, vxlan, wai, wassp, waveagent, wbxml, wccp, wcp, websocket, wfleet-hdlc, who, whois, wifi_dpp, wifi_display, wifi_p2p, wimax, wimaxasncp, wimaxmacphy, wins, winsrepl, wlancertextn, wlccp, wmio, wol, wow, wpan, wpan-nonask-phy, wpan-tap, wreth, wsmp, wsp, wtp, wtls, wtp-wsp, x11, x224, x225, x25, x29, x2ap, x509af, x509ce, x509if, x509sat, xdmcp, xip, xmcp, xml, xmpp, xmpp-xml, xnap, xot, xra, xtp, xyplex, yami, yhoo, ymsg, z21, z3950, zabbix, zbee_apf, zbee_aps, zbee_beacon, zbee_nwk, zbee_nwk_gp, zbee_zcl, zbee_zcl_closures.door_lock, zbee_zcl_general.alarms, zbee_zcl_general.analog_input, zbee_zcl_general.analog_output, zbee_zcl_general.analog_value, zbee_zcl_general.appliance_control, zbee_zcl_general.appliance_events_alerts, zbee_zcl_general.appliance_statistics, zbee_zcl_general.ballast_configuration, zbee_zcl_general.basic, zbee_zcl_general.binary_input, zbee_zcl_general.binary_output, zbee_zcl_general.binary_value, zbee_zcl_general.color_control, zbee_zcl_general.commissioning, zbee_zcl_general.device_temperature_configuration, zbee_zcl_general.diagnostics, zbee_zcl_general.groups, zbee_zcl_general.identify, zbee_zcl_general.level_control, zbee_zcl_general.multistate_input, zbee_zcl_general.multistate_output, zbee_zcl_general.multistate_value, zbee_zcl_general.on_off, zbee_zcl_general.on_off_switch_configuration, zbee_zcl_general.ota, zbee_zcl_general.partition, zbee_zcl_general.poll_control, zbee_zcl_general.power_configuration, zbee_zcl_general.power_profile, zbee_zcl_general.rssi_location, zbee_zcl_general.scenes, zbee_zcl_general.time, zbee_zcl_ha.appliance_identification, zbee_zcl_ha.meter_identification, zbee_zcl_hvac.dehumidification_control, zbee_zcl_hvac.fan_control, zbee_zcl_hvac.pump_configuration_control, zbee_zcl_hvac.thermostat, zbee_zcl_hvac.thermostat_ui_configuration, zbee_zcl_hvac.user_interface_configuration, zbee_zcl_lighting.ballast_configuration, zbee_zcl_lighting.color_control, zbee_zcl_meas_sensing.electrical_measurement, zbee_zcl_meas_sensing.flow_measurement, zbee_zcl_meas_sensing.illuminance_level_sensing, zbee_zcl_meas_sensing.illuminance_measurement, zbee_zcl_meas_sensing.occupancy_sensing, zbee_zcl_meas_sensing.pressure_measurement, zbee_zcl_meas_sensing.relative_humidity_measurement, zbee_zcl_meas_sensing.temperature_measurement, zbee_zcl_se.calendar, zbee_zcl_se.device_management, zbee_zcl_se.drlc, zbee_zcl_se.energy_management, zbee_zcl_se.events, zbee_zcl_se.ke, zbee_zcl_se.mdm, zbee_zcl_se.messaging, zbee_zcl_se.metering, zbee_zcl_se.prepayment, zbee_zcl_se.price, zbee_zcl_se.tunneling, zbee_zdp, zbip_beacon, zebra, zep, zigbee, zigbee-ip, zip, zipl, zmtp, zrtp

</details>

</details>

---

## 完整分类统计表

| 序号 | 分类名称 | 协议数量 | 业务价值 | 流量占比估算 |
|------|---------|---------|---------|------------|
| 1 | Web应用与API服务 | 17 | ⭐⭐⭐⭐⭐ | 40-60% |
| 2 | 数据库服务 | 9 | ⭐⭐⭐⭐⭐ | 10-20% |
| 3 | 消息队列与流处理 | 7 | ⭐⭐⭐⭐⭐ | 5-15% |
| 4 | 容器与云原生平台 | 6 | ⭐⭐⭐⭐⭐ | 5-10% |
| 5 | 对象存储与分布式存储 | 30 | ⭐⭐⭐⭐⭐ | 10-25% |
| 6 | 负载均衡与反向代理 | 12 | ⭐⭐⭐⭐ | - |
| 7 | 身份认证与访问控制 | 25 | ⭐⭐⭐⭐ | <1% |
| 8 | 监控与可观测性 | 5 | ⭐⭐⭐⭐ | 1-5% |
| 9 | DNS与服务发现 | 4 | ⭐⭐⭐⭐ | <1% |
| 10 | 网络基础设施 | 130 | ⭐⭐⭐⭐⭐ | 100% (底层) |
| 11 | DHCP与地址管理 | 5 | ⭐⭐⭐ | <1% |
| 12 | 时间同步 | 4 | ⭐⭐⭐ | <1% |
| 13 | VPN与加密隧道 | 10 | ⭐⭐⭐⭐ | 5-20% |
| 14 | 防火墙与安全网关 | 4 | ⭐⭐⭐⭐ | - |
| 15 | 邮件系统 | 5 | ⭐⭐⭐ | 1-5% |
| 16 | 文件传输 | 6 | ⭐⭐⭐ | 1-10% |
| 17 | 远程管理 | 8 | ⭐⭐⭐ | <1% |
| 18 | VoIP与统一通信 | 26 | ⭐⭐⭐ | 1-10% |
| 19 | 工业控制系统 | 12 | ⭐⭐ | 特定行业 |
| 20 | 电信与移动网络 | 45 | ⭐⭐ | 电信专用 |
| 21 | 物联网 | 14 | ⭐⭐ | 物联网场景 |
| 22 | 多媒体流 | 2 | ⭐ | <1% |
| 23 | P2P与文件共享 | 4 | ⭐ | 极少 |
| 24 | 游戏协议 | 6 | ⭐ | 特定场景 |
| 25 | 遗留协议 | 28 | ⭐ | 遗留系统 |
| 26 | Wireshark内部协议 | 6 | - | - |
| 27 | 未分类/其他 | 613 | ⭐ | 极少 |
| **总计** | **全部分类** | **1043** | - | - |

---

## 数据中心协议分析建议

### 优先级1：核心业务系统 (前69个协议)

这69个协议支撑了现代数据中心80-90%的核心业务流量，应作为协议分析模块开发的**最高优先级**：

1. **Web/API层** (17个): HTTP/HTTPS、gRPC、JSON、Protobuf、TLS
2. **数据层** (9个): MySQL、PostgreSQL、Redis、MongoDB、Elasticsearch
3. **消息层** (7个): Kafka、RabbitMQ、MQTT
4. **容器层** (6个): VXLAN、Geneve、GRE
5. **存储层** (30个): NFS、SMB、iSCSI、FC、S3

### 优先级2：基础设施服务 (前185个协议)

这些协议是数据中心基础设施的支柱，应作为**第二优先级**：

- 网络基础：TCP/IP、VLAN、路由协议
- 负载均衡：VRRP、BGP、ECMP
- 安全认证：LDAP、Kerberos、RADIUS
- 监控运维：SNMP、Syslog、NetFlow

### 优先级3：企业应用与专用系统 (约100个协议)

根据具体业务需求选择性支持：

- VoIP/UC：SIP、RTP（如有统一通信需求）
- 工业控制：Modbus、S7（如有OT网络）
- 物联网：MQTT、CoAP（如有IoT场景）

### 低优先级：其他协议 (约700个)

这些协议在现代数据中心中使用频率极低，可暂不支持。

---

---

## 性能分析协议统计

### 包含性能信息的协议总览

**总计**: 63 个协议包含错误码、返回码、状态信息等性能指标（标记为 🔍）

这些协议直接承载应用服务，可用于APM（应用性能监控）、故障诊断、SLA监控等场景。

| 分类 | 性能协议数 | 总协议数 | 覆盖率 | 关键协议 |
|------|-----------|---------|--------|---------|
| Web/API | 8 | 17 | 47% | http, http2, grpc, thrift |
| 数据库 | 9 | 9 | 100% | mysql, pgsql, mongodb, redis |
| 消息队列 | 5 | 7 | 71% | kafka, amqp, mqtt |
| 存储 | 8 | 30 | 27% | nfs, smb, iscsi, ceph |
| 认证 | 6 | 25 | 24% | ldap, kerberos, radius |
| 监控 | 2 | 5 | 40% | snmp, syslog |
| DNS | 1 | 4 | 25% | dns |
| 邮件 | 3 | 5 | 60% | smtp, imap, pop |
| 文件传输 | 3 | 6 | 50% | ftp, sftp, tftp |
| 远程管理 | 3 | 8 | 38% | rdp, ssh, vnc |
| VoIP | 6 | 26 | 23% | sip, rtcp, h323 |
| 工控 | 4 | 12 | 33% | modbus, s7comm, dnp3 |
| 网络服务 | 2 | 9 | 22% | dhcp, ntp |
| VPN | 3 | 10 | 30% | ssh, openvpn, sftp |
| **总计** | **63** | **~200** | **~32%** | - |

### 性能协议优先级建议

#### 🔥 最高优先级（APM核心协议）- 30个

**Web/API层** (8个):
- http, http2, grpc, thrift, json, protobuf, quic, spdy

**数据库层** (9个):
- mysql, pgsql, tds, tns, cql, elasticsearch, memcache, couchbase, drda

**消息队列** (5个):
- kafka, amqp, mqtt, mq, openwire

**存储层** (8个):
- nfs, smb, smb2, iscsi, nvme-tcp, ceph, lustre, afs

这30个协议覆盖了现代数据中心80-90%的核心业务流量，且全部包含丰富的性能指标。

#### ⭐ 高优先级（企业应用）- 18个

**认证与安全** (6个): ldap, kerberos, radius, tacacs, tacplus, diameter
**VoIP通信** (6个): sip, rtcp, h323, mgcp, megaco, sccp
**邮件系统** (3个): smtp, imap, pop
**远程管理** (3个): rdp, ssh, vnc

#### 📊 中优先级（特定场景）- 15个

**工控系统** (4个): modbus, s7comm, dnp3, bacnet
**文件传输** (3个): ftp, sftp, tftp
**网络服务** (2个): dns, snmp, syslog, dhcp, ntp
**VPN** (3个): openvpn

---

**分析脚本**: `classify_by_datacenter_systems.py`, `mark_performance_protocols.py`
**生成日期**: 2025-11-02
**分类方法**: 基于现代IT数据中心业务系统架构和流量特征
**性能标记**: 基于协议是否包含错误码、返回码、状态信息等性能指标

