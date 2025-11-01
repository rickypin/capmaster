# 新增 tshark 命令说明

本文档说明了新增到 `tshark_commands.conf` 配置文件中的两个分析命令。

## 命令列表

### 1. TLS Alert 消息统计 (tls-alert-message)

**用途**: 统计 TLS 连接中的 Alert 消息，按 Alert 类型分组，显示每种 Alert 的数量和相关的连接五元组。

**命令**:
```bash
tshark -r {INPUT} -Y "tls.alert_message && tcp" \
  -o tcp.desegment_tcp_streams:TRUE \
  -o tcp.reassemble_out_of_order:TRUE \
  -T fields \
  -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tls.alert_message.desc | \
  awk '{desc=$5; pair=$1":"$2" -> "$3":"$4; cnt[desc]++; if(!seen[desc"|"pair]++) list[desc]=list[desc]"\n"pair} END{for(d in cnt) print "TLS Alert: " d " (count " cnt[d] "):" list[d] "\n"}'
```

**协议依赖**: `tls,tcp`

**输出文件后缀**: `tls-alert-message.txt`

**输出格式示例**:
```
TLS Alert:  (count 36):
61.148.244.65:61921 -> 10.131.46.55:443
61.148.244.65:61920 -> 10.131.46.55:443
...

TLS Alert: 46 (count 202):
61.148.244.65:62175 -> 10.131.46.55:443
61.148.244.65:22807 -> 10.131.46.55:443
...
```

**说明**:
- Alert 类型为空表示未知或无法解析的 Alert
- Alert 类型 46 表示 "Certificate Unknown"
- 每个 Alert 类型下列出所有相关的连接（源IP:源端口 -> 目的IP:目的端口）
- 统计数量显示该 Alert 类型出现的总次数

**测试用例**: `cases/TC-006-02-20180518-1/TC-006-02-20180518-O-61.148.244.65.pcap`

**应用场景**:
- 诊断 TLS 握手失败问题
- 识别证书验证错误
- 发现 TLS 协议协商问题
- 分析加密连接异常

---

### 2. HTTP 响应状态码统计 (http-response-code)

**用途**: 统计 HTTP 响应状态码，按状态码分组，显示每种状态码对应的服务器和客户端连接信息。

**命令**:
```bash
tshark -r {INPUT} -Y "http.response" \
  -T fields \
  -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e http.response.code | \
  awk '{code=$5; pair=$1":"$2" -> "$3":"$4; a[code]=a[code]"\n"pair} END{for(i in a) print "Status "i":"a[i]"\n"}'
```

**协议依赖**: `http`

**输出文件后缀**: `http-response-code.txt`

**输出格式示例**:
```
Status 502:
10.112.195.130:80 -> 10.116.193.91:46592
10.112.195.130:80 -> 10.116.193.93:36860

Status 200:
10.112.195.130:80 -> 10.116.193.91:46590
10.112.195.130:80 -> 10.116.193.91:46592
10.112.195.130:80 -> 10.116.193.93:36858
...
```

**说明**:
- 按 HTTP 状态码分组（200, 404, 502 等）
- 每个状态码下列出所有相关的连接（服务器IP:端口 -> 客户端IP:端口）
- 可以快速识别错误响应和成功响应的分布

**测试用例**: `cases/TC-034-9-20230222-O-1/TC-034-9-20230222-O-A-nginx.pcap`

**应用场景**:
- 诊断 HTTP 服务器错误（5xx）
- 识别客户端请求错误（4xx）
- 分析负载均衡器健康检查
- 监控 API 响应状态
- 发现后端服务故障

---

## 使用方法

### 方法 1: 使用 analyze_pcap.sh 脚本（推荐）

这两个命令已经集成到 `tshark_commands.conf` 配置文件中，会自动根据协议检测结果执行：

```bash
# 分析包含 TLS 流量的 pcap 文件
./analyze_pcap.sh -i cases/TC-006-02-20180518-1/TC-006-02-20180518-O-61.148.244.65.pcap

# 分析包含 HTTP 流量的 pcap 文件
./analyze_pcap.sh -i cases/TC-034-9-20230222-O-1/TC-034-9-20230222-O-A-nginx.pcap
```

输出文件会自动生成在输入文件所在目录的 `statistics/` 子目录中。

### 方法 2: 直接运行命令

如果需要单独运行某个命令：

```bash
# TLS Alert 消息统计
tshark -r input.pcap -Y "tls.alert_message && tcp" \
  -o tcp.desegment_tcp_streams:TRUE \
  -o tcp.reassemble_out_of_order:TRUE \
  -T fields \
  -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tls.alert_message.desc | \
  awk '{desc=$5; pair=$1":"$2" -> "$3":"$4; cnt[desc]++; if(!seen[desc"|"pair]++) list[desc]=list[desc]"\n"pair} END{for(d in cnt) print "TLS Alert: " d " (count " cnt[d] "):" list[d] "\n"}'

# HTTP 响应状态码统计
tshark -r input.pcap -Y "http.response" \
  -T fields \
  -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e http.response.code | \
  awk '{code=$5; pair=$1":"$2" -> "$3":"$4; a[code]=a[code]"\n"pair} END{for(i in a) print "Status "i":"a[i]"\n"}'
```

---

## 命令解析

### TLS Alert 消息命令解析

1. **过滤器**: `-Y "tls.alert_message && tcp"` - 只提取包含 TLS Alert 消息的 TCP 报文
2. **TCP 选项**: 
   - `tcp.desegment_tcp_streams:TRUE` - 启用 TCP 流重组
   - `tcp.reassemble_out_of_order:TRUE` - 重组乱序的 TCP 报文
3. **字段提取**: `-T fields -e ...` - 提取源IP、源端口、目的IP、目的端口、Alert 描述
4. **AWK 处理**: 
   - 按 Alert 类型分组
   - 统计每种 Alert 的数量
   - 去重连接五元组
   - 格式化输出

### HTTP 响应状态码命令解析

1. **过滤器**: `-Y "http.response"` - 只提取 HTTP 响应报文
2. **字段提取**: `-T fields -e ...` - 提取源IP、源端口、目的IP、目的端口、响应状态码
3. **AWK 处理**:
   - 按状态码分组
   - 收集每个状态码对应的所有连接
   - 格式化输出

---

## 常见 TLS Alert 类型

| Alert 代码 | 名称 | 说明 |
|-----------|------|------|
| 0 | Close Notify | 正常关闭连接 |
| 10 | Unexpected Message | 收到意外消息 |
| 20 | Bad Record MAC | MAC 验证失败 |
| 21 | Decryption Failed | 解密失败 |
| 22 | Record Overflow | 记录溢出 |
| 40 | Handshake Failure | 握手失败 |
| 42 | Bad Certificate | 证书错误 |
| 43 | Unsupported Certificate | 不支持的证书 |
| 44 | Certificate Revoked | 证书已吊销 |
| 45 | Certificate Expired | 证书已过期 |
| 46 | Certificate Unknown | 证书未知 |
| 47 | Illegal Parameter | 非法参数 |
| 48 | Unknown CA | 未知的 CA |
| 70 | Protocol Version | 协议版本不匹配 |
| 80 | Internal Error | 内部错误 |
| 112 | Unrecognized Name | 未识别的名称（SNI） |

---

## 常见 HTTP 状态码

| 状态码 | 类别 | 说明 |
|-------|------|------|
| 200 | 成功 | 请求成功 |
| 301 | 重定向 | 永久重定向 |
| 302 | 重定向 | 临时重定向 |
| 304 | 重定向 | 未修改（缓存有效） |
| 400 | 客户端错误 | 错误的请求 |
| 401 | 客户端错误 | 未授权 |
| 403 | 客户端错误 | 禁止访问 |
| 404 | 客户端错误 | 未找到 |
| 500 | 服务器错误 | 内部服务器错误 |
| 502 | 服务器错误 | 网关错误 |
| 503 | 服务器错误 | 服务不可用 |
| 504 | 服务器错误 | 网关超时 |

---

## 故障排查示例

### 示例 1: 诊断 TLS 证书问题

如果 TLS Alert 统计显示大量 Alert 46 (Certificate Unknown)：

```
TLS Alert: 46 (count 202):
61.148.244.65:62175 -> 10.131.46.55:443
...
```

**可能原因**:
- 服务器证书不受信任
- 证书链不完整
- 客户端缺少根证书

**下一步**:
- 检查服务器证书配置
- 验证证书链完整性
- 检查客户端信任的 CA 列表

### 示例 2: 诊断 HTTP 502 错误

如果 HTTP 状态码统计显示 502 错误：

```
Status 502:
10.112.195.130:80 -> 10.116.193.91:46592
10.112.195.130:80 -> 10.116.193.93:36860
```

**可能原因**:
- 后端服务器不可达
- 后端服务器响应超时
- 负载均衡器配置错误

**下一步**:
- 检查后端服务器健康状态
- 查看负载均衡器日志
- 验证网络连通性

---

## 测试

运行测试脚本验证新命令：

```bash
./test_new_commands.sh
```

该脚本会：
1. 对 TLS 测试用例运行分析
2. 对 HTTP 测试用例运行分析
3. 显示生成的统计结果

---

## 配置文件位置

这两个命令已添加到 `tshark_commands.conf` 配置文件的末尾：

- 第 39 行: TLS Alert 消息统计
- 第 42 行: HTTP 响应状态码统计

---

## 更新日志

- **2025-10-31**: 新增 TLS Alert 消息统计和 HTTP 响应状态码统计命令

