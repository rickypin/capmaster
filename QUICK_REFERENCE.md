# 新增命令快速参考

## 🔐 TLS Alert 消息统计

**命令后缀**: `tls-alert-message.txt`  
**协议要求**: TLS + TCP  
**测试文件**: `cases/TC-006-02-20180518-1/TC-006-02-20180518-O-61.148.244.65.pcap`

### 快速使用
```bash
./analyze_pcap.sh -i your-tls-capture.pcap
# 查看结果
cat statistics/*-tls-alert-message.txt
```

### 输出示例
```
TLS Alert: 46 (count 202):
61.148.244.65:62175 -> 10.131.46.55:443
61.148.244.65:22807 -> 10.131.46.55:443
```

### 常见 Alert 代码
| 代码 | 含义 | 说明 |
|-----|------|------|
| 0 | Close Notify | 正常关闭 |
| 40 | Handshake Failure | 握手失败 |
| 42 | Bad Certificate | 证书错误 |
| 46 | Certificate Unknown | 证书未知 ⚠️ |
| 48 | Unknown CA | 未知 CA |

---

## 🌐 HTTP 响应状态码统计

**命令后缀**: `http-response-code.txt`  
**协议要求**: HTTP  
**测试文件**: `cases/TC-034-9-20230222-O-1/TC-034-9-20230222-O-A-nginx.pcap`

### 快速使用
```bash
./analyze_pcap.sh -i your-http-capture.pcap
# 查看结果
cat statistics/*-http-response-code.txt
```

### 输出示例
```
Status 502:
10.112.195.130:80 -> 10.116.193.91:46592

Status 200:
10.112.195.130:80 -> 10.116.193.91:46590
```

### 常见状态码
| 代码 | 含义 | 说明 |
|-----|------|------|
| 200 | OK | 成功 ✅ |
| 301 | Moved Permanently | 永久重定向 |
| 404 | Not Found | 未找到 |
| 500 | Internal Server Error | 服务器错误 ⚠️ |
| 502 | Bad Gateway | 网关错误 ⚠️ |
| 503 | Service Unavailable | 服务不可用 ⚠️ |

---

## 📋 配置文件位置

`tshark_commands.conf` 第 38-42 行：

```bash
# TLS 相关统计
tshark -r {INPUT} -Y "tls.alert_message && tcp" ...::tls-alert-message.txt::tls,tcp

# HTTP 相关统计
tshark -r {INPUT} -Y "http.response" ...::http-response-code.txt::http
```

---

## 🧪 测试命令

```bash
# 运行自动化测试
./test_new_commands.sh

# 手动测试 TLS
./analyze_pcap.sh -i cases/TC-006-02-20180518-1/TC-006-02-20180518-O-61.148.244.65.pcap

# 手动测试 HTTP
./analyze_pcap.sh -i cases/TC-034-9-20230222-O-1/TC-034-9-20230222-O-A-nginx.pcap
```

---

## 🔍 故障排查速查

### TLS Alert 46 (Certificate Unknown)
**症状**: 大量 Alert 46  
**原因**: 证书不受信任、证书链不完整  
**解决**: 检查服务器证书配置、验证证书链

### HTTP 502 (Bad Gateway)
**症状**: 出现 502 状态码  
**原因**: 后端服务器不可达、响应超时  
**解决**: 检查后端服务器、查看负载均衡器日志

### HTTP 503 (Service Unavailable)
**症状**: 出现 503 状态码  
**原因**: 服务过载、维护中  
**解决**: 检查服务器负载、查看应用日志

---

## 📚 详细文档

- **完整说明**: `NEW_COMMANDS_README.md`
- **使用指南**: `ANALYZE_PCAP_GUIDE.md`
- **更改总结**: `CHANGES_SUMMARY.md`

---

**更新日期**: 2025-10-31

