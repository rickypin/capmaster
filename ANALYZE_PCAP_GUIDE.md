# PCAP 分析脚本指南

`analyze_pcap.sh` 是一个灵活的 pcap/pcapng 文件分析脚本，用于自动执行 tshark 命令并生成统计报告。

## 快速开始

```bash
# 分析单个文件（推荐）
./analyze_pcap.sh -i test.pcap

# 使用自定义配置文件
./analyze_pcap.sh -i test.pcap -c custom_commands.conf

# 查看帮助
./analyze_pcap.sh -h
```

## 功能特性

- ✅ **灵活输入**: 支持单个文件、多个文件、目录扫描和混合模式
- ✅ **智能输出**: 默认输出到输入文件所在目录的 `statistics/` 子目录
- ✅ **协议检测**: 自动检测 pcap 文件中的协议，仅执行相关协议的分析命令
- ✅ **外部配置**: 通过配置文件 `tshark_commands.conf` 自定义分析命令
- ✅ **错误处理**: 自动跳过无效文件，继续处理其他文件

## 参数说明

| 参数 | 必需 | 说明 | 示例 |
|------|------|------|------|
| `-i` | ✅ | 输入文件/目录 | `-i test.pcap` |
| `-c` | ❌ | 配置文件路径 | `-c custom.conf` |
| `-o` | ❌ | 输出目录 | `-o output/` |
| `-h` | ❌ | 显示帮助 | `-h` |

### 输入方式

| 方式 | 命令示例 | 说明 |
|------|----------|------|
| 单个文件 | `-i test.pcap` | 最简单 |
| 逗号分隔 | `-i "f1.pcap,f2.pcap"` | 紧凑 |
| 多次 -i | `-i f1.pcap -i f2.pcap` | 清晰 |
| 目录扫描 | `-i cases/test/` | 批量处理 |
| 混合模式 | `-i f1.pcap -i cases/test/ -i "f2.pcap,f3.pcap"` | 最灵活 |

## 输出位置

### 默认输出（不使用 -o）

```
输入文件: cases/test/capture.pcap
输出位置: cases/test/statistics/capture-*.md
```

### 指定输出（使用 -o）

```
输入文件: cases/test/capture.pcap
输出位置: output/capture-*.md
```

## 生成的文件

输出文件命名格式：`<文件名>-<序号>-<后缀>`

对于输入文件 `example.pcap`，根据配置文件中的命令顺序，生成类似以下分析文件：

```
example-1-protocol-hierarchy.md           # 协议层次统计
example-2-ipv4-conversations.md           # IPv4 会话统计
example-3-dns-general.md                  # DNS 通用统计（仅当检测到 DNS 协议）
example-4-tcp-conversations.md            # TCP 会话统计（仅当检测到 TCP 协议）
...
```

**注意**: 实际生成的文件取决于配置文件中的命令和 pcap 文件中检测到的协议。

## 实际使用示例

### 场景 1: 快速分析单个文件

```bash
./analyze_pcap.sh -i capture.pcap
# 结果在 ./statistics/ 目录
```

### 场景 2: 分析案例目录

```bash
./analyze_pcap.sh -i cases/case-001/
# 自动找到该目录下的所有 pcap 文件
# 结果在 cases/case-001/statistics/ 目录
```

### 场景 3: 批量分析多个案例

```bash
./analyze_pcap.sh \
  -i cases/case-001/ \
  -i cases/case-002/ \
  -i cases/case-003/ \
  -o batch_results/
# 所有结果集中到 batch_results/ 目录
```

### 场景 4: 分析相关的两个文件

```bash
./analyze_pcap.sh -i "client.pcap,server.pcap" -o analysis/
# 两个文件的结果都在 analysis/ 目录
```

### 场景 5: 混合使用多种输入方式

```bash
./analyze_pcap.sh \
  -i file1.pcap \
  -i cases/test/ \
  -i "file2.pcap,file3.pcapng" \
  -o output/
```

## 配置文件

### 配置文件位置

脚本默认使用 `tshark_commands.conf` 配置文件，查找顺序：
1. 脚本所在目录
2. 当前工作目录

也可以使用 `-c` 参数指定自定义配置文件。

### 配置文件格式

每行一条命令，格式：`命令模板::输出文件后缀::协议依赖`

- **命令模板**: tshark 命令，使用 `{INPUT}` 作为输入文件占位符
- **输出文件后缀**: 生成文件的后缀名（会自动添加序号前缀）
- **协议依赖**（可选）: 逗号分隔的协议列表，仅当检测到这些协议时才执行
  - 留空或 `all`: 总是执行
  - 单个协议: `dns`、`tcp`、`http` 等
  - 多个协议（OR 关系）: `dns,mdns`（检测到任一协议即执行）

### 配置示例

```bash
# 总是执行的命令（无协议依赖）
tshark -r {INPUT} -q -z io,phs::protocol-hierarchy.md
tshark -r {INPUT} -q -z conv,ip::ipv4-conversations.md::all

# 仅当检测到 DNS 协议时执行
tshark -r {INPUT} -q -z dns,tree::dns-general.md::dns
tshark -r {INPUT} -q -z dns_qr,tree::dns-query-response.md::dns

# 仅当检测到 TCP 协议时执行
tshark -r {INPUT} -q -z conv,tcp::tcp-conversations.md::tcp

# 检测到 DNS 或 MDNS 任一协议时执行
tshark -r {INPUT} -q -z dns,tree::dns-stats.md::dns,mdns

# 复杂命令（包含管道）
tshark -r {INPUT} -Y "tcp.analysis.zero_window" -T fields -e ip.src -e tcp.srcport | sort | uniq -c::tcp-zero-window.md::tcp
```

### 编辑配置文件

```bash
# 编辑默认配置文件
vim tshark_commands.conf

# 创建自定义配置文件
cp tshark_commands.conf my_custom.conf
vim my_custom.conf

# 使用自定义配置文件
./analyze_pcap.sh -i test.pcap -c my_custom.conf
```

## 协议检测机制

脚本会自动检测 pcap 文件中包含的协议，并根据配置文件中的协议依赖决定是否执行命令：

1. **检测阶段**: 使用 `tshark -q -z io,phs` 分析协议层次
2. **过滤阶段**: 检查每条命令的协议依赖，仅执行匹配的命令
3. **跳过提示**: 不匹配的命令会显示跳过信息

**优势**: 避免在不相关的 pcap 文件上执行无意义的分析命令，提高效率。

## 常用 tshark 统计命令参考

### 协议统计

```bash
# 协议层次统计（总是执行）
tshark -r {INPUT} -q -z io,phs::protocol-hierarchy.md

# HTTP 统计（仅 HTTP 流量）
tshark -r {INPUT} -q -z http,tree::http-statistics.md::http

# DNS 统计（仅 DNS 流量）
tshark -r {INPUT} -q -z dns,tree::dns-general.md::dns
tshark -r {INPUT} -q -z dns_qr,tree::dns-query-response.md::dns
```

### 会话统计

```bash
# IPv4 会话（总是执行）
tshark -r {INPUT} -q -z conv,ip::ipv4-conversations.md

# TCP 会话（仅 TCP 流量）
tshark -r {INPUT} -q -z conv,tcp::tcp-conversations.md::tcp

# UDP 会话（仅 UDP 流量）
tshark -r {INPUT} -q -z conv,udp::udp-conversations.md::udp
```

### TCP 连接完整性分析

```bash
# TCP 连接完整性统计（仅 TCP 流量）
# 分析 TCP 连接的握手和关闭状态，支持 IPv4 和 IPv6
# 输出格式：按连接状态（Complete/Established/Half-open）和数据传输情况分组
tshark -2 -r {INPUT} -Y tcp -T fields -Eseparator=$'\t' -e tcp.stream -e tcp.completeness.str -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e ipv6.src -e ipv6.dst | awk -F$'\t' 'function pick(a,b){return a!=""?a:b} function decode(f){r=f~/R/;fn=f~/F/;d=f~/D/;a=f~/A/;sa=substr(f,5,1)=="S";sn=substr(f,6,1)=="S";b=(sn&&sa&&a)?"Complete":(sn&&a)?"Established":sn?"Half-open":"Unknown";dt=(fn||r)?(d?"WITH_DATA_CLOSED":"NO_DATA_CLOSED"):(d?"WITH_DATA":"NO_DATA");return b", "dt} {s=$1;if(!(s in seen)){seen[s]=1;comp[s]=$2;dir[s]=pick($3,$7)":"$4" -> "pick($5,$8)":"$6}} END{for(s in comp){k=decode(comp[s])SUBSEP comp[s];cnt[k]++;list[k]=list[k](list[k]?"\n":"")dir[s]} PROCINFO["sorted_in"]="@ind_str_asc";for(k in cnt){split(k,p,SUBSEP);printf "[Status: %s] [Flags: %s] [Count: %d connections]\n%s\n\n",p[1],p[2],cnt[k],list[k]}}'::tcp-completeness.txt::tcp
```

### TLS 统计

```bash
# TLS Alert 消息统计（仅 TLS 流量）
tshark -r {INPUT} -Y "tls.alert_message && tcp" -o tcp.desegment_tcp_streams:TRUE -o tcp.reassemble_out_of_order:TRUE -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tls.alert_message.desc | awk '{desc=$5; pair=$1":"$2" -> "$3":"$4; cnt[desc]++; if(!seen[desc"|"pair]++) list[desc]=list[desc]"\n"pair} END{for(d in cnt) print "TLS Alert: " d " (count " cnt[d] "):" list[d] "\n"}'::tls-alert-message.txt::tls,tcp
```

### HTTP 统计

```bash
# HTTP 响应状态码统计（仅 HTTP 流量）
tshark -r {INPUT} -Y "http.response" -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e http.response.code | awk '{code=$5; pair=$1":"$2" -> "$3":"$4; a[code]=a[code]"\n"pair} END{for(i in a) print "Status "i":"a[i]"\n"}'::http-response-code.txt::http
```

## 错误处理

脚本会自动处理以下错误情况：

1. ❌ **输入文件不存在**
2. ❌ **输入文件不是 pcap/pcapng 格式**
3. ❌ **输出目录无法创建或不可写**
4. ❌ **tshark 命令未安装**
5. ❌ **tshark 命令执行失败**

### 文件覆盖行为

- ✅ 如果输出文件已存在，脚本会**直接覆盖**，无需确认
- ✅ 覆盖前会显示警告信息
- ✅ 适合重复运行分析以更新结果

## 故障排除

### tshark 命令未找到

```bash
# 检查 tshark 是否安装
which tshark

# macOS 安装
brew install wireshark

# Ubuntu/Debian 安装
sudo apt-get install tshark
```

### 权限错误

```bash
# 确保脚本有执行权限
chmod +x analyze_pcap.sh

# 确保输出目录可写
ls -ld statistics/
```

### 文件不存在或找不到

```bash
# 使用绝对路径
./analyze_pcap.sh -i /absolute/path/to/file.pcap

# 确认当前目录
pwd
ls -l *.pcap
```

### 处理特殊文件名

```bash
# 包含空格的文件名
./analyze_pcap.sh -i "my capture file.pcap"

# 逗号分隔时使用引号
./analyze_pcap.sh -i "file1.pcap,file2.pcap"
```

## 最佳实践

### 💡 推荐用法

1. **使用默认输出目录**: 结果和源文件在一起，便于管理
   ```bash
   ./analyze_pcap.sh -i cases/test/capture.pcap
   # 输出: cases/test/statistics/
   ```

2. **批量处理使用目录扫描**: 简单直接
   ```bash
   ./analyze_pcap.sh -i cases/test/
   ```

3. **文件覆盖用于更新**: 重复运行时自动更新结果
   ```bash
   ./analyze_pcap.sh -i test.pcap  # 第一次运行
   ./analyze_pcap.sh -i test.pcap  # 第二次运行（自动覆盖）
   ```

### 查看分析结果

```bash
# 查看生成的文件
./analyze_pcap.sh -i test.pcap
ls -lh statistics/

# 查看特定分析文件
cat statistics/test-1-protocol-hierarchy.md
```

## 依赖要求

- **bash**: 4.0+
- **tshark**: Wireshark 命令行工具
- **标准 Unix 工具**: file, basename, mkdir 等

## 开发维护指南

### 核心函数

- `detect_protocols()`: 检测 pcap 文件中的协议
- `protocol_exists()`: 检查协议依赖是否满足
- `load_config_file()`: 加载配置文件
- `execute_tshark_command()`: 执行单条 tshark 命令
- `process_single_file()`: 处理单个 pcap 文件

### 配置文件解析逻辑

配置文件每行格式：`命令::后缀::协议`

解析步骤：
1. 按 `::` 分割字符串
2. 第一部分：命令模板（必需）
3. 第二部分：输出后缀（必需）
4. 第三部分：协议依赖（可选，默认为空表示总是执行）

### 协议检测实现

使用 `tshark -q -z io,phs` 获取协议层次，解析输出提取协议名称列表。

### 输出文件命名规则

格式：`<文件名>-<序号>-<后缀>`

- 文件名：从输入文件提取（不含扩展名）
- 序号：命令在配置文件中的顺序（1-based）
- 后缀：配置文件中指定的后缀

### 扩展建议

1. **添加新协议支持**: 在配置文件中添加相应命令，指定协议依赖
2. **自定义输出格式**: 修改 tshark 命令的输出参数
3. **批量处理优化**: 使用目录扫描功能处理多个文件

## 许可证

本脚本为开源工具，可自由修改和使用。
