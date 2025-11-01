# match_tcp_conns.sh - 开发维护指南

> **版本**: v3.0
> **最后更新**: 2025-10-30
> **仓库**: `/Users/ricky/Downloads/code/tshark`

---

## 目录

1. [核心架构](#核心架构)
2. [代码结构](#代码结构)
3. [关键函数](#关键函数)
4. [修改指南](#修改指南)
5. [调试技巧](#调试技巧)
6. [性能优化](#性能优化)

---

## 核心架构

### 匹配特征权重（v3.0）

| 特征 | 权重 | 代码位置 | 说明 |
|------|------|----------|------|
| **IPID匹配** | 16% | L990-1006 | **必要条件**，无IPID直接拒绝 |
| SYN选项序列 | 25% | L925-932 | MSS, WScale, SACK, Timestamp |
| 客户端ISN | 12% | L934-941 | 初始序列号 |
| 服务器ISN | 6% | L943-950 | 初始序列号 |
| TCP时间戳 | 10% | L952-959 | TSval/TSecr |
| 客户端首包负载 | 15% | L962-969 | MD5哈希（前256字节） |
| 服务器首包负载 | 8% | L970-978 | MD5哈希（前256字节） |
| 长度形状签名 | 8% | L980-988 | 前N个包的长度序列 |

**总权重**: 1.00

### 自动检测策略

#### Header-only检测（L509）
```awk
header_only = (cap_bad_cnt > 0 && cap_bad_cnt * 1.0 / total_cnt >= 0.80) ? 1 : 0
```
- 统计 `frame.cap_len < frame.len` 的报文比例
- 超过80%判定为header-only

#### 分桶策略检测（L290-379）
```bash
if 服务器IP完全相同:
    BUCKET="server"  # 高精度
elif 有共同端口:
    BUCKET="port"    # NAT/LB友好
else:
    BUCKET="server"  # 警告
```

#### 采样策略（L745-824）
```bash
if 连接数 > 1000:
    启用时间分层采样（10%，最多3000个）
    保护异常连接（报文数<=3 或 >=500）
```

---

## 代码结构

```
match_tcp_conns.sh (1187行)
├─ 帮助信息 (L17-56)
│  └─ usage() 函数
├─ 文件扫描 (L59-91)
│  └─ scan_directory_for_pcap() 函数
├─ 参数解析 (L93-153)
├─ 输入验证 (L155-214)
├─ 依赖检查 (L216-242)
├─ 临时目录 (L244-246)
├─ extract_fields() (L263-283)
│  └─ tshark提取25+字段
├─ 自动检测策略 (L290-379)
│  ├─ 提取服务器IP:端口
│  ├─ 计算交集
│  └─ 决策分桶策略
├─ build_conn_table() (L382-529)
│  ├─ 按tcp.stream分组
│  ├─ 计算各维度指纹
│  ├─ 检测header-only
│  └─ 输出连接特征表
├─ sample_connections() (L536-743)
│  ├─ 时间分层采样
│  ├─ 异常连接保护
│  └─ 随机采样
├─ 采样决策 (L745-824)
└─ 匹配逻辑 (L827-1186)
   ├─ 准备分桶数据
   ├─ score_pair() 函数 (L882-1011)
   │  ├─ IPID必要条件检查
   │  ├─ 计算各特征分数
   │  └─ 返回总分和证据
   ├─ quicksort() 函数 (L1013-1037)
   ├─ 读取连接表
   ├─ 按桶分组
   ├─ 计算相似度
   ├─ 贪心匹配
   └─ 输出结果
```

---

## 关键函数

### 1. extract_fields() (L263-283)

**功能**: 提取TCP报文字段

**输入**: pcap文件路径, 输出TSV文件路径

**输出**: TSV格式的报文字段（25+字段）

**关键字段**:
```bash
tcp.stream          # TCP流编号
frame.time_epoch    # 时间戳
ip.src/ip.dst       # IP地址
tcp.srcport/dstport # 端口
tcp.flags.syn/ack   # TCP标志
tcp.seq/ack         # 序列号
tcp.len             # TCP负载长度
tcp.options.*       # TCP选项
ip.id               # IP标识符
frame.cap_len/len   # 捕获/实际长度
data.data           # 负载数据（十六进制）
```

### 2. build_conn_table() (L382-529)

**功能**: 构建连接特征表

**输入**: TSV报文数据, 侧标识(A/B), 输出文件, topN, lenSig

**输出**: 连接特征表（每行一个连接）

**主要逻辑**:
1. 按tcp.stream分组
2. 识别握手（SYN, SYN-ACK）
3. 提取客户端/服务器IP:端口
4. 计算各维度指纹:
   - synopt: SYN选项序列
   - isn_c/isn_s: 初始序列号
   - ts0/te0: TCP时间戳
   - data_c_md5/data_s_md5: 首包负载MD5
   - lensig: 长度形状签名
   - ipid0/ttl0: IP层特征
5. 检测header-only
6. 输出: side-stream | bucket_key | five | features...

### 3. sample_connections() (L536-743)

**功能**: 时间分层采样 + 异常连接保护

**输入**: 连接表, 侧标识, 输出文件, 目标数量

**输出**: 采样后的连接表

**采样策略**:
1. 识别异常连接（报文数<=3 或 >=500）
2. 将正常连接按时间分成20个桶
3. 每个桶按比例随机采样
4. 保留所有异常连接
5. 输出采样统计信息

### 4. score_pair() (L882-1011)

**功能**: 计算两个连接的相似度分数

**输入**: A侧连接, B侧连接

**输出**: "分数\t可用权重\t证据"

**评分逻辑**:
1. **IPID必要条件检查**（L990-1006）
   - 没有IPID匹配直接返回 `"0\t0\tno-ipid"`
2. 计算各特征分数（L913-988）
3. 置信度 = 匹配分数 / 可用权重
4. 返回分数、可用权重、证据列表

---

## 修改指南

### 添加新特征

**步骤**:

1. **在 extract_fields() 中添加tshark字段** (L263-283)
   ```bash
   -e tcp.new_field  # 新字段
   ```

2. **在 build_conn_table() 中计算特征值** (L382-529)
   ```awk
   new_field = $26  # 假设是第26个字段
   # 计算逻辑...
   ```

3. **在 score_pair() 中添加比较和权重** (L882-1011)
   ```awk
   w_new = 0.05  # 新特征权重
   if (eq(newA, newB)) {
       raw += w_new
       avail += w_new
       evi = evi "new_feature "
   }
   ```

4. **更新测试用例**
   ```bash
   # 在 test_match_tcp_conns.sh 中添加测试
   ```

### 调整权重

**位置**: score_pair() 函数 (L913-922)

```awk
w_syn = 0.25      # SYN选项序列
w_ic = 0.12       # 客户端ISN
w_is = 0.06       # 服务器ISN
w_dc = 0.15       # 客户端首包负载
w_ds = 0.08       # 服务器首包负载
w_ts = 0.10       # TCP时间戳
w_ls = 0.08       # 长度形状签名
w_ipid = 0.16     # IPID匹配（必要条件）
# 总计: 1.00
```

**调整原则**:
- 提高可靠特征的权重（SYN选项、TCP时间戳、IPID）
- 降低不可靠特征的权重（ISN、负载哈希、长度签名）
- 确保总权重为1.00
- IPID作为必要条件，额外加分

### 修改分桶策略

**位置**: 自动检测逻辑 (L290-379)

```bash
# 决策逻辑 (L357-373)
if [[ $common_server_count -gt 0 ]] && \
   [[ $common_server_count -eq $A_server_count ]] && \
   [[ $common_server_count -eq $B_server_count ]]; then
    BUCKET="server"  # 服务器IP完全相同
elif [[ $common_port_count -gt 0 ]]; then
    BUCKET="port"    # 有共同端口,但服务器IP不同
else
    BUCKET="server"  # 没有共同端口
    echo "警告: 没有共同端口,可能无法匹配"
fi
```

### 修改采样策略

**位置**: 采样决策逻辑 (L745-824)

```bash
# 调整采样阈值 (L759)
if [[ $A_count -gt 1000 || $B_count -gt 1000 ]]; then
    SAMPLE_ENABLED=1
fi

# 调整采样率 (L767-779)
A_TARGET=$(awk -v count="$A_count" 'BEGIN {
  target = int(count * 0.10 + 0.5)  # 10%采样率
  if (target < 100) target = 100    # 最少100个
  if (count > 30000 && target > 3000) target = 3000  # 最多3000个
  print target
}')
```

---

## 调试技巧

### 1. 查看中间文件

```bash
# 修改脚本，注释掉trap清理 (L246)
# trap 'rm -rf "$tmpdir"' EXIT

# 运行脚本后查看临时文件
ls -lh /tmp/tmp.XXXXXX/
cat /tmp/tmp.XXXXXX/A.tsv | head -20
cat /tmp/tmp.XXXXXX/A_conn.tsv | head -10
```

### 2. 单独测试函数

```bash
# 提取extract_fields函数
extract_fields "test.pcap" "output.tsv"

# 查看输出
column -t -s $'\t' output.tsv | less -S
```

### 3. 验证分桶策略

```bash
# 查看服务器IP:端口集合
awk -F'\t' '{print $2}' A_conn.tsv | sort -u
awk -F'\t' '{print $2}' B_conn.tsv | sort -u

# 查看共同端口
comm -12 <(cut -d: -f2 A_servers.txt | sort -u) \
         <(cut -d: -f2 B_servers.txt | sort -u)
```

### 4. 分析匹配结果

```bash
# 统计置信度分布
grep "置信度:" correlations.txt | \
  awk '{print $2}' | \
  awk '{
    if ($1 >= 0.9) high++
    else if ($1 >= 0.7) mid++
    else low++
  }
  END {
    print "高(>=0.9):", high
    print "中(0.7-0.9):", mid
    print "低(<0.7):", low
  }'

# 统计证据类型
grep "证据:" correlations.txt | \
  awk -F'证据: ' '{print $2}' | \
  tr ' ' '\n' | sort | uniq -c | sort -rn
```

---

## 性能优化

### 代码结构（v3.0）

```
match_tcp_conns.sh (1187行)
├─ 帮助信息 (17-56)
│  └─ usage() 函数
├─ 文件扫描 (59-91)
│  └─ scan_directory_for_pcap() 函数
├─ 参数解析 (93-153)
│  ├─ 输入/输出目录
│  └─ 高级选项
├─ 输入验证 (155-214)
│  ├─ 目录存在性检查
│  ├─ 扫描pcap文件
│  └─ 输出目录创建
├─ 依赖检查 (216-242)
│  ├─ require() 函数
│  └─ tshark版本检查
├─ 临时目录 (244-246)
│  └─ trap清理机制
├─ extract_fields() (263-283)
│  └─ tshark提取25+字段
├─ 自动检测策略 (290-379)
│  ├─ 提取服务器IP:端口
│  ├─ 计算交集
│  └─ 决策分桶策略
├─ build_conn_table() (382-529)
│  ├─ 按tcp.stream分组
│  ├─ 计算各维度指纹
│  ├─ 检测header-only
│  └─ 输出连接特征表
├─ sample_connections() (536-743)
│  ├─ 时间分层采样
│  ├─ 异常连接保护
│  └─ 随机采样
├─ 采样决策 (745-824)
│  ├─ auto: 连接数>1000时采样
│  ├─ off: 强制不采样
│  └─ N: 强制采样到N个
└─ 匹配逻辑 (827-1186)
   ├─ 准备分桶数据
   ├─ score_pair() 函数
   │  ├─ IPID必要条件检查
   │  ├─ 计算各特征分数
   │  └─ 返回总分和证据
   ├─ quicksort() 函数
   ├─ 读取连接表
   ├─ 按桶分组
   ├─ 计算相似度
   ├─ 贪心匹配
   └─ 输出结果
```

### 关键函数详解

#### 1. scan_directory_for_pcap()

```bash
# 功能: 扫描目录中的pcap/pcapng文件
# 输入: 目录路径
# 输出: 找到的文件列表（每行一个）
# 验证: 必须有且只有2个文件

scan_directory_for_pcap() {
    local dir="$1"
    local -a found_files=()

    # 查找文件（仅当前目录，不递归）
    while IFS= read -r -d '' file; do
        found_files+=("$file")
    done < <(find "$dir" -maxdepth 1 -type f \
             \( -iname "*.pcap" -o -iname "*.pcapng" \) -print0)

    # 验证文件数量
    if [ ${#found_files[@]} -ne 2 ]; then
        echo "错误: 必须有且只有2个文件" >&2
        return 1
    fi

    printf '%s\n' "${found_files[@]}"
}
```

#### 2. extract_fields()

```bash
# 功能: 提取TCP报文字段
# 输入: pcap文件路径, 输出TSV文件路径
# 输出: TSV格式的报文字段（25+字段）

extract_fields() {
  local in="$1" out="$2"

  tshark -r "$in" -Y "tcp" -o tcp.desegment_tcp_streams:false \
    -T fields -Eseparator=$'\t' \
    -e tcp.stream          # TCP流编号
    -e frame.number        # 帧号
    -e frame.time_epoch    # 时间戳
    -e ip.version          # IP版本
    -e ip.src              # 源IP
    -e ip.dst              # 目的IP
    -e tcp.srcport         # 源端口
    -e tcp.dstport         # 目的端口
    -e tcp.flags.syn       # SYN标志
    -e tcp.flags.ack       # ACK标志
    -e tcp.seq             # 序列号
    -e tcp.ack             # 确认号
    -e tcp.len             # TCP负载长度
    -e tcp.window_size_value  # 窗口大小
    -e tcp.options.mss_val    # MSS选项
    -e tcp.options.wscale.shift  # 窗口缩放
    -e tcp.options.sack_perm     # SACK允许
    -e tcp.options.timestamp.tsval  # 时间戳值
    -e tcp.options.timestamp.tsecr  # 时间戳回显
    -e ip.id               # IP标识符
    -e ip.ttl              # TTL
    -e ipv6.hlim           # IPv6跳数限制
    -e frame.cap_len       # 捕获长度
    -e frame.len           # 实际长度
    -e data.data           # 负载数据（十六进制）
    2>/dev/null | sort -t$'\t' -k1,1n -k2,2n > "$out"
}
```

#### 3. build_conn_table()

```awk
# 功能: 构建连接特征表
# 输入: TSV报文数据, 侧标识(A/B), 输出文件, topN, lenSig
# 输出: 连接特征表（每行一个连接）

# 主要逻辑:
# 1. 按tcp.stream分组
# 2. 识别握手（SYN, SYN-ACK）
# 3. 提取客户端/服务器IP:端口
# 4. 计算各维度指纹:
#    - synopt: SYN选项序列
#    - isn_c/isn_s: 初始序列号
#    - ts0/te0: TCP时间戳
#    - data_c_md5/data_s_md5: 首包负载MD5
#    - lensig: 长度形状签名
#    - ipid0/ttl0: IP层特征
# 5. 检测header-only
# 6. 输出: side-stream | bucket_key | five | features...
```

#### 4. sample_connections()

```awk
# 功能: 时间分层采样 + 异常连接保护
# 输入: 连接表, 侧标识, 输出文件, 目标数量
# 输出: 采样后的连接表

# 采样策略:
# 1. 识别异常连接（报文数<=3 或 >=500）
# 2. 将正常连接按时间分成20个桶
# 3. 每个桶按比例随机采样
# 4. 保留所有异常连接
# 5. 输出采样统计信息
```

#### 5. score_pair()

```awk
# 功能: 计算两个连接的相似度分数
# 输入: A侧连接, B侧连接
# 输出: "分数\t可用权重\t证据"

# 评分逻辑:
# 1. IPID必要条件检查（没有IPID直接返回0分）
# 2. 计算各特征分数:
#    - SYN选项序列匹配: 0.25
#    - 客户端ISN匹配: 0.12
#    - 服务器ISN匹配: 0.06
#    - TCP时间戳匹配: 0.10
#    - 客户端首包负载匹配: 0.15
#    - 服务器首包负载匹配: 0.08
#    - 长度形状签名相似度: 0.08
#    - IPID匹配: 0.16
# 3. 置信度 = 匹配分数 / 可用权重
# 4. 返回分数、可用权重、证据列表
```

### 修改指南

#### 添加新特征

**步骤**:

1. **在 `extract_fields()` 中添加tshark字段**
   ```bash
   -e tcp.new_field  # 新字段
   ```

2. **在 `build_conn_table()` 中计算特征值**
   ```awk
   new_field = $26  # 假设是第26个字段
   # 计算逻辑...
   ```

3. **在 `score_pair()` 中添加比较和权重**
   ```awk
   w_new = 0.05  # 新特征权重
   if (eq(newA, newB)) {
       raw += w_new
       evi = evi "new_feature "
   }
   ```

4. **更新测试用例**
   ```bash
   # 在 test_match_tcp_conns.sh 中添加测试
   ```

#### 调整权重（v3.0）

```awk
# 在 score_pair() 函数中 (约913-922行)
w_syn = 0.25      # SYN选项序列 (从0.20提升)
w_ic = 0.12       # 客户端ISN (从0.15降低)
w_is = 0.06       # 服务器ISN (从0.08降低)
w_dc = 0.15       # 客户端首包负载 (从0.18降低)
w_ds = 0.08       # 服务器首包负载 (从0.10降低)
w_ts = 0.10       # TCP时间戳 (从0.07提升)
w_ls = 0.08       # 长度形状签名 (从0.15降低)
w_ipid = 0.16     # IPID匹配 (新增,必要条件)
# 总计: 1.00

# 注意: IPID是必要条件,没有IPID直接返回0分
```

**权重调整原则**:

- 提高可靠特征的权重（SYN选项、TCP时间戳、IPID）
- 降低不可靠特征的权重（ISN、负载哈希、长度签名）
- 确保总权重为1.00
- IPID作为必要条件，额外加分

#### 修改分桶策略

```bash
# 在自动检测逻辑中 (约290-379行)

# 决策逻辑:
if [[ $common_server_count -gt 0 ]] && \
   [[ $common_server_count -eq $A_server_count ]] && \
   [[ $common_server_count -eq $B_server_count ]]; then
    # 服务器IP完全相同
    BUCKET="server"
elif [[ $common_port_count -gt 0 ]]; then
    # 有共同端口,但服务器IP不同
    BUCKET="port"
else
    # 没有共同端口
    BUCKET="server"
    echo "警告: 没有共同端口,可能无法匹配"
fi
```

#### 修改采样策略

```bash
# 在采样决策逻辑中 (约745-824行)

# 调整采样阈值
if [[ $A_count -gt 1000 || $B_count -gt 1000 ]]; then
    SAMPLE_ENABLED=1
fi

# 调整采样率
A_TARGET=$(awk -v count="$A_count" 'BEGIN {
  target = int(count * 0.10 + 0.5)  # 10%采样率
  if (target < 100) target = 100    # 最少100个
  if (count > 30000 && target > 3000) target = 3000  # 最多3000个
  print target
}')
```

### 调试技巧

#### 1. 查看中间文件

```bash
# 修改脚本，注释掉trap清理
# trap 'rm -rf "$tmpdir"' EXIT

# 运行脚本后查看临时文件
ls -lh /tmp/tmp.XXXXXX/
cat /tmp/tmp.XXXXXX/A.tsv | head -20
cat /tmp/tmp.XXXXXX/A_conn.tsv | head -10
```

#### 2. 单独测试函数

```bash
# 提取extract_fields函数
extract_fields "test.pcap" "output.tsv"

# 查看输出
column -t -s $'\t' output.tsv | less -S
```

#### 3. 验证分桶策略

```bash
# 查看服务器IP:端口集合
awk -F'\t' '{print $2}' A_conn.tsv | sort -u
awk -F'\t' '{print $2}' B_conn.tsv | sort -u

# 查看共同端口
comm -12 <(cut -d: -f2 A_servers.txt | sort -u) \
         <(cut -d: -f2 B_servers.txt | sort -u)
```

#### 4. 分析匹配结果

```bash
# 统计置信度分布
grep "置信度:" correlations.txt | \
  awk '{print $2}' | \
  awk '{
    if ($1 >= 0.9) high++
    else if ($1 >= 0.7) mid++
    else low++
  }
  END {
    print "高(>=0.9):", high
    print "中(0.7-0.9):", mid
    print "低(<0.7):", low
  }'

# 统计证据类型
grep "证据:" correlations.txt | \
  awk -F'证据: ' '{print $2}' | \
  tr ' ' '\n' | sort | uniq -c | sort -rn
```

---

## 性能优化

### 性能特性

| 场景 | 连接数 | 处理时间 | 内存占用 | 优化策略 |
|------|--------|----------|----------|----------|
| 小规模 | < 100 | < 5秒 | < 50MB | 无需优化 |
| 中规模 | 100-1000 | 5-30秒 | 50-200MB | 默认设置 |
| 大规模 | 1000-10000 | 30-300秒 | 200MB-1GB | 自动采样 |
| 超大规模 | > 10000 | > 300秒 | > 1GB | 强制采样 |

### 性能瓶颈

#### 1. tshark提取字段

**瓶颈**: 提取25+字段，大文件耗时长

**优化**:
```bash
# 使用过滤器减少报文数
tshark -r large.pcap -Y "tcp.port==80" -w filtered.pcap

# 然后再运行匹配
bash match_tcp_conns.sh -i filtered_dir/
```

#### 2. 连接匹配

**瓶颈**: 同一桶内的连接两两比较，复杂度O(n²)

**优化**:
```bash
# 使用采样减少连接数
bash match_tcp_conns.sh -i cases/large/ --sample 1000

# 或使用server分桶（如果适用）
bash match_tcp_conns.sh -i cases/large/ --bucket server
```

#### 3. 排序

**瓶颈**: 候选匹配排序，大桶耗时长

**优化**: 已使用快速排序替代冒泡排序（v3.0）

### 性能建议

#### 按连接数选择策略

```bash
# < 100 连接: 禁用采样
bash match_tcp_conns.sh -i cases/small/ --sample off

# 100-1000 连接: 使用默认设置
bash match_tcp_conns.sh -i cases/medium/

# 1000-10000 连接: 自动采样
bash match_tcp_conns.sh -i cases/large/

# > 10000 连接: 强制采样到1000个
bash match_tcp_conns.sh -i cases/huge/ --sample 1000
```

#### 按场景选择分桶策略

```bash
# 服务器IP相同: 使用server分桶（最快）
bash match_tcp_conns.sh -i cases/firewall/ --bucket server

# 服务器IP不同: 使用port分桶（较慢）
bash match_tcp_conns.sh -i cases/f5/ --bucket port

# 不确定: 使用auto（推荐）
bash match_tcp_conns.sh -i cases/unknown/ --bucket auto
```

#### 预过滤pcap

```bash
# 只分析特定端口
tshark -r large.pcap -Y "tcp.port==443" -w https_only.pcap

# 只分析特定IP
tshark -r large.pcap -Y "ip.addr==10.0.0.1" -w specific_ip.pcap

# 只分析特定时间段
tshark -r large.pcap -Y "frame.time >= \"2024-01-01 00:00:00\"" -w filtered.pcap
```

### 性能监控

```bash
# 使用time命令测量
time bash match_tcp_conns.sh -i cases/test/

# 查看内存使用
/usr/bin/time -l bash match_tcp_conns.sh -i cases/test/  # macOS
```

---

**文档版本**: v3.0
**最后更新**: 2025-10-30
**维护者**: Ricky

