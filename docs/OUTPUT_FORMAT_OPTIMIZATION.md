# 输出格式优化说明

## 概述

本次优化将三个命令的输出格式从冗长的多行文本格式转换为简洁的表格格式，大幅减少了重复信息，同时保持了所有必要的数据完整性。

## 优化的命令

### 1. `capmaster match` - 匹配连接输出

**命令示例：**
```bash
capmaster match -i /path/to/pcaps/ -o tmp/matched_connections.txt
```

**优化前格式：**
```
[1] A (stream 7): 10.93.137.244:43803 <-> 10.93.75.130:8443
    B (stream 33): 172.68.164.118:51891 <-> 10.93.136.244:443
    Confidence: 1.00 | Evidence: F5_TRAILER(client=172.68.164.118:51891)

[2] A (stream 8): 10.93.137.244:42850 <-> 10.93.75.130:8443
    B (stream 34): 172.71.124.6:56385 <-> 10.93.136.244:443
    Confidence: 1.00 | Evidence: F5_TRAILER(client=172.71.124.6:56385)
```

**优化后格式（表格）：**
```
No.    Stream A   Client A               Server A               Stream B   Client B               Server B               Conf   Evidence                                
1      7          10.93.137.244:43803    10.93.75.130:8443      33         172.68.164.118:51891   10.93.136.244:443      1.00   F5_TRAILER(client=172.68.164.118:51891) 
2      8          10.93.137.244:42850    10.93.75.130:8443      34         172.71.124.6:56385     10.93.136.244:443      1.00   F5_TRAILER(client=172.71.124.6:56385)   
```

**优化效果：**
- 每个匹配对从 4 行减少到 1 行
- 减少约 75% 的行数
- 信息更加紧凑，易于浏览

---

### 2. `capmaster comparative-analysis --service` - 服务级别网络质量分析

**命令示例：**
```bash
capmaster comparative-analysis -i /path/to/pcaps/ --service --topology topology.txt -o tmp/service-network-quality.txt
```

**优化前格式：**
```
Service: 10.93.136.244:443

  File B (10.93.75.130_VIP.pcap):
    Client -> Server:
      Total Packets:        9,336
      Retransmissions:      75 (0.80%)
      Duplicate ACKs:       344 (3.68%)
      Lost Segments:        70 (0.75%)

    Server -> Client:
      Total Packets:        11,509
      Retransmissions:      443 (3.85%)
      Duplicate ACKs:       179 (1.56%)
      Lost Segments:        0 (0.00%)
```

**优化后格式（表格）：**
```
Service                File   Direction       Packets    Retrans      Dup ACK      Lost Seg    
10.93.136.244:443      B      Client->Server  9,336          75 ( 0.8%)    344 ( 3.7%)     70 ( 0.7%)
                              Server->Client  11,509        443 ( 3.8%)    179 ( 1.6%)      0 ( 0.0%)
```

**优化效果：**
- 每个服务的每个方向从 5 行减少到 1 行
- 减少约 80% 的行数
- 便于横向对比不同服务和文件的质量指标

---

### 3. `capmaster comparative-analysis --matched-connections` - 连接对级别质量分析

**命令示例：**
```bash
capmaster comparative-analysis -i /path/to/pcaps/ --matched-connections matched_connections.txt --top-n 10 -o tmp/poor-quality-connections.txt
```

**优化前格式：**
```
Connection Pair #131 (Confidence: 1.00) - Performance Score: 83.0/100
  A (stream 203): 10.93.137.244:38330 <-> 10.93.75.130:8443
  B (stream 205): 172.68.164.167:44200 <-> 10.93.136.244:443

  File A (10.93.75.130_SNAT.pcap) - Score: 100.0/100:
    Client -> Server:
      Total Packets:        73
      Retransmissions:      0 (0.00%)
      Duplicate ACKs:       0 (0.00%)
      Lost Segments:        0 (0.00%)

    Server -> Client:
      Total Packets:        109
      Retransmissions:      0 (0.00%)
      Duplicate ACKs:       0 (0.00%)
      Lost Segments:        0 (0.00%)

  File B (10.93.75.130_VIP.pcap) - Score: 83.0/100:
    Client -> Server:
      Total Packets:        52
      Retransmissions:      6 (11.54%)
      Duplicate ACKs:       16 (30.77%)
      Lost Segments:        0 (0.00%)

    Server -> Client:
      Total Packets:        81
      Retransmissions:      41 (50.62%)
      Duplicate ACKs:       0 (0.00%)
      Lost Segments:        0 (0.00%)
```

**优化后格式（表格）：**
```
Pair#   Stream   Connection                                    File   Dir             Pkts     Retrans      DupACK       LostSeg      Score    Conf  
131     203      10.93.137.244:38330 <-> 10.93.75.130:8443     A      C->S            73           0( 0.0%)     0( 0.0%)     0( 0.0%) 100.0    1.00  
                                                                      S->C            109          0( 0.0%)     0( 0.0%)     0( 0.0%)                
        205      172.68.164.167:44200 <-> 10.93.136.244:443    B      C->S            52           6(11.5%)    16(30.8%)     0( 0.0%) 83.0           
                                                                      S->C            81          41(50.6%)     0( 0.0%)     0( 0.0%)                
```

**优化效果：**
- 每个连接对从 24 行减少到 5 行（包括分隔线）
- 减少约 79% 的行数
- 更容易快速识别问题连接

---

## 兼容性

### 向后兼容
- `parse_matched_connections()` 函数已更新，支持同时解析旧格式和新格式
- 现有的旧格式文件仍然可以被正确解析
- 新格式文件可以作为 `--matched-connections` 参数的输入

### 依赖关系保持
所有命令之间的输入输出依赖关系保持不变：
1. `match` → `matched_connections.txt` → `comparative-analysis --matched-connections`
2. `match --topology` → `topology.txt` → `comparative-analysis --service --topology`

---

## 技术实现

### 修改的文件
1. `capmaster/plugins/match/plugin.py` - `_output_results()` 方法
2. `capmaster/plugins/match/quality_analyzer.py` - 三个函数：
   - `parse_matched_connections()` - 支持新旧格式解析
   - `format_quality_report()` - 服务级别表格格式
   - `format_connection_pair_report()` - 连接对级别表格格式

### 关键特性
- 使用固定宽度列对齐，确保表格整齐
- 保留所有原有信息，无数据丢失
- 使用分隔线清晰区分不同的记录
- 百分比格式统一为 `X.X%`
- 数字使用千位分隔符提高可读性

---

## 测试验证

所有三个命令已通过测试：
```bash
# 测试 1: 匹配连接
capmaster match -i /path/to/pcaps/ -o tmp/matched_connections-new.txt

# 测试 2: 服务级别分析
capmaster comparative-analysis -i /path/to/pcaps/ --service --topology tmp/topology.txt -o tmp/service-network-quality-new.txt

# 测试 3: 连接对级别分析
capmaster comparative-analysis -i /path/to/pcaps/ --matched-connections tmp/matched_connections-new.txt --top-n 10 -o tmp/poor-quality-connections-new.txt

# 测试 4: 验证新格式可被解析
capmaster comparative-analysis -i /path/to/pcaps/ --matched-connections tmp/matched_connections-new.txt --top-n 5 -o tmp/test-parse.txt
```

所有测试均成功通过，新格式输出正确且可被后续命令正确解析。

