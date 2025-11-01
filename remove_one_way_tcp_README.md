# remove_one_way_tcp.sh - 单向 TCP 连接过滤工具

## 功能说明

该脚本用于去除 pcap/pcapng 文件中因捕获丢失导致的单向 TCP 连接噪音。这些连接实际上是双向传输，但由于捕获点位置或配置问题，只捕获到了一个方向的流量。

## 识别逻辑

脚本使用以下逻辑识别单向 TCP 连接（实际为双向传输）:

1. **方向性检查**: 仅存在 A→B（或仅 B→A）报文，反向计数为 0
2. **ACK 进位计算**: 
   - 取该方向第一个与最后一个报文的 ACK，计算 32 位无符号差 `ack_delta`
3. **形态学证据**: 存在 ≥1 个纯 ACK（tcp.len==0）且 ACK 上升的报文
4. **阈值判断**: `ack_delta > threshold`（默认阈值为 20，建议设置 ≥ 20）
5. **命中判定**: 满足以上所有条件即判为"仅捕获单方向"

## 使用方法

### 基本语法

```bash
./remove_one_way_tcp.sh -i <input> [-o <output_path>] [-t <threshold>]
```

### 参数说明

- `-i <input>`: 输入文件或目录（必需）
  - 单个文件: `-i test.pcap`
  - 多个文件（逗号分隔）: `-i file1.pcap,file2.pcapng`
  - 目录: `-i cases/test/` （自动扫描目录及子目录下的 pcap/pcapng 文件）
  - 可多次使用 `-i` 参数

- `-o <path>`: 输出目录路径（可选）
  - 如不指定，默认输出到原文件所在目录

- `-t <num>`: ACK 增量阈值（可选，默认: 20）
  - 用于判断是否为单向捕获
  - 建议设置 ≥ 20，可根据实际情况调整（如 100）

- `-h`: 显示帮助信息

### 使用示例

#### 1. 处理单个文件

```bash
./remove_one_way_tcp.sh -i test.pcap
```

输出文件: `test-OWTR.pcap`（在原文件所在目录）

#### 2. 处理单个文件并指定输出目录

```bash
./remove_one_way_tcp.sh -i test.pcap -o output/
```

输出文件: `output/test-OWTR.pcap`

#### 3. 处理多个文件

```bash
./remove_one_way_tcp.sh -i file1.pcap,file2.pcapng
```

#### 4. 处理目录中的所有文件

```bash
./remove_one_way_tcp.sh -i cases/test/
```

自动扫描 `cases/test/` 及其子目录下的所有 pcap/pcapng 文件

#### 5. 使用自定义阈值

```bash
./remove_one_way_tcp.sh -i test.pcap -t 100
```

使用 ACK 增量阈值 100 进行过滤

## 输出说明

### 文件命名

- 输出文件名格式: `<原文件名>-OWTR.<扩展名>`
- 例如: `capture.pcap` → `capture-OWTR.pcap`

### 输出行为

- **发现单向连接**: 创建过滤后的文件，去除识别到的单向 TCP 流
- **未发现单向连接**: 不创建输出文件，避免不必要的文件生成

### 屏幕输出

脚本会在屏幕上打印:
- 发现的每个单向 TCP 流的 stream ID
- 五元组信息（源 IP:端口 -> 目的 IP:端口）
- ACK 增量值
- 处理总结（总文件数、成功处理数、已过滤数、失败数）

## 测试用例

可使用以下测试用例验证脚本功能:

```bash
./remove_one_way_tcp.sh -i cases/TC-034-3-20210604-O/ -t 20
```

## 技术细节

### 依赖工具

- `tshark`: Wireshark 命令行工具
- `bash`: 版本 3.2+ （macOS 默认版本）

### 性能优化

- 使用 AWK 进行批量数据处理，避免逐个流调用 tshark
- 一次性提取所有 TCP 报文信息，减少 I/O 操作
- 适用于包含数千个 TCP 流的大型 pcap 文件

### 兼容性

- 支持 bash 3.2+（macOS 默认版本）
- 支持 pcap 和 pcapng 格式
- 自动处理 ACK 序号回绕（32 位无符号整数）

## 注意事项

1. **阈值设置**: 
   - 默认阈值 20 适用于大多数场景
   - 对于高流量环境，可适当提高阈值（如 100）以提高准确性

2. **文件覆盖**: 
   - 如果输出文件已存在，会被覆盖
   - 建议使用不同的输出目录或备份原文件

3. **性能考虑**:
   - 处理大文件（> 1GB）可能需要较长时间
   - 建议在性能较好的机器上运行

4. **准确性**:
   - 脚本基于启发式规则识别单向连接
   - 在极少数情况下可能存在误判
   - 建议在使用前先在测试数据上验证

## 故障排除

### 问题: 脚本无法执行

```bash
chmod +x remove_one_way_tcp.sh
```

### 问题: 找不到 tshark

确保已安装 Wireshark:
- macOS: `brew install wireshark`
- Linux: `sudo apt-get install tshark` 或 `sudo yum install wireshark`

### 问题: 未发现任何文件

检查:
- 输入路径是否正确
- 文件扩展名是否为 `.pcap` 或 `.pcapng`
- 是否有读取权限

## 作者

基于 tshark 的网络分析工具

## 许可证

根据项目需求设置

