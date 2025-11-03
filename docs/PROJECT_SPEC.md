# CapMaster Python 重构规范

> **AI Agent 执行文档** - 包含所有技术规范和实施标准

---

## 1. 项目目标

将三个 Shell 脚本重构为统一的 Python CLI 工具：
- `analyze_pcap.sh` (656行) → `capmaster analyze`
- `match_tcp_conns.sh` (1187行) → `capmaster match`
- `remove_one_way_tcp.sh` (485行) → `capmaster filter`

**核心要求:**
- 两层插件架构
- 基于 tshark 4.0+
- Python 3.10+
- 测试覆盖率 ≥ 80%
- 性能 ≥ 90% 原脚本

---

## 2. 技术栈

```toml
[project]
name = "capmaster"
version = "1.0.0"
requires-python = ">=3.10"

dependencies = [
    "click>=8.1.0",      # CLI 框架
    "rich>=13.0.0",      # 终端美化
    "pyyaml>=6.0",       # 配置解析
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-cov>=4.1.0",
    "black>=23.0.0",
    "ruff>=0.1.0",
    "mypy>=1.5.0",
]
```

---

## 3. 目录结构

```
capmaster/
├── capmaster/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                    # CLI 主框架
│   ├── core/                     # 核心组件
│   │   ├── __init__.py
│   │   ├── file_scanner.py       # PCAP 文件扫描
│   │   ├── tshark_wrapper.py     # tshark 封装
│   │   ├── protocol_detector.py  # 协议检测
│   │   └── output_manager.py     # 输出管理
│   ├── plugins/                  # 插件层
│   │   ├── __init__.py
│   │   ├── base.py              # 插件基类
│   │   ├── analyze/             # analyze 插件
│   │   │   ├── __init__.py
│   │   │   ├── plugin.py
│   │   │   ├── config_loader.py
│   │   │   ├── executor.py
│   │   │   └── modules/         # 统计模块（第二层插件）
│   │   │       ├── __init__.py
│   │   │       ├── base.py
│   │   │       ├── protocol_hierarchy.py
│   │   │       ├── tcp_conversations.py
│   │   │       ├── tcp_zero_window.py
│   │   │       ├── tcp_duration.py
│   │   │       ├── tcp_completeness.py
│   │   │       ├── udp_conversations.py
│   │   │       ├── dns_stats.py
│   │   │       ├── http_stats.py
│   │   │       ├── ftp_stats.py
│   │   │       ├── icmp_stats.py
│   │   │       └── ipv4_hosts.py
│   │   ├── match/               # match 插件
│   │   │   ├── __init__.py
│   │   │   ├── plugin.py
│   │   │   ├── extractor.py
│   │   │   ├── connection.py
│   │   │   ├── sampler.py
│   │   │   ├── scorer.py
│   │   │   └── matcher.py
│   │   └── filter/              # filter 插件
│   │       ├── __init__.py
│   │       ├── plugin.py
│   │       └── detector.py
│   ├── utils/
│   │   ├── __init__.py
│   │   └── logger.py
│   └── config/
│       ├── __init__.py
│       └── default_commands.yaml
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_core/
│   │   └── __init__.py
│   └── test_plugins/
│       ├── __init__.py
│       ├── test_analyze/
│       │   └── __init__.py
│       ├── test_match/
│       │   └── __init__.py
│       └── test_filter/
│           └── __init__.py
└── pyproject.toml
```

---

## 4. 核心组件规范

### 4.1 PcapScanner (core/file_scanner.py)

```python
class PcapScanner:
    VALID_EXTENSIONS = {'.pcap', '.pcapng'}
    
    @classmethod
    def scan(cls, paths: List[str], recursive: bool = False) -> List[Path]:
        """扫描并返回所有有效的 PCAP 文件"""
        
    @staticmethod
    def is_valid_pcap(path: Path) -> bool:
        """验证 PCAP 文件（检查扩展名和文件大小）"""
```

### 4.2 TsharkWrapper (core/tshark_wrapper.py)

```python
class TsharkWrapper:
    def __init__(self):
        self.tshark_path = self._find_tshark()
        self.version = self._get_version()
    
    def execute(
        self,
        args: List[str],
        input_file: Optional[Path] = None,
        output_file: Optional[Path] = None,
        timeout: Optional[int] = None
    ) -> subprocess.CompletedProcess:
        """执行 tshark 命令"""
```

### 4.3 ProtocolDetector (core/protocol_detector.py)

```python
class ProtocolDetector:
    def detect(self, pcap_file: Path) -> Set[str]:
        """使用 tshark -z io,phs 检测协议"""
```

### 4.4 OutputManager (core/output_manager.py)

```python
class OutputManager:
    @staticmethod
    def create_output_dir(input_file: Path, custom_output: Optional[Path] = None) -> Path:
        """创建输出目录（默认: 输入文件目录/statistics/）"""
    
    @staticmethod
    def get_output_path(output_dir: Path, base_name: str, sequence: int, suffix: str) -> Path:
        """生成输出文件路径: {base_name}-{sequence}-{suffix}"""
```

---

## 5. 插件系统规范

### 5.1 插件基类 (plugins/base.py)

```python
class PluginBase(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """插件名称（CLI 子命令名）"""
    
    @abstractmethod
    def setup_cli(self, cli_group: click.Group) -> None:
        """注册 CLI 子命令"""
    
    @abstractmethod
    def execute(self, **kwargs) -> int:
        """执行插件逻辑，返回退出码"""
```

### 5.2 分析模块基类 (plugins/analyze/modules/base.py)

```python
class AnalysisModule(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """模块名称"""
    
    @property
    @abstractmethod
    def output_suffix(self) -> str:
        """输出文件后缀"""
    
    @property
    def required_protocols(self) -> Set[str]:
        """所需协议，空集表示总是执行"""
        return set()
    
    @abstractmethod
    def build_tshark_args(self, input_file: Path) -> list[str]:
        """构建 tshark 命令参数"""
    
    def should_execute(self, detected_protocols: Set[str]) -> bool:
        """判断是否应该执行"""
        if not self.required_protocols:
            return True
        return bool(self.required_protocols & detected_protocols)
```

---

## 6. Analyze 插件规范

### 6.1 统计模块列表 (17个模块，完全对齐原脚本)

| 模块 | 输出后缀 | 必需协议 | tshark 参数 | Python后处理 |
|------|---------|---------|------------|-------------|
| protocol_hierarchy | protocol-hierarchy.txt | [] | `-q -z io,phs` | 无 |
| ipv4_conversations | ipv4-conversations.txt | [ip] | `-q -z conv,ip` | 无 |
| ipv4_source_ttls | ipv4-source-ttls.txt | [ip] | `-q -z ip_ttl,tree` | 无 |
| ipv4_destinations | ipv4-destinations-and-ports.txt | [ip] | `-q -z dests,tree` | 无 |
| ipv4_hosts | ipv4-hosts.txt | [ip] | `-q -z endpoints,ip` | 无 |
| tcp_conversations | tcp-conversations.txt | [tcp] | `-q -z conv,tcp` | 无 |
| tcp_zero_window | tcp-zero-window.txt | [tcp] | `-Y "tcp.analysis.zero_window" -T fields ...` | Counter计数+排序 |
| tcp_duration | tcp-connection-duration.txt | [tcp] | `-q -z conv,tcp` | regex解析+分桶 |
| tcp_completeness | tcp-completeness.txt | [tcp] | `-2 -Y tcp -T fields -e tcp.completeness.str ...` | 标志解码+分类 |
| udp_conversations | udp-conversations.txt | [udp] | `-q -z conv,udp` | 无 |
| dns_stats | dns-stats.txt | [dns] | `-q -z dns,tree` | 无 |
| dns_qr_stats | dns-query-response.txt | [dns] | `-q -z dns_qr,tree` | 无 |
| tls_alert | tls-alert-message.txt | [tls,ssl] | `-Y "tls.alert_message && tcp" -T fields ...` | defaultdict聚合 |
| http_stats | http-stats.txt | [http] | `-q -z http,tree` | 无 |
| http_response | http-response-code.txt | [http] | `-Y "http.response" -T fields ...` | defaultdict聚合 |
| ftp_stats | ftp-response-code.txt | [ftp] | `-Y "ftp.response.code" -T fields ...` | defaultdict聚合 |
| icmp_stats | icmp-messages.txt | [icmp] | `-Y icmp -T fields -e icmp.type -e icmp.code ...` | 类型/代码映射 |

### 6.2 配置文件格式 (config/default_commands.yaml)

```yaml
modules:
  - name: protocol_hierarchy
    description: "协议层次统计"
    output_suffix: "protocol-hierarchy.txt"
    protocols: []
    tshark_args: ["-q", "-z", "io,phs"]
  
  - name: tcp_conversations
    description: "TCP 会话统计"
    output_suffix: "tcp-conversations.txt"
    protocols: ["tcp"]
    tshark_args: ["-q", "-z", "conv,tcp"]
```

---

## 7. Match 插件规范

### 7.1 核心数据结构

```python
@dataclass
class TcpConnection:
    """TCP 连接特征"""
    stream_id: int
    client_ip: str
    server_ip: str
    server_port: int
    syn_timestamp: float
    syn_options: str          # TCP 选项指纹
    client_isn: int           # 客户端初始序列号
    server_isn: int           # 服务器初始序列号
    payload_hash: str         # 前N字节负载哈希
    length_signature: str     # 长度签名
    is_header_only: bool      # 是否仅头部
    ipid_first: int          # 首个 IPID
```

### 7.2 匹配流程

1. **提取 TCP 字段** (extractor.py)
   - 使用 tshark 提取: frame.number, tcp.stream, ip.src, ip.dst, tcp.srcport, tcp.dstport, tcp.flags, tcp.seq, tcp.ack, tcp.options, tcp.len, ip.id
   - 输出 TSV 格式

2. **构建连接特征** (connection.py)
   - 识别 SYN 包（tcp.flags.syn==1 && tcp.flags.ack==0）
   - 提取连接特征
   - 检测 header-only（所有包 tcp.len==0）

3. **采样策略** (sampler.py)
   - 如果连接数 > 1000，启用时间分层采样
   - 保护异常连接（header-only, 特殊端口）

4. **评分算法** (scorer.py)
   - IPID 必要条件: |ipid1 - ipid2| <= 5
   - 特征评分:
     - SYN 选项匹配: 40分
     - ISN 差值 < 1000: 30分
     - 负载哈希匹配: 20分
     - 长度签名相似: 10分

5. **匹配逻辑** (matcher.py)
   - 分桶策略: auto（自动选择）/ server（按服务器IP）/ port（按端口）
   - 贪心一一匹配（每个连接最多匹配一次）

---

## 8. Filter 插件规范

### 8.1 单向连接检测算法

```python
@dataclass
class TcpStream:
    stream_id: int
    packets: List[Tuple[int, int, int]]  # [(frame_num, seq, ack), ...]
    
def identify_one_way_streams(pcap_file: Path, threshold: int = 100) -> Set[int]:
    """
    识别单向 TCP 流
    
    算法:
    1. 提取所有 TCP 包: frame.number, tcp.stream, tcp.seq, tcp.ack, tcp.len
    2. 按 stream 分组
    3. 对每个 stream:
       - 计算 ACK 增量（处理回绕）
       - 统计纯 ACK 包数量（tcp.len==0）
       - 如果纯 ACK 包数 > threshold，标记为单向流
    4. 返回单向流 ID 集合
    """
```

### 8.2 ACK 回绕处理

```python
def ack_delta(ack1: int, ack2: int) -> int:
    """计算 ACK 增量（处理 32 位无符号回绕）"""
    delta = ack2 - ack1
    if delta < 0:
        delta += 2**32
    return delta
```

---

## 9. CLI 规范

### 9.1 主命令

```bash
capmaster --help
capmaster --version
capmaster -v analyze ...    # 详细输出
capmaster -vv analyze ...   # 调试输出
```

### 9.2 子命令

```bash
# Analyze
capmaster analyze -i <file|dir> [-o <output_dir>] [-c <config.yaml>]

# Match
capmaster match -i <dir> [-o <output_file>] [--mode <auto|header>] [--bucket <auto|server|port>]

# Filter
capmaster filter -i <file> [-o <output_file>] [-t <threshold>]
```

---

## 10. 测试规范

### 10.1 测试数据

使用 `cases/` 目录下的真实数据：
- Analyze: 所有 `.pcap/.pcapng` 文件
- Match: 包含 2 个文件的目录（如 TC-001-1-20160407）
- Filter: 单个 PCAP 文件

### 10.2 测试类型

```python
# 单元测试
def test_scan_single_file(test_pcap):
    files = PcapScanner.scan([str(test_pcap)])
    assert len(files) == 1

# 集成测试
def test_analyze_full_workflow(runner, test_pcap, temp_output):
    result = runner.invoke(cli, ['analyze', '-i', str(test_pcap), '-o', str(temp_output)])
    assert result.exit_code == 0
    assert len(list(temp_output.glob('*.txt'))) > 0

# 对比测试（与原脚本输出对比）
def test_output_parity(test_pcap):
    # 运行原脚本和新工具，对比输出
    pass
```

### 10.3 覆盖率要求

- 核心组件: ≥ 80%
- 插件: ≥ 80%
- 总体: ≥ 80%

---

## 11. 验收标准

### 11.1 功能验收

- [ ] `capmaster --help` 可运行
- [ ] `capmaster analyze` 所有模块输出与原脚本一致
- [ ] `capmaster match` 匹配结果与原脚本一致
- [ ] `capmaster filter` 过滤结果与原脚本一致

### 11.2 性能验收

| 操作 | 文件大小 | 原脚本 | 目标 |
|------|---------|--------|------|
| Analyze (单文件) | 10MB | 2.5s | ≤ 2.8s |
| Match (100 连接) | 20MB | 5s | ≤ 5.5s |
| Filter (单文件) | 10MB | 3s | ≤ 3.3s |

### 11.3 质量验收

- [ ] 测试覆盖率 ≥ 80%
- [ ] mypy 类型检查 100% 通过
- [ ] ruff 代码检查 100% 通过
- [ ] black 格式化一致

---

## 12. 命令对照表

| 原脚本 | 新命令 |
|--------|--------|
| `./analyze_pcap.sh -i test.pcap` | `capmaster analyze -i test.pcap` |
| `./analyze_pcap.sh -i dir/` | `capmaster analyze -i dir/` |
| `./analyze_pcap.sh -i test.pcap -c custom.conf` | `capmaster analyze -i test.pcap -c custom.yaml` |
| `./match_tcp_conns.sh -i dir/` | `capmaster match -i dir/` |
| `./match_tcp_conns.sh -i dir/ --mode header` | `capmaster match -i dir/ --mode header` |
| `./remove_one_way_tcp.sh -i test.pcap` | `capmaster filter -i test.pcap` |
| `./remove_one_way_tcp.sh -i test.pcap -t 100` | `capmaster filter -i test.pcap -t 100` |

---

## 13. Match 功能实现说明

### 13.1 算法差异

**评分系统**:
- 原脚本: 8特征加权归一化评分 (0-1)
- 新实现: 4特征简化评分 (0-100)
  - SYN options: 40分
  - ISN (Client + Server): 30分
  - Payload hash: 20分
  - Length signature: 10分

**阈值设置**:
- 原脚本: 0.60 (60%)
- 新实现: 30分 (适应简化评分)

**关键修复**:
1. 使用绝对序列号: `-o tcp.relative_sequence_numbers:false`
2. 禁用TCP重组: `-o tcp.desegment_tcp_streams:false`

**Match插件优化 (2024-11-02)**:
- ✅ 完整实现8特征加权评分系统
- ✅ IPID作为必要条件（不匹配则拒绝）
- ✅ 支持无SYN包的连接（使用首包方向）
- ✅ 修复IPID=0被错误拒绝的bug
- ✅ TCP timestamp完整实现
- ✅ Payload hash (MD5) 完整实现
- ✅ 长度签名Jaccard相似度算法

**测试结果**:
- TC-001-1-20160407: 63对匹配 ✅ (与原脚本完全一致)
- TC-002-5-20220215-O: 4对匹配 ✅ (比原脚本多1个)
- TC-034-3-20210604-O: 469对匹配 ✅ (不采样，比原脚本多194个，+70.5%)
- 详细对比: 参见 `MATCH_COMPARISON_REPORT.md`

---

## 14. Phase 5.2 用户体验增强 (2024-11-02)

### 14.1 进度条支持

**实现方式:**
- 使用 `rich.progress` 库
- 所有插件支持进度显示
- 嵌套进度任务（总体进度 + 详细进度）

**Analyze 插件:**
```python
with Progress(...) as progress:
    overall_task = progress.add_task("Analyzing N file(s)...", total=N)
    for file in files:
        # 每个文件显示模块执行进度
        module_task = progress.add_task("Running module...", total=M)
```

**Match 插件:**
- 扫描阶段、提取阶段、采样阶段、匹配阶段、输出阶段

**Filter 插件:**
- 文件进度、检测阶段、过滤阶段

### 14.2 错误处理系统

**自定义异常类 (capmaster/utils/errors.py):**
```python
class CapMasterError(Exception):
    """Base exception with message and suggestion"""
    def __init__(self, message: str, suggestion: Optional[str] = None)
    def display(self) -> None  # Rich formatted output

# Specific exceptions:
- FileNotFoundError
- InvalidFileError
- NoPcapFilesError
- InsufficientFilesError
- TsharkNotFoundError
- TsharkExecutionError
- OutputDirectoryError
- NoProtocolsDetectedError
- ConfigurationError
```

**错误处理函数:**
```python
def handle_error(error: Exception, verbose: bool = False) -> int:
    """Unified error handling with rich output"""
```

### 14.3 完善的 --help 输出

**主命令:**
- 所有子命令概览
- 使用示例
- 详细说明

**子命令:**
- 详细功能说明
- 多个使用示例
- 参数说明
- 输出说明

**示例:**
```bash
capmaster analyze --help
# 显示:
# - 功能描述
# - 5个使用示例
# - 并发处理说明
# - 输出说明
```

### 14.4 并发处理支持

**参数:**
- `--workers` / `-w`: 工作进程数量
- 默认值: 1 (单路处理)
- 推荐值: CPU核心数

**实现方式:**
```python
from concurrent.futures import ProcessPoolExecutor, as_completed

if workers > 1 and len(files) > 1:
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(process_file, f): f for f in files}
        for future in as_completed(futures):
            result = future.result()
```

**支持的插件:**
- Analyze: 并发处理多个PCAP文件
- Filter: 并发过滤多个PCAP文件
- Match: 不支持（需要成对处理）

**使用示例:**
```bash
# 使用4个工作进程并发分析
capmaster analyze -i captures/ -w 4

# 使用8个工作进程并发过滤
capmaster filter -i captures/ -w 8
```

---

## 15. 递归目录扫描行为 (2024-11-02)

### 15.1 原脚本行为对照

| 脚本 | find 命令 | 递归行为 |
|------|----------|---------|
| analyze_pcap.sh | `find "$dir"` | ✅ 默认递归 |
| remove_one_way_tcp.sh | `find "$dir"` | ✅ 默认递归 |
| match_tcp_conns.sh | `find "$dir" -maxdepth 1` | ❌ 不递归 |

### 15.2 新实现行为

**Analyze 插件:**

- 默认递归扫描（`recursive=True`）
- 使用 `-r/--no-recursive` 禁用递归
- 示例：`capmaster analyze -i cases/` 扫描所有子目录

**Filter 插件:**

- 默认递归扫描（`recursive=True`）
- 使用 `-r/--no-recursive` 禁用递归
- 使用统一的 `PcapScanner` 组件
- 示例：`capmaster filter -i cases/` 扫描所有子目录

**Match 插件:**

- 不递归扫描（`recursive=False`）
- 与原脚本行为一致
- 示例：`capmaster match -i cases/TC-001/` 只扫描顶层目录

### 15.3 实现细节

**PcapScanner.scan() 方法:**

```python
@classmethod
def scan(cls, paths: list[str], recursive: bool = False) -> list[Path]:
    """
    Scan and return all valid PCAP files from the given paths.

    Args:
        paths: List of file or directory paths to scan
        recursive: If True, scan directories recursively
    """
```

**插件调用:**

```python
# Analyze 和 Filter: 默认递归
pcap_files = PcapScanner.scan([str(input_path)], recursive=True)

# Match: 不递归
pcap_files = PcapScanner.scan([str(input_path)], recursive=False)
```

---

**AI Agent 执行要点:**

1. 严格按照目录结构创建文件
2. 所有类必须实现指定的抽象方法
3. 每个组件完成后立即编写测试
4. 使用 `cases/` 目录数据进行验证
5. 确保类型提示完整（mypy 检查）
6. Phase 5.2 用户体验增强已全部完成
7. 递归目录扫描行为与原脚本完全一致
