# AI Agent 插件扩展快速指南

> **精简版** - 专为 AI Agent 优化，去除冗余，聚焦核心步骤

---

## 1. 添加新的顶层插件

### 1.1 核心步骤

```
1. 创建目录: capmaster/plugins/your_plugin/
2. 实现插件类: 继承 PluginBase
3. 注册插件: 使用 @register_plugin 装饰器
4. 添加导入: 在 discover_plugins() 中导入
```

### 1.2 必需实现的方法

```python
from capmaster.plugins.base import PluginBase
from capmaster.plugins import register_plugin

@register_plugin
class YourPlugin(PluginBase):
    @property
    def name(self) -> str:
        return "command_name"  # CLI 子命令名
    
    def setup_cli(self, cli_group: click.Group) -> None:
        @cli_group.command(name=self.name)
        @click.option("-i", "--input", required=True)
        @click.pass_context
        def command(ctx, input):
            exit_code = self.execute(input=input)
            ctx.exit(exit_code)
    
    def execute(self, **kwargs) -> int:
        # 实现业务逻辑
        return 0  # 0=成功, 非0=失败
```

### 1.3 注册插件

在 `capmaster/plugins/__init__.py` 的 `discover_plugins()` 中添加：

```python
try:
    import capmaster.plugins.your_plugin  # noqa: F401
except ImportError:
    pass
```

### 1.4 参考现有插件

- **简单**: `clean/plugin.py` - 单一功能
- **中等**: `filter/plugin.py` - 包含检测器
- **复杂**: `analyze/plugin.py` - 包含子模块系统

---

## 2. 添加新的 Analyze 模块

### 2.1 核心步骤

```
1. 创建文件: capmaster/plugins/analyze/modules/your_module.py
2. 实现模块类: 继承 AnalysisModule
3. 注册模块: 使用 @register_module 装饰器
4. 添加导入: 在 discover_modules() 中导入
```

### 2.2 必需实现的方法

```python
from pathlib import Path
from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule

@register_module
class YourModule(AnalysisModule):
    @property
    def name(self) -> str:
        return "module_name"
    
    @property
    def output_suffix(self) -> str:
        return "output-file.txt"
    
    @property
    def required_protocols(self) -> set[str]:
        return {"protocol"}  # 或 set() 表示总是执行
    
    def build_tshark_args(self, input_file: Path) -> list[str]:
        # 返回 tshark 命令参数
        return ["-q", "-z", "command"]
    
    def post_process(self, tshark_output: str) -> str:
        # 可选: 后处理 tshark 输出
        return tshark_output
```

### 2.3 注册模块

在 `capmaster/plugins/analyze/modules/__init__.py` 的 `discover_modules()` 中添加：

```python
try:
    from capmaster.plugins.analyze.modules import your_module  # noqa: F401
except ImportError:
    pass
```

### 2.4 三种模块类型

**类型 1: 简单统计** (无后处理)
```python
def build_tshark_args(self, input_file: Path) -> list[str]:
    return ["-q", "-z", "protocol,tree"]
```
参考: `protocol_hierarchy.py`, `dns_stats.py`

**类型 2: 字段提取** (带后处理)
```python
def build_tshark_args(self, input_file: Path) -> list[str]:
    return ["-Y", "filter", "-T", "fields", "-e", "field1", "-e", "field2"]

def post_process(self, tshark_output: str) -> str:
    from collections import Counter
    counter = Counter(tshark_output.strip().split('\n'))
    return '\n'.join(f"{count}\t{item}" for item, count in counter.most_common())
```
参考: `tcp_zero_window.py`

**类型 3: 复杂处理** (分组/聚合)
```python
def post_process(self, tshark_output: str) -> str:
    from collections import defaultdict
    groups = defaultdict(list)
    for line in tshark_output.strip().split('\n'):
        key, value = line.split('\t')
        groups[key].append(value)
    return '\n'.join(f"{k}: {','.join(v)}" for k, v in groups.items())
```
参考: `http_response.py`

---

## 3. 常用 tshark 命令模式

### 3.1 统计命令 (-z 选项)

```python
# 协议统计
["-q", "-z", "io,phs"]           # 协议层次
["-q", "-z", "conv,tcp"]         # TCP 会话
["-q", "-z", "dns,tree"]         # DNS 统计
["-q", "-z", "http,tree"]        # HTTP 统计
["-q", "-z", "endpoints,ip"]     # IP 端点
```

### 3.2 字段提取 (-T fields)

```python
# 基本模式
["-Y", "filter_expression",      # 显示过滤器
 "-T", "fields",                  # 字段输出
 "-e", "field1",                  # 字段 1
 "-e", "field2",                  # 字段 2
 "-E", "separator=\t"]            # 分隔符
```

### 3.3 常用字段

```python
# 基础字段
"frame.number"        # 帧号
"frame.time_epoch"    # 时间戳
"ip.src", "ip.dst"    # IP 地址
"tcp.srcport", "tcp.dstport"  # TCP 端口
"tcp.stream"          # TCP 流 ID
"tcp.seq", "tcp.ack"  # 序列号
"tcp.len"             # TCP 负载长度

# 协议特定字段
"http.response.code"  # HTTP 响应码
"dns.qry.name"        # DNS 查询名
"tls.handshake.type"  # TLS 握手类型
```

---

## 4. 后处理技术速查

### 4.1 计数和排序

```python
from collections import Counter

counter = Counter(lines)
sorted_items = sorted(counter.items(), key=lambda x: -x[1])  # 按频率降序
```

### 4.2 分组聚合

```python
from collections import defaultdict

groups = defaultdict(list)
for line in lines:
    key, value = line.split('\t')
    groups[key].append(value)
```

### 4.3 正则解析

```python
import re

pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+):(\d+)')
for line in lines:
    match = pattern.search(line)
    if match:
        ip, port = match.groups()
```

### 4.4 数值分桶

```python
buckets = {"<1s": 0, "1-10s": 0, ">10s": 0}
for value in values:
    if value < 1:
        buckets["<1s"] += 1
    elif value < 10:
        buckets["1-10s"] += 1
    else:
        buckets[">10s"] += 1
```

---

## 5. 核心组件使用

### 5.1 可用组件

```python
from capmaster.core.file_scanner import PcapScanner
from capmaster.core.tshark_wrapper import TsharkWrapper
from capmaster.core.protocol_detector import ProtocolDetector
from capmaster.core.output_manager import OutputManager
from capmaster.utils.errors import handle_error, NoPcapFilesError
from capmaster.utils.logger import get_logger
```

### 5.2 常用模式

```python
# 扫描 PCAP 文件
pcap_files = PcapScanner.scan([str(input_path)], recursive=True)

# 执行 tshark
tshark = TsharkWrapper()
result = tshark.execute(args, input_file=pcap_file)

# 检测协议
detector = ProtocolDetector(tshark)
protocols = detector.detect(pcap_file)

# 创建输出目录
output_dir = OutputManager.create_output_dir(pcap_file)

# 错误处理
try:
    # 业务逻辑
    pass
except Exception as e:
    return handle_error(e, verbose=verbose)
```

### 5.3 ⚠️ 重要约束：必须使用 TsharkWrapper

**禁止直接使用 subprocess.run 调用 tshark！**

❌ **错误示例**:
```python
import subprocess

# 不要这样做！
cmd = ["tshark", "-r", str(pcap_file), "-T", "fields", ...]
result = subprocess.run(cmd, capture_output=True, text=True)
```

✅ **正确示例**:
```python
from capmaster.core.tshark_wrapper import TsharkWrapper

# 使用 TsharkWrapper
tshark = TsharkWrapper()
args = ["-T", "fields", "-e", "tcp.stream", ...]
result = tshark.execute(args=args, input_file=pcap_file)
```

**原因**:
1. **统一错误处理**: TsharkWrapper 自动处理 exit code 2（警告）
2. **版本检查**: 自动验证 tshark 版本要求
3. **路径管理**: 自动查找 tshark 可执行文件
4. **日志记录**: 统一的日志输出
5. **代码一致性**: 与项目其他部分保持一致
6. **易于测试**: 可以 mock TsharkWrapper 进行单元测试

**TsharkWrapper 支持的用法**:

```python
# 文本输出（捕获 stdout）
result = tshark.execute(
    args=["-q", "-z", "io,phs"],
    input_file=pcap_file
)
output = result.stdout

# 文本输出（重定向到文件）
result = tshark.execute(
    args=["-q", "-z", "conv,tcp"],
    input_file=pcap_file,
    output_file=output_txt_file
)

# PCAP 输出（使用 -w 参数）
result = tshark.execute(
    args=["-Y", "tcp.port == 80", "-w", str(output_pcap_file)],
    input_file=pcap_file
)

# 超时控制
result = tshark.execute(
    args=["-q", "-z", "http,tree"],
    input_file=pcap_file,
    timeout=300  # 5 分钟超时
)
```

---

## 6. 测试模板

### 6.1 单元测试

```python
def test_module_name():
    module = YourModule()
    assert module.name == "expected_name"

def test_module_protocols():
    module = YourModule()
    assert module.required_protocols == {"protocol"}

def test_should_execute():
    module = YourModule()
    assert module.should_execute({"protocol"}) is True
    assert module.should_execute({"other"}) is False

def test_build_tshark_args(test_pcap):
    module = YourModule()
    args = module.build_tshark_args(test_pcap)
    assert isinstance(args, list)
    assert len(args) > 0
```

### 6.2 集成测试

```python
def test_plugin_integration(test_pcap, tmp_path):
    plugin = YourPlugin()
    exit_code = plugin.execute(
        input_path=test_pcap,
        output_file=tmp_path / "output.txt"
    )
    assert exit_code == 0
    assert (tmp_path / "output.txt").exists()
```

---

## 7. 检查清单

### 7.1 插件开发

- [ ] 继承 `PluginBase`
- [ ] 实现 `name`, `setup_cli`, `execute`
- [ ] 使用 `@register_plugin`
- [ ] 在 `discover_plugins()` 中导入
- [ ] **使用 `TsharkWrapper` 而非 `subprocess.run`**
- [ ] 添加类型提示
- [ ] 编写测试 (覆盖率 ≥ 80%)
- [ ] 运行 `mypy` 和 `ruff`

### 7.2 模块开发

- [ ] 继承 `AnalysisModule`
- [ ] 实现 `name`, `output_suffix`, `required_protocols`, `build_tshark_args`
- [ ] 使用 `@register_module`
- [ ] 在 `discover_modules()` 中导入
- [ ] **`build_tshark_args` 返回参数列表（不包括 tshark 和 -r）**
- [ ] 添加类型提示
- [ ] 编写测试 (覆盖率 ≥ 80%)
- [ ] 运行 `mypy` 和 `ruff`

---

## 8. 快速参考

### 8.1 文件位置

```
插件基类:     capmaster/plugins/base.py
模块基类:     capmaster/plugins/analyze/modules/base.py
插件注册:     capmaster/plugins/__init__.py
模块注册:     capmaster/plugins/analyze/modules/__init__.py
```

### 8.2 命令验证

```bash
# 验证插件
python -m capmaster your_command --help

# 验证模块
python -m capmaster analyze -i test.pcap

# 运行测试
pytest tests/test_plugins/test_your_plugin/ -v

# 类型检查
mypy capmaster/plugins/your_plugin/

# 代码检查
ruff check capmaster/plugins/your_plugin/
```

---

**精简完成！** 本指南聚焦核心步骤，去除冗余示例。

