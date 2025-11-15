# AI Agent 插件扩展快速指南

> **精简版** - 专为 AI Agent 优化，去除冗余，聚焦核心步骤

---

## 0. 前言（给 AI Agent 的说明）

- 代码与注释：使用英文
- 与用户沟通：使用中文
- 单个代码文件：不超过 500 行
- 不新增第三方依赖，优先复用现有模块和标准库
- 顶层插件：继承 `PluginBase` 且使用 `@register_plugin`
- Analyze 模块：继承 `AnalysisModule` 且使用 `@register_module`
- 禁止直接 `subprocess.run("tshark", ...)`，必须使用 `TsharkWrapper`

> **Maintenance（维护约定）**：当插件体系结构、注册方式或对 AI 的约束发生变化时，优先更新本文件顶部的约定和示例，避免在多处重复描述同一规则。

## 1. 添加新的顶层插件

### 1.1 核心步骤

```
1. 创建目录: capmaster/plugins/your_plugin/
2. 实现插件类: 继承 PluginBase
3. 注册插件: 使用 @register_plugin 装饰器
4. 在 discover_plugins() 的 plugin_modules 列表中添加模块路径
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

在 `capmaster/plugins/__init__.py` 的 `discover_plugins()` 中，将你的插件模块添加到 `plugin_modules` 列表，例如：

```python
plugin_modules = [
    "capmaster.plugins.analyze",
    "capmaster.plugins.match",
    "capmaster.plugins.filter",
    "capmaster.plugins.clean",
    "capmaster.plugins.compare",
    "capmaster.plugins.your_plugin",  # 新增插件
]
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
4. 在 discover_modules() 的 module_names 列表中添加模块名
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

在 `capmaster/plugins/analyze/modules/__init__.py` 的 `discover_modules()` 中，将你的模块名添加到 `module_names` 列表，例如：

```python
module_names = [
    "protocol_hierarchy",
    "ipv4_conversations",
    # ... 其他已有模块
    "your_module",  # 新增模块
]
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
```
参考: `dns_stats.py` 等 *_stats 模块

**类型 3: 复杂处理** (分组/聚合)
```python
def post_process(self, tshark_output: str) -> str:
    ...
```
参考: `http_response.py`, `tcp_zero_window.py`

---

## 3. tshark 命令与后处理（简要说明）

- 构造 tshark 参数时，优先模仿现有模块的 `build_tshark_args` 实现。
- 常见命令模式和字段组合，请参考 `capmaster/plugins/analyze/modules/` 目录中的现有模块。
- 后处理时，可以自由使用标准库（如 `collections`, `re` 等），不再在本文中展开。

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

## 6. 测试要求（简化）

- 新顶层插件：至少编写 1–2 个单元测试，覆盖 `execute` 的成功和失败路径。
- 新 Analyze 模块：至少测试 `build_tshark_args` 和必要的 `post_process` 行为。
- 推荐参考：
  - `tests/test_plugins/test_clean/`
  - `tests/test_plugins/test_analyze/`
- 确保相关测试在本地或 CI 中通过 `pytest` 运行。

---

## 7. 检查清单

### 7.1 插件开发

- [ ] 继承 `PluginBase`
- [ ] 单个新文件行数 < 500
- [ ] 未新增第三方依赖
- [ ] 实现 `name`, `setup_cli`, `execute`
- [ ] 使用 `@register_plugin`
- [ ] 在 `discover_plugins()` 的 `plugin_modules` 列表中注册你的插件模块
- [ ] **使用 `TsharkWrapper` 而非 `subprocess.run`**
- [ ] 添加类型提示
- [ ] 编写测试 (覆盖率 ≥ 80%)
- [ ] 运行 `mypy` 和 `ruff`

### 7.2 模块开发

- [ ] 继承 `AnalysisModule`
- [ ] 单个新文件行数 < 500
- [ ] 未新增第三方依赖
- [ ] 实现 `name`, `output_suffix`, `required_protocols`, `build_tshark_args`
- [ ] 使用 `@register_module`
- [ ] 在 `discover_modules()` 的 `module_names` 列表中注册你的模块名
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

本小节主要方便人类开发者在本地验证，AI Agent 通常无需执行这些命令。

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

