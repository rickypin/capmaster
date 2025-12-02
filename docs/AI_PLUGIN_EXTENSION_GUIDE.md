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
    "capmaster.plugins.compare",
    "capmaster.plugins.preprocess",
    "capmaster.plugins.topology",
    "capmaster.plugins.streamdiff",
    "capmaster.plugins.pipeline",
    "capmaster.plugins.your_plugin",  # 新增插件
]
```

### 1.4 参考现有插件

- **简单**: `streamdiff/plugin.py` - 单连接对比
- **中等**: `compare/plugin.py` - 双文件比较逻辑
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
    return ["-Y", "tcp.port == 80", "-T", "fields", "-e", "field1", "-e", "field2"]
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

## 4. 并发与批处理中的错误处理（AI 重点）

本节专门约束 AI Agent 在实现 / 修改支持「多文件处理」或「并发处理」的插件（例如 `analyze`, `preprocess`）时的行为，避免出现“跑完但没算对”的静默失败。

### 4.1 必须遵守的原则

- **不要在 worker 中吞掉所有异常然后返回“看起来像成功”的结果**
  - 例如：在 `ProcessPoolExecutor` 的子进程 worker 里 `except Exception: ... return (pcap_file, 0)` 是禁止的。
- worker 级别的异常必须：
  - 要么直接抛出，让主进程在 `future.result()` 处感知到；
  - 要么显式封装成“失败”的返回值，并且主进程必须据此统计失败数量。
- 顶层 `execute()` 在并发 / 批处理场景中必须：
  - 统计 **成功文件数** 与 **失败文件数**；
  - 对任意失败文件返回 **非 0 exit code**（推荐 `1`）；
  - 在日志中清晰区分：
    - 「0 个输出，因为没有匹配结果」vs
    - 「0 个输出，因为所有文件都处理失败」。

### 4.2 推荐实现模式（示意）

```python
# worker: 不吞异常
def _process_single_file(pcap_file: Path, ...) -> tuple[Path, int]:
    ...
    return (pcap_file, num_outputs)

# execute: 并发聚合时统计失败
failed_files = 0
total_outputs = 0

with ProcessPoolExecutor(max_workers=workers) as executor:
    ...
    for future in as_completed(futures):
        pcap_file = futures[future]
        try:
            _, num_outputs = future.result()
            total_outputs += num_outputs
        except Exception as e:
            failed_files += 1
            logger.error(f"Failed to process {pcap_file.name}: {e}")

if failed_files > 0:
    logger.error(
        f"Completed with errors: {failed_files} of {len(pcap_files)} file(s) failed"
    )
    return 1

return 0
```

> 提示：新增或修改并发逻辑时，AI Agent 应同时补充至少 1 条测试，用来断言「有 worker 失败时 `execute()` 返回非 0」。


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

### 5.4 CLI 统一输入控制约束（AI 重点）

> 适用于所有需要 PCAP 输入的插件命令，例如 `match`、`compare`、`analyze` 等。

1. **必须使用统一装饰器 `unified_input_options`**
   - 所有插件命令必须使用 `capmaster.utils.cli_options.unified_input_options` 来声明输入参数：
     - `-i/--input`: 支持目录、文件或逗号分隔的文件列表。
     - `--file1` 至 `--file6`: 支持显式指定最多 6 个文件。
      - `--allow-no-input`: 支持在文件数量不满足要求时静默退出（返回码 0，原 --silent-exit）。
   - **禁止**在各个命令中手写上述选项，避免与全局规则不一致。

2. **必须使用 `InputManager` 进行解析**
   - 在命令执行逻辑中，必须调用 `capmaster.core.input_manager.InputManager.resolve_inputs` 来解析输入参数。
   - 解析后，必须调用 `InputManager.validate_file_count` 来验证文件数量是否符合当前插件的要求。
   - `InputManager` 会自动处理：
     - 输入源的互斥检查（`-i` vs `--fileX`）。
     - 文件的存在性检查和扩展名验证。
     - 自动分配 `pcapid` (0-5) 和 `capture_point` (A-F)。

3. **单一真相源**
   - 输入参数的定义在 `capmaster/utils/cli_options.py`。
   - 输入解析和验证逻辑在 `capmaster/core/input_manager.py`。
   - 如需修改输入规则（如最大文件数、支持的扩展名等），**必须只在上述位置修改**。

4. **新增命令的推荐模式**
   ```python
   @cli_group.command()
   @unified_input_options
   @click.pass_context
     def my_command(ctx, input_path, file1, file2, file3, file4, file5, file6, allow_no_input, ...):
       # 1. 解析输入
       file_args = {1: file1, 2: file2, 3: file3, 4: file4, 5: file5, 6: file6}
       input_files = InputManager.resolve_inputs(input_path, file_args)
       
       # 2. 验证数量 (例如需要至少 1 个文件)
       InputManager.validate_file_count(input_files, min_files=1, allow_no_input=allow_no_input)
       
       # 3. 业务逻辑
       for input_file in input_files:
           process(input_file.path)
   ```

5. **CLI 负向测试要求**
   - 对任意使用 `unified_input_options` 的命令，如有新增或修改逻辑，推荐增加以下场景的 CLI 级负向测试：
     - 未提供任何输入；
     - 同时提供 `-i/--input` 与 `--fileX`；
     - 提供超过限制数量的文件（如通过 `-i` 列表）。


### 5.5 ServerDetector：服务端判定的单一真相源（AI 重点）

> **目标**：在项目中统一“谁是服务端”的判定逻辑，避免在各插件 / 模块中各自实现一套端口 / SYN / cardinality 规则。

- **必须使用 `ServerDetector` 判定服务端**
  - 所有需要回答“这条连接 / 会话的服务端是谁？”的问题，必须通过
    `capmaster.plugins.match.server_detector.ServerDetector` 的 `detect()` 方法获取结果。
  - 典型场景包括（但不限于）：
    - 连接匹配（`match` 插件）中的 server/client 角色校正；
    - 拓扑分析（`topology` 插件，单点 / 双点）中的 server/client 角色与 hops 计算；
    - 任意新插件或分析模块中，需要基于 IP/端口判断“哪一侧是服务端”的场景。

- **禁止在局部重写 server 判定规则**
  - 禁止在单个插件 / 模块中根据端口号、SYN 方向、cardinality 等重新实现一套
    “本地 server 判定逻辑”。
  - 如需增加 / 调整启发式（例如：特殊端口、额外字段、service list 语义变化），
    应只在 `ServerDetector` 内修改，使其成为**服务端判定的单一真相源**。

- **保持与抓包拓扑解耦**
  - `ServerDetector` 只面向 TCP 连接本身（`TcpConnection` 及其 IP/端口），
    不感知“单点 / 双点 / 抓包点 A/B / file1/file2”等拓扑概念。
  - 如需引入“抓包点 A 在 client 侧、B 在 server 侧”等语义，应在上层插件 / 模块
    中基于 `ServerDetector.detect()` 的结果进行推导，而不是将这些语义塞进
    `ServerDetector` 内部。

- **推荐调用模式（示意）**

  ```python
  from capmaster.plugins.match.server_detector import ServerDetector

  detector = ServerDetector(service_list_path=service_list)
  for conn in connections:
      detector.collect_connection(conn)
  detector.finalize_cardinality()

  for conn in connections:
      info = detector.detect(conn)
      # 使用 info.server_ip/info.server_port/info.client_ip/info.client_port
      # 作为后续统计、拓扑或匹配逻辑中的“语义 server/client” 角色
  ```

- **衍生信息也应基于 ServerDetector 结果**
  - 若需要计算“server 一侧的 TTL/hops”或“client 一侧的 TTL/hops”，
    应先依据 `ServerDetector.detect()` 得到 server/client 角色，再将原始
    `TcpConnection.client_ttl/server_ttl` 映射到对应一侧，避免与 service list
    或其他启发式产生冲突。

### 5.6 TTL hops 模块：基于 TTL 的跳数计算单一真相源（AI 重点）

> 与 5.5 中的 `ServerDetector` 一样，`ttl_utils` 属于“单一真相源类”核心模块。
> 当前该类模块包括：
> - `ServerDetector`：统一 server/client 角色判定
> - `ttl_utils`：统一 TTL → hops 及“是否存在中间网络设备”的判定

- **必须使用 `ttl_utils` 计算 hops 与中间设备**
  - 所有需要根据 IP TTL 推导“从抓包点到 client/server 的 hops 数”或“是否存在中间网络设备”的逻辑，必须通过
    `capmaster.plugins.match.ttl_utils` 中的公共 API（如 `calculate_hops`, `most_common_hops`）实现。
  - 典型场景包括（但不限于）：
    - 端点统计（`EndpointStatsCollector`）中计算 `client_hops_*` / `server_hops_*`；
    - 单/双采集拓扑（`topology` 插件）中基于 hops 决定路径顺序、标记 `[Network Device]`；
    - 任何新插件或分析模块中，需要基于 TTL 表达“距离”或“是否经过中间设备”的场景。

- **禁止在局部重写 TTL→hops 公式**
  - 禁止在单个插件 / 模块中直接假设初始 TTL（如 64/128/255）并手写 `hops = 初始_TTL - ttl` 之类逻辑。
  - 禁止绕开 `ttl_utils` 自行对 TTL 列表做 hops 聚合（如本地实现众数统计）。
  - 如需调整初始 TTL 假设或 hops 计算规则，只能在 `ttl_utils.TtlDelta` / `calculate_hops` / `most_common_hops` 内修改，使其成为**TTL→hops 的单一真相源**。

- **推荐调用模式（示意）**

  ```python
  from capmaster.plugins.match.ttl_utils import most_common_hops

  client_hops = most_common_hops(client_ttls)
  server_hops = most_common_hops(server_ttls)
  ```

---

## 6. 测试要求（简化）

- 新顶层插件：至少编写 1–2 个单元测试，覆盖 `execute` 的成功和失败路径。
- 新 Analyze 模块：至少测试 `build_tshark_args` 和必要的 `post_process` 行为。
- 推荐参考：
  - `tests/test_plugins/test_streamdiff/`
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
- [ ] **并发/批处理场景：不得静默吞掉 worker 异常，必须统计失败数并在有失败时返回非 0 exit code**
- [ ] **如需判断 server/client 角色：统一使用 `ServerDetector.detect()`，不得手写本地启发式**
- [ ] **如需基于 TTL 推导 hops/中间网络设备：统一使用 `capmaster.plugins.match.ttl_utils`（如 `calculate_hops` / `most_common_hops`），不得手写初始 TTL 判断或 hops 公式**
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

