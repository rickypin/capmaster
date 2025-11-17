# CapMaster Preprocess 插件 & 配置系统设计说明

## 1. 背景与目标

CapMaster 需要一个新的 **预处理插件（preprocess）**，在进行 match/compare 等分析前，对 PCAP 数据做标准化清洗。典型需求：
- 删除重复包（mirror、多点抓包导致的重复）。
- 删除无意义的单向 TCP 连接。
- 对多份 PCAP 做“时间重叠裁剪”，保证分析区间一致。
- 对“原始 PCAP”做归档备份，便于审计/回溯。
- 提供“全自动模式”，同时允许细粒度控制步骤和参数。
- CapMaster 将作为模块集成到更大项目中，需要：
  - 支持配置文件/配置对象；
  - CLI 只是配置的一种视图和覆盖方式。

本设计文档覆盖两部分：
- **Preprocess 插件设计**（功能、API、CLI、执行顺序）。
- **配置系统设计**（配置对象、YAML、环境变量、CLI 映射、优先级）。

## 2. 范围

### 2.1 当前范围
- 仅为 **preprocess 插件** 引入配置对象 + YAML + ENV + CLI 映射。
- 实现以下步骤：`dedup`（editcap）、`oneway`（迁移自 filter 插件）、`time-align`（使用 Wireshark 系列工具，如 capinfos/tshark + editcap，按性能优先级选择），以及一个可选的原始文件归档选项 `archive_original_files`（非 pipeline 步骤，在全部处理完成后执行）。
- 提供 Python API，供上层项目直接调用，无需绕 CLI。
- 在 preprocess 引入 oneway 能力后，filter 插件中对应的 oneway 功能计划弃用并删除，实现逻辑统一收敛到 preprocess。

### 2.2 不在范围
- 现有 `match/filter/analyze` 插件的配置改造。
- 全局统一配置框架（可后续演进）。

## 3. 总体设计

### 3.1 核心思想

1. **配置对象为中心**：
   - `ToolsConfig`：`tshark` / `editcap` / `capinfos` 等工具路径。
   - `PreprocessConfig`：预处理业务参数。
   - `PreprocessRuntimeConfig`：聚合前两者，作为 pipeline 唯一配置入口。
2. **多源配置，优先级明确（高→低）**：
   1. 上层代码显式传入的 `PreprocessRuntimeConfig`。
   2. CLI 参数。
   3. 环境变量（主要用于工具路径）。
   4. YAML 配置文件。
   5. 代码内置默认值（dataclass 默认）。
3. **CLI 是配置的视图与覆盖层**：
   - 所有布尔开关统一采用 `--enable-xxx / --disable-xxx` 成对形式；
   - 与配置字段 `xxx_enabled: bool` 语义一致，避免负向 flag 歧义。
4. **工具调用遵循 Wireshark 生态最佳实践**：
   - 去重、时间裁剪/对齐优先使用 `editcap`（结合 `-A/-B/-d/-D/-I` 等参数）。
   - 时间元数据（首包/末包时间、包数等）优先使用 `capinfos`，协议字段解析使用 `tshark`（通过 `TsharkWrapper`）。
   - 所有外部工具调用集中到 `pcap_tools.py` 或类似模块中。
5. **运行报告与可追溯性**：
   - 每次运行可选生成一份 Markdown 报告，汇总本次执行的步骤、关键参数以及原始/最终 PCAP 指标（详见附录 G）。

## 4. 配置对象设计

文件：`capmaster/plugins/preprocess/config.py`

### 4.1 ToolsConfig

```python
from dataclasses import dataclass
from pathlib import Path

@dataclass
class ToolsConfig:
    tshark_path: Path | None = None
    editcap_path: Path | None = None
    capinfos_path: Path | None = None
```

- `tshark_path`：
  - 若非 `None`，构造 `TsharkWrapper` 时优先使用该路径；
  - 否则按顺序：环境变量 `TSHARK_PATH` → `shutil.which("tshark")`。
- `editcap_path`：
  - 若非 `None`，所有 `editcap` 调用优先使用该路径；
  - 否则按顺序：环境变量 `EDITCAP_PATH` → `shutil.which("editcap")`。
- `capinfos_path`：
  - 若非 `None`，所有 `capinfos` 调用优先使用该路径；
  - 否则按顺序：环境变量 `CAPINFOS_PATH` → `shutil.which("capinfos")`。

### 4.2 PreprocessConfig

```python
@dataclass
class PreprocessConfig:
    # Step toggles
    dedup_enabled: bool = True
    oneway_enabled: bool = True
    time_align_enabled: bool = True
    archive_original_files: bool = False

    # Dedup params (editcap-based)
    dedup_window_packets: int | None = None  # None -> use editcap -d (默认窗口)，否则使用 -D N
    dedup_ignore_bytes: int = 0  # 映射为 editcap -I N

    # Oneway params
    oneway_ack_threshold: int = 20

    # Time align params
    time_align_allow_empty: bool = False

    # Reporting
    report_enabled: bool = True
    report_path: str | None = None

    # Performance
    workers: int = 4
```

- 步骤开关：默认启用 `dedup/oneway/time-align`，默认不归档、不压缩。
- 去重默认行为（遵循 editcap 官方语义）：
  - 未给 dedup 相关 CLI 参数时，使用 `editcap -d`（等价 `-D 5`，即对前 4 个包窗口做 MD5+长度去重）；
  - `--dedup-window-packets N` → `dedup_window_packets`，内部映射为 `editcap -D N`，适用于需要扩大/缩小重复检测窗口的场景；
    - 在单个 PCAP 尺寸可能达到 2GB 的前提下，不建议将 N 设为过大，以避免去重阶段耗时和内存占用急剧上升；
  - `dedup_ignore_bytes > 0` 时附加 `editcap -I N`，用于忽略链路层头等前缀导致的差异（例如不同抓包点的 MAC 地址不同但载荷一致的场景）。

### 4.3 PreprocessRuntimeConfig

```python
@dataclass
class PreprocessRuntimeConfig:
    tools: ToolsConfig
    preprocess: PreprocessConfig
```

pipeline 内所有步骤只依赖 `PreprocessRuntimeConfig`，不直接读取 ENV/CLI/YAML。

## 5. 配置文件与环境变量

### 5.1 YAML 结构

默认文件名建议：`capmaster_config.yaml`，或由 `CAPMASTER_CONFIG` / CLI `--config` 指定路径。

```yaml
tools:
  tshark_path: "/usr/local/bin/tshark"
  editcap_path: "/usr/local/bin/editcap"
  capinfos_path: "/usr/local/bin/capinfos"

preprocess:
  dedup_enabled: true
  oneway_enabled: true
  time_align_enabled: true
  archive_original_files: false

  dedup_window_packets: null
  dedup_ignore_bytes: 0

  oneway_ack_threshold: 20

  time_align_allow_empty: false

  report_enabled: true
  report_path: null

  workers: 4
```

### 5.2 环境变量

- 工具路径：
  - `TSHARK_PATH`：优先级高于 PATH，用于定位 `tshark`。
  - `EDITCAP_PATH`：优先级高于 PATH，用于定位 `editcap`。
  - `CAPINFOS_PATH`：优先级高于 PATH，用于定位 `capinfos`。
- 配置文件路径：
  - `CAPMASTER_CONFIG`：指定 YAML 配置文件路径。

预处理业务参数优先通过 YAML 或 CLI 控制，避免 ENV 过度膨胀。

## 6. CLI 设计（preprocess 插件）

### 6.1 子命令

- 命令名称：`capmaster preprocess`。

### 6.2 输入输出

- `-i, --input TEXT`（必选）：文件/目录/逗号分隔列表，使用 `PcapScanner` 解析。
- `-o, --output PATH`（可选）：输出目录；未指定时使用约定默认（例如 `<input>_prep` 或 `prep/` 子目录）。
- `--config PATH`（可选）：指定 YAML；否则使用 `CAPMASTER_CONFIG` 或默认文件名。

### 6.3 步骤控制：自动模式 vs 显式 steps

- `--step [STEP]`（多次）：`STEP ∈ {dedup, oneway, time-align}`。
  - 若至少指定一次 `--step`：
    - 视为“显式步骤模式”，实际执行步骤 = `--step` 列表（顺序同 CLI）；
    - 此时 `*_enabled` 不再控制步骤集合，只作默认文档。
  - 若未指定 `--step`：
    - 视为“自动模式”，实际步骤 = 所有 `*_enabled == True` 的步骤，按固定顺序执行。

### 6.4 布尔开关与配置映射

- 使用成对 flag，与配置字段直接对应：
  - `--enable-dedup` / `--disable-dedup` → `PreprocessConfig.dedup_enabled`。
  - `--enable-oneway` / `--disable-oneway` → `PreprocessConfig.oneway_enabled`。
  - `--enable-time-align` / `--disable-time-align` → `PreprocessConfig.time_align_enabled`。
- 校验规则：
  - 同一对中若同时出现 enable/disable，CLI 应报错；
  - 当 CLI 中指定了一个或多个 `--step` 时，禁止同时指定影响这些步骤的 `--enable-xxx/--disable-xxx`；如同时出现，CLI 应报错，并提示用户在“自动模式 + enable/disable”与“显式 steps 模式（--step）”之间二选一。

### 6.5 其他参数映射

- Dedup：
  - `--dedup-window-packets N` → `dedup_window_packets`
    - 未指定时使用 `editcap -d` 默认窗口；指定时内部映射为 `editcap -D N`；
  - `--dedup-ignore-bytes N` → `dedup_ignore_bytes`（内部映射为 `editcap -I N`）。
- Oneway：
  - `--oneway-ack-threshold N` → `oneway_ack_threshold`。
- Time align：
  - `--enable-time-align-allow-empty` / `--disable-time-align-allow-empty` → `time_align_allow_empty`。
- Archive：
  - `--archive-original-files` / `--no-archive-original-files` → `archive_original_files`。
- 并行度：
  - `-w, --workers N` → `workers`。
- 报告：
  - `--no-report` 将 `report_enabled` 置为 False；
  - `--report-path PATH` → `report_path`，若未指定则默认使用 `output_dir / "preprocess_report.md"`。

## 7. Pipeline 与步骤执行

### 7.1            

-           preprocess           RuntimeConfig         +        
-                    PcapScanner       PCAP          input_files       
-               output_dir      tmp_dir          

         PreprocessContext         :

```python
from dataclasses import dataclass
from pathlib import Path

@dataclass
class PreprocessContext:
    runtime: PreprocessRuntimeConfig
    input_files: list[Path]
    output_dir: Path
    tmp_dir: Path
```

       STEP_HANDLERS         :

```python
STEP_HANDLERS = {
    "archive-original": archive_step,
    "dedup": dedup_step,
    "oneway": oneway_step,
    "time-align": time_align_step,
}
```

-                   --step       steps_to_run                       ");
-                 --step           dedup      oneway      time-align      archive-original                 enabled        

### 7.2         

-         preprocess          --step          oneway      Filter         one-way detection         
-                      filter         one-way         oy          preprocess              

## 8. Time-align         

### 8.1        

-         N \u2265 2   PCAP         PcapScanner           input_files        
-         capinfos            (                   )           ;
-                 tshark         TsharkWrapper         
-                        + editcap         

         T_start          ...

## 附录：Preprocess 设计补充（Pipeline / Time-align / Archive / 性能 / 命名）

> 说明：由于上文第 7、8 小节在早期编辑时出现过编码损坏，以下附录视为 **当前版本的规范说明**，优先级高于前文对应小节。

### A. Pipeline 与步骤执行

- CLI 层负责解析 `PreprocessRuntimeConfig`、输入 PCAP 列表、输出目录等；
- Pipeline 内部通过一个 `PreprocessContext` 在各步骤之间传递状态（当前文件列表、输出目录、临时目录等）；
- 各步骤通过一个简单的字典 `STEP_HANDLERS` 注册和调度。

```python
from dataclasses import dataclass
from pathlib import Path

@dataclass
class PreprocessContext:
    runtime: PreprocessRuntimeConfig
    input_files: list[Path]
    output_dir: Path
    tmp_dir: Path
```

```python
STEP_HANDLERS = {
    "dedup": dedup_step,
    "oneway": oneway_step,
    "time-align": time_align_step,
}
```

- 显式步骤模式：若 CLI 指定了一个或多个 `--step`，则 `steps_to_run` = CLI 中出现的步骤（按出现顺序）；
- 自动模式：未指定 `--step` 时，按固定顺序 `["time-align", "dedup", "oneway"]` 过滤出对应 `*_enabled == True` 的步骤作为 `steps_to_run`，以保证：
  - time-align 尽早裁剪到重叠时间区间，减少后续步骤的数据量；
  - dedup 和 oneway 只在对齐后的时间窗口上进行，降低 2GB 级文件上的 CPU 与 I/O 开销。

### B. Filter oneway 功能迁移

- preprocess 中的 `oneway` 步骤复用（或抽取自）现有 Filter 插件中的 one-way detection 实现；
- 在 preprocess 的 oneway 功能稳定后，Filter 插件中的 oneway 相关 CLI/实现将标记为弃用，并在后续版本中移除，以避免重复维护。

### C. Time-align 行为与工具选择

- 输入文件：通过 `PcapScanner` 扫描得到的 `input_files`，要求数量 `N ≥ 2`；
- 对每个 PCAP，获取起止时间：
  - 首选使用 `capinfos`（Wireshark 工具链的一部分）从元数据中读取首包/末包时间，避免解析全部数据包；
  - 如环境中缺少 `capinfos`，可回退为 `tshark` + `TsharkWrapper` 获取首包/末包时间；
- 计算全局重叠时间区间：
  - `T_start = max(first_ts_i)`；
  - `T_end = min(last_ts_i)`。

- 若 `T_start < T_end`：
  - 使用 `editcap -A T_start -B T_end` 对每个输入 PCAP 生成裁剪后的新文件；
  - 替换 `PreprocessContext.input_files` 中对应的路径。
- 若 `T_start >= T_end`：
  - 当 `time_align_allow_empty == False`：
    - 记录错误日志并返回非 0 退出码，不生成裁剪结果；
  - 当 `time_align_allow_empty == True`：
    - 为每个输入生成空 PCAP 文件（例如使用 `editcap` 生成仅包含全局头的空文件），并替换 `PreprocessContext.input_files` 中对应的路径；
    - 在日志中输出明确的 warning，说明“无重叠区间，已按配置生成空 PCAP 输出”。

### D. Archive-original-files 行为（简化后）

- 当 `archive_original_files == True` 时：
  - 在所有预处理步骤（包括报告生成）全部成功完成后，收集 **作为输入传入的原始 PCAP 文件**（即来自 `--input`，且文件名本身不包含 `.ready.` / `.prep.` / `.preprocessed.` / `.preprocess.` 这类已处理标记的文件）；
  - 将这些原始 PCAP 一次性打包为 `archive.tar.gz`（位于输出目录根部，使用 `tar.gz` 压缩格式）；
  - 打包成功后，删除这些原始 PCAP 文件，效果类似于：`tar -czf archive.tar.gz a b --remove-files`；
  - 该归档逻辑只关心“是不是输入的原始文件”，**不再根据“是否有实质变化”做任何筛选**。
- 当 `archive_original_files == False` 时：
  - 不执行任何归档/删除原始文件的操作。

- 设计要点：
  - 归档操作与实际预处理步骤、报告生成解耦，**总是在它们之后执行**，避免中间步骤访问不到原始输入；
  - 整个运行中不再创建 `archive/` 子目录，也不再存在“先拷贝原始再压缩目录”的双阶段逻辑，只有最终的 `archive.tar.gz`；
  - 归档与否完全由 `archive_original_files` 决定。

### E. 性能策略与并行

- `workers` 控制外部工具调用的并发度，默认 4；
- 并发粒度：
  - 以“单个 PCAP 文件”为单位做 dedup/oneway/time-align 等操作，对不同文件进行并行处理；
  - time-align 获取起止时间阶段也可以对各文件并行调用 `capinfos`/`tshark`。
- 资源控制：
  - 同一时刻并行的 tshark/editcap/capinfos 进程数不超过 `workers`，避免把 CPU 和磁盘打满；
  - 中间结果写入 `tmp_dir`（例如 `output_dir / ".tmp_preprocess"`），所有步骤成功后再迁移/重命名为最终输出文件。
- editcap 调用优化（可选实现细节）：
  - 当同时启用了 time-align 与 dedup 时，实现层可以将 `editcap -A/-B` 与 `-d/-D/-I` 合并为一次调用，在单次顺序遍历中同时完成裁剪与去重，以减少对 2GB 级 PCAP 的重复扫描；
  - 此优化不改变对外语义，仅作为性能提升手段，是否启用由具体实现决定。

### G. 运行报告（Markdown）

- 目的：为单次 `preprocess` 运行生成一份精简的 Markdown 文档，用于后续审计与问题追溯。
- 输出控制：
  - `PreprocessConfig.report_enabled`：
    - `True`（默认）：在本次运行完成后生成报告；
    - `False`：跳过报告生成。
  - `PreprocessConfig.report_path`：
    - 若为 `None`，默认写入 `output_dir / "preprocess_report.md"`；
    - 若为非空字符串，则视为绝对或相对路径，直接写入该路径。
- 报告作用域：
  - 以“单次运行”为粒度，一份报告覆盖本次运行中所有输入/输出 PCAP 文件；
  - 不为每个文件单独生成一份独立报告，避免产物过多。
- 报告建议结构：
  - **Run 概览**：
    - 运行时间（UTC 与本地时间）、CapMaster 版本、preprocess 插件版本；
    - 调用入口（CLI 命令行或上层 API 摘要）、配置来源（YAML 路径等）。
  - **步骤摘要**：
    - 实际执行的步骤列表（按 pipeline 顺序，例如 `time-align → dedup → oneway`）；
    - 各步骤关键参数（如 `dedup_window_packets`、`dedup_ignore_bytes`、`time_align_allow_empty`、`oneway_ack_threshold` 等）。
  - **文件级对比（原始 vs 最终）**：
    - 对每个输入 PCAP，记录至少以下信息：
      - 原始与最终输出的 `path`；
      - `packet_count`（可由 `capinfos -c` 获取）；
      - `file_size_bytes`（文件大小）；
      - `first_ts` / `last_ts`（可由 `capinfos` 获取）。
    - 建议使用 Markdown 表格展示原始与最终的对比，便于人工快速浏览。
  - **步骤效果汇总（可选）**：
    - time-align：总体裁剪情况（例如与原始时间范围相比，重叠区间的长度比例）；
    - dedup：总去重前/后包数及去重率；
    - oneway：总连接数与移除的 one-way 连接数（若实现层提供统计数据）。

实现层可以在不改变对外语义的前提下，按上述建议结构组织 Markdown 内容；如需扩展额外字段，应保持向后兼容，不影响既有的追溯能力。


### F. 输出文件命名与目录结构

- 对于输入文件 `<name>.pcap` 或 `<name>.pcapng`：
  - 最终预处理后的输出命名为 `<name>.ready.pcap` 或 `<name>.ready.pcapng`；
- 为避免过度复杂：
  - 中间步骤（如 dedup/oneway/time-align 分步输出）统一使用临时文件名并放在 `tmp_dir` 中，不对外暴露；
  - 用户可见的最终结果仅保留一份“预处理完成”的 PCAP 文件，以及最终的 `archive.tar.gz`（若启用原始文件归档）。

### H. 实现路线与测试约定（基于测试骨架）

本设计文档配套了一套基于真实故障案例的测试骨架，用于驱动 preprocess 插件的实现与回归测试。

#### H.1 测试数据布局

- 目录：`tests/preprocess_cases/`
  - 由真实故障排查案例复制而来，仅包含 `.pcap/.pcapng` 文件，用于测试，不纳入版本控制（已在 `.gitignore` 中忽略）：
    - `tests/preprocess_cases/TC-060-2-20210730/`
    - `tests/preprocess_cases/TC-035-06-20240704/`
    - `tests/preprocess_cases/TC-044-2-20230920/`
    - `tests/preprocess_cases/TC-063-1-20230306/`
    - `tests/preprocess_cases/TC-014-1-20231212/`
    - `tests/preprocess_cases/TC-047-7-20240328/`
    - `tests/preprocess_cases/TC-028-1-20240308/`
  - 各案例的典型用途：
    - `TC-060-2-20210730`：F5 前/后多份抓包，含明显重复报文及 `*-dedup.pcap`，用于验证 dedup 语义与大文件性能；
    - `TC-035-06-20240704`：视频卡顿场景，包含多条单向 TCP 连接，用于验证 oneway 步骤；
    - `TC-044-2-20230920`：多采集点 + 过滤版 + 异常 flow 小文件，用于验证 time-align + dedup 在多 tap 场景下的行为；
    - `TC-063-1-20230306`：邮件业务多节点链路，用于验证 time-align 在复杂路径上的表现；
    - `TC-014-1-20231212`：防火墙内/外/对端 + 截断 PCAP，用于验证异常/错误处理与报告记录；
    - `TC-047-7-20240328`：人行 / 前置网关 / 微服务 / MQ 等多节点服务链，用于 end-to-end 对齐与分析；
    - `TC-028-1-20240308`：单一小 PCAP，用作快速 baseline 场景，验证“全流程跑通但结果基本不变”。

#### H.2 测试骨架位置与角色

- 目录：`tests/test_plugins/test_preprocess/`
  - `__init__.py`：简要说明该目录用于 preprocess 插件测试；
  - `test_integration.py`：集成测试骨架，直接关联本设计文档：
    - `test_preprocess_cases_layout`：
      - 校验 `tests/preprocess_cases` 目录存在，且包含上面列出的所有案例子目录；
      - 确保未来如移动/删除测试数据时，同步更新设计文档和测试；
    - `TestPreprocessPluginIntegration` 集成测试类：
      - 针对每个案例提供一条集成测试骨架（目前以 `@pytest.mark.xfail + pytest.skip` 形式存在）；
      - 每个测试方法的 docstring 明确对应步骤（time-align/dedup/oneway）和报告行为的预期；
      - preprocess 插件实现完成后，应逐步用真实逻辑替换 `pytest.skip(...)`，并根据本设计文档补充断言。

#### H.3 从测试骨架出发的实现路线建议

实现 preprocess 插件时，建议严格对齐本设计文档的语义，并以测试骨架作为“落地契约”：

1. **基础结构与配置层**：
   - 按第 4 节实现 `ToolsConfig` / `PreprocessConfig` / `PreprocessRuntimeConfig`；
   - 按附录 A 实现 `PreprocessContext`、`STEP_HANDLERS` 以及自动模式 / 显式 steps 模式；
   - 此阶段可先补充纯单元测试（不依赖真实 PCAP），确保配置与调度行为符合文档描述。
2. **外部工具封装与步骤实现**：
   - 在 `pcap_tools.py` 或等价模块中封装 `capinfos` / `editcap` / `tshark` 调用；
   - 根据附录 C/D/E 实现 `time-align`、`dedup`、`oneway` 三个步骤，并按附录 D 实现独立的原始文件归档逻辑（非 pipeline 步骤）；
   - 使用 `tests/preprocess_cases` 中对应案例，逐步为 `TestPreprocessPluginIntegration` 中各测试方法填充真实逻辑与断言：
     - `TC-060-2-20210730` → 验证 dedup 前后包数及与 `*-dedup.pcap` 的接近程度；
     - `TC-035-06-20240704` → 验证 one-way 连接删除效果；
     - `TC-044-2-20230920` / `TC-063-1-20230306` → 验证多节点 time-align 行为与重叠时间区间计算；
     - `TC-014-1-20231212` → 验证截断 PCAP 的鲁棒性与错误记录；
     - `TC-047-7-20240328` → 验证服务链场景下的 end-to-end 对齐；
     - `TC-028-1-20240308` → 验证小文件 baseline，全流程应快速完成且结果可预期。
3. **Markdown 报告实现与验证**：
   - 按附录 G 的结构生成 per-run 报告（默认 `output_dir / "preprocess_report.md"`）；
   - 在集成测试中为关键案例（如 `TC-060-2-20210730`、`TC-063-1-20230306`、`TC-014-1-20231212`）增加对报告内容的断言：
     - run 概览是否包含时间 / 版本 / 配置摘要；
     - 文件级对比是否正确列出原始与最终 PCAP 的 packet_count / first_ts / last_ts；
     - 步骤效果汇总中是否正确反映裁剪区间、去重率、one-way 删除数量等。

通过上述方式，preprocess 插件的实现将与本设计文档以及测试骨架形成闭环：
- 文档定义语义与行为；
- 测试骨架将文档内容具体化为可执行的验收标准；
- 插件实现则以通过这些测试为目标，确保功能、性能与可追溯性满足预期。

#### H.4 实施计划 Checklist（用于过程追踪）

> 说明：下面的 checklist 更偏工程视角，可用于跟踪 preprocess 插件从“设计就绪”到“开发落地”的整体进度。

1. **环境与工具准备**
   - [x] 确认 Wireshark 工具链已安装且版本满足要求（`tshark` / `editcap` / `capinfos`）。
   - [x] 在开发环境中配置好 `ToolsConfig` / 环境变量 / PATH，确保外部工具可以被发现并正确调用。

2. **配置与 CLI 层打通**
   - [x] 完成 `capmaster/plugins/preprocess/config.py` 中 `ToolsConfig` / `PreprocessConfig` / `PreprocessRuntimeConfig` 的定义及默认值（对应第 4 节）。
   - [x] 将 YAML / ENV / CLI 与配置对象的映射全部打通，包括步骤开关、dedup/time-align/oneway 参数、报告配置与 `workers` 等（对应第 5、6 节）。
   - [x] 实现 `capmaster preprocess` 子命令和 `--step` / `--enable-xxx` / `--disable-xxx` 等参数的冲突校验逻辑（对应第 6.3、6.4、6.5 节）。

3. **Pipeline 主流程搭建**
   - [x] 按附录 A 定义 `PreprocessContext`、`STEP_HANDLERS`，实现自动模式与显式 steps 模式的调度规则。
   - [x] 实现一个对外 API（例如 `run_preprocess(...)`），负责构造 `PreprocessContext`、创建 `tmp_dir`、按顺序执行各步骤，并在全部成功后迁移产物到 `output_dir`。

4. **外部工具封装与各步骤实现**
   - [x] 在 `pcap_tools.py` 或等价模块中封装 `capinfos` / `editcap` / `tshark` 的调用。
   - [x] 基于 `workers` 的并发控制（对应第 3.1、附录 E）。
   - [x] 按附录 C / D / E 的语义实现 `time-align`、`dedup`、`oneway` 三个步骤，并保证在多文件场景下行为正确；同时按附录 D 实现独立的原始文件归档逻辑（非 pipeline 步骤）。
   - [x] （可选）实现 time-align + dedup 的单次 `editcap` 优化调用，在大文件场景下降低 I/O 成本。

5. **报告与输出结构**
   - [x] 按附录 F 约定实现最终 PCAP 输出命名规则以及 `archive/` 目录结构，确保对上层只暴露“预处理完成”的结果文件。
   - [x] 按附录 G 约定生成 per-run Markdown 报告，并在 CLI / API 中接好 `report_enabled` / `report_path` 开关。

6. **测试与验收闭环**
   - [x] 按 H.1 准备或同步 `tests/preprocess_cases` 目录结构，确保各案例数据到位（即使仅在本地存在、不入库）。
   - [x] 按 H.2 / H.3 逐步填充 `tests/test_plugins/test_preprocess/test_integration.py` 中各案例的集成测试，实现从 `xfail/skip` 向真实断言演进。
   - [x] 在 CI 中接入 preprocess 相关测试，保证后续改动可以自动回归。

当以上 checklist 条目全部勾选完成时，可以认为 preprocess 插件已经从“设计就绪”进入“实现与验证闭环就绪”的状态，后续工作可以聚焦在功能迭代与性能优化上。