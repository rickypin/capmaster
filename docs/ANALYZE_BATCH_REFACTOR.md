# Analyze 批处理重构方案

## 背景
- 基准（2025-11-29）：`analyze_single` 运行全部模块耗时 ~70.6s，约占全套 benchmark 的 90%+
- 主要瓶颈：
  1. 每个模块独立调用 `tshark`，缺乏命令复用；
  2. Worker 进程重复初始化 `TsharkWrapper`、`ProtocolDetector`、模块实例；
  3. 缺少模块级耗时指标，难以定位最慢链路。

目标：将单文件耗时压缩到 <20s，并为后续优化（并行/模块裁剪）提供可观测性；同时保证现有 CLI 体验、输出格式、sidecar 逻辑与错误处理保持不变。

## 总体思路

### 1. 模块分组 + 批量执行
- 引入 `ModuleBatch` 概念：按 `build_tshark_args` 类型将模块聚类，支持一次调用输出多模块原始数据，复用单次 `tshark` 执行的 stdout。
  - **Field-based 模块**：以 `-T fields -e ...` 形式，允许拼接字段；需要在 `ModuleBatch` 中记录字段范围与模块绑定。
  - **Statistics 模块**：`-z conv,tcp` 等，目前难以合并；保留单独调用但可与其他 `-z` 同类模块合并。
- 每个 `ModuleBatch` 包含：
  ```python
  class ModuleBatch:
      name: str
      modules: list[AnalysisModule]
      builder: BatchCommandBuilder  # 提供 tshark 参数 + output parser
      def execute(self, input_file, tshark, output_dir, format, sidecar, progress): ...
  ```
- `AnalysisExecutor.execute_modules` 调整流程：
  1. 根据 `modules` 生成若干 `ModuleBatch`;
  2. 逐 batch 调用 `tshark`；
  3. Batch 内部将 stdout 拆分回原模块 -> `module.post_process()` -> 写文件。

### 2. Worker 初始化缓存
- 进程启动后在 `_process_single_file` 里缓存批处理执行器（模块级全局变量），避免重复初始化：
  ```python
  _BATCH_ENGINE = None
  def _get_batch_engine():
      global _BATCH_ENGINE
      if _BATCH_ENGINE is None:
          tshark = TsharkWrapper()
          protocol_detector = ProtocolDetector(tshark)
          executor = AnalysisExecutor(tshark, protocol_detector)
          _BATCH_ENGINE = executor
      return _BATCH_ENGINE
  ```
- 每个 worker 进程仍拥有独立实例，上述缓存仅避免同一进程重复构造；在 macOS 默认 spawn 模式下，需要通过 `ProcessPoolExecutor(initializer=...)` 预热，确保全局缓存生效。

> 现有 `ProcessPoolExecutor` 场景中 `_process_single_file` 会被 pickle；需确认新的 `AnalysisExecutor` 成员可被 picklable 或者在 worker 内即时构建，以上缓存仅在 worker 侧保存 Python 对象，不尝试跨进程共享。

### 3. 模块元数据与策略
- 在 `AnalysisModule` 基类新增或默认实现属性：
  - `batch_group`: Literal["fields", "stats", "custom"]；
  - `fields`: list[str]（适用于 fields 模式）。
- 对已有模块一次性标注，形成可维护的 batch 规则；默认值为 `"custom"`，可保证未显式标注的模块保持旧逻辑。

### 4. 监控与输出
- 新增 `ModuleMetrics` 数据结构：
  ```python
  {
      "module": "...",
      "batch": "...",
      "tshark_time_sec": ...,
      "post_process_time_sec": ...,
      "output_file": "...",
  }
  ```
- 每次运行写入 `artifacts/tmp/analyze_metrics/<pcap>.json`（避免污染 benchmarks 目录），记录 batch 和模块耗时；在 logger 中打印 top N 慢模块，便于快速追踪。
- `run_benchmarks.py` 不需要变更，只需在基准运行后检查新增 metrics 文件即可判断优化效果。

## 详细设计

### ModuleBatch 构建
1. 使用新增元数据扫描 modules，按 `batch_group` 归类；
2. `fields` 组：聚合所有字段，必要时按「字段数量 / 命令长度」拆分多个 Batch（例如 >200 字段时拆段），Batch 输出中记录每个模块字段区间；
3. `stats` 组：按 `-z` 子命令类型分组，确保上下文兼容（例如 `-z conv,tcp` 与 `-z io,stat,0,1,"tcp"` 可组合，但 `-z expert` 需独立执行）；
4. `custom`：保留现有逐模块调用。

### 执行流程
```
ProtocolDetector.detect(input_file)
 -> modules_to_run (与当前逻辑完全一致)
 -> batches = build_batches(modules_to_run)
 -> for batch in batches:
        batch_metrics = batch.run_tshark(...)
        for module in batch.modules:
            parsed = module.extract(batch_metrics.raw)
            output_path = OutputManager.get_output_path(...)
            module.write(parsed, output_path, format, sidecar)
```
其中 `batch.run_tshark` 负责构造命令、计时、记录原始 stdout/stderr，并在失败时抛异常；`module.extract` 默认为基于字段截取的辅助函数，保留 `module.post_process` 兼容。

### 错误处理
- 保持原有 `handle_error` 行为；
-- Batch 失败视为包含模块整体失败，记录 metrics（含命令、退出码、stderr），并抛出异常保证外层日志与 exit code 行为不变；
- 需要保障 `selected_modules` 过滤后仍正常批处理。

### 并发扩展（预留）
- 当模块批处理完成后，可进一步解耦“文件维度并行”与“batch 维度并发”；阶段 1 不改动进程池，只在 `ProcessPoolExecutor` 内部减少 `tshark` 调用；
- 初期先完成单文件批处理，确认稳定后再评估引入 `ThreadPoolExecutor` 为批任务加速。

## 验证方案
1. **功能回归**：运行 `tests/test_plugins/test_analyze/*` + 基准 `capmaster analyze`（单文件/多文件/`-m` 过滤/`--sidecar`）。
2. **性能对比**：  
   - 基准：`python3 scripts/benchmarks/run_benchmarks.py --suite analyze --output artifacts/benchmarks/benchmarks-before.json`  
   - 重构后同命令，使用 `compare_benchmarks.py` 检查 `analyze_single` 与 `analyze_parallel` 的 wall time & max RSS。
3. **指标检查**：确认 `artifacts/tmp/analyze_metrics/*.json` 生成，并包含 batch/module 耗时与命令信息。

## 交付物
- 代码：`AnalysisExecutor` + 新的 batch 构建与执行器、模块元数据；`benchmarks.yaml` / CLI 层无需改动。
- 文档：更新本方案 + `docs/AI_PLUGIN_EXTENSION_GUIDE.md`（新增 `AnalysisModule.batch_group` 指南）。
- 基线：提交重构后新的 `artifacts/benchmarks/benchmarks-YYYYMMDD.json` 及 diff 报告。

