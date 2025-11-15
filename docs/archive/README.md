# Archive - Historical Analysis & Design Reports

本目录用于归档 **行为匹配、策略对比、修复说明** 等历史/分析类文档。
这些文档通常带有明确的时间背景和实验环境，用于解释当前实现的由来，
但不保证与最新代码在细节上完全同步。

## 文档列表

- `BEHAVIORAL_MATCHING_TUNING.md`
  - 行为匹配策略调优报告，分析特征选择与权重配置的影响。
- `BEHAVIORAL_PRECISION_ANALYSIS.md`
  - 行为匹配精确度分析，评估误匹配（False Positive）情况。
- `BEHAVIORAL_VALIDATION_REPORT.md`
  - 行为匹配策略验证报告，基于多案例对比 Auto 与推荐配置。
- `MATCHING_STRATEGIES_COMPARISON.md`
  - 匹配策略对比分析，讨论 F5 / TLS / Behavioral / Auto 等策略的原理与适用场景。
- `STRATEGY_COMPARISON_SUMMARY.md`
  - 匹配策略对比总结，给出代表性案例的结果与推荐配置。
- `MERGE_BY_5TUPLE_FIX.md`
  - `--merge-by-5tuple` 在 F5/TLS 场景下的修复说明，记录关键设计决策。
- `PROTOCOL_COVERAGE_REPORT.md`
  - 协议覆盖率报告，记录在特定数据集上的协议分布与已实现分析模块列表（历史快照）。
- `PERFORMANCE_REPORT.md`
  - 性能基准测试报告，包含不同命令在指定环境下的运行耗时和资源使用情况（历史快照）。
- `MATCH_PLUGIN_PERFORMANCE_REVIEW.md`
  - Match 插件性能审查与优化建议，记录当时的性能分析和优化思路（历史快照）。

## 使用建议

- 了解 **当前行为匹配和策略选择的设计背景** 时，可从这些文档开始阅读；
- 若代码实现与文档存在出入，请以 **代码与测试** 为准，并在必要时更新/追加新的报告；
- 对需要长期维护的对外行为（CLI、主要指标、用户工作流），请优先更新
  `USER_GUIDE.md`、`QUICK_REFERENCE.md` 和相关特性文档。

