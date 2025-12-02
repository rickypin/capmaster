# comparative-analysis 承载 compare 功能实施方案

本方案旨在让 `comparative-analysis` 插件完整复刻 `compare` 的逐包差异功能，确保 CLI 行为与输出 **100% 一致**，同时遵循“理性、实用、不过度工程化”的原则。

## 目标

1. 在 `comparative-analysis` CLI 中提供新的 `packet-diff` 模式，默认逻辑与 `capmaster compare` 完全一致。
2. 在过渡期保留 `compare` 命令作为回退入口，直到新模式验证稳定。
3. 复用 `capmaster.plugins.compare_common` 中的所有实现，避免代码复制。

## 基线与一致性要求

| 项目 | 要求 |
| --- | --- |
| 输入解析 | 继续使用 `InputManager.resolve_inputs/validate_file_count`，同 `compare.execute` |
| 匹配逻辑 | 调用 `MatchPlugin.match_connections_in_memory`，参数与 compare 相同 |
| 报文提取/差异统计 | 直接导入 `compare_common.PacketExtractor`、`PacketComparator` |
| 输出 | 使用 `compare_common.output_formatter.build_report_text`、`DatabaseWriter`，meta 写入 `packet_differences` |
| CLI 行为 | 选项名称、默认值、日志内容保持一致；出现差异需在设计前评审 |

## 实施步骤

### 阶段 1：接入 compare_common

1. 在 `comparative_analysis` runner 内引入 `compare_common` 包；新增 `execute_packet_diff` 辅助函数，将 compare 的核心逻辑搬入函数中供两个命令共用。
2. `compare` 插件暂时调用新函数（共享代码路径），验证输出无变化。

### 阶段 2：扩展 CLI

1. 在 `capmaster/plugins/match/cli_commands.py` 的 `comparative-analysis` 命令中新增 `--packet-diff`（或 `--mode packet`），并在 `MatchPlugin.resolve_args` 中映射为 `analysis_type="packet"`。
2. `run_comparative_analysis` 根据 `analysis_type` 分支调用 `execute_packet_diff`。
3. 更新帮助信息与用户文档，提示 `compare` 将在未来版本废弃。

### 阶段 3：验证

1. 复用 data/2hops 中的若干案例，比较 `capmaster compare` 与 `capmaster comparative-analysis --packet-diff` 输出文件/数据库内容，确保一致。
2. 为新模式补充 CLI 测试：至少覆盖输入数量校验、`--show-flow-hash`、`--matched-only`、数据库写入等主路径。

### 阶段 4：收尾

1. 当 `comparative-analysis --packet-diff` 在真实案例中稳定运行后，发布迁移公告，下一版删除 `compare` 插件及 CLI 注册。
2. 更新文档与示例脚本，统一使用 `comparative-analysis --packet-diff`。

## 注意事项

- **复用而非复制**：严禁在 comparative-analysis 内重写报文提取或差异计算逻辑，必须 import `compare_common`。
- **元数据一致性**：保持 meta JSON 写入 `command_id="packet_differences"`；如需区分来源，可额外添加字段但不得改变现有值。
- **数据库依赖**：沿用 compare 的 `validate_database_params` 校验规则，避免 CLI 行为差异。
- **回退策略**：在 compare 移除前，任何异常都可通过原命令验证；必要时保留 `compare` 日志提示“请改用 comparative-analysis --packet-diff”。

此方案聚焦最少改动即可共享实现，确保在对用户影响最低的前提下完成迁移。若需调整，请先评估是否会破坏一致性目标。*** End Patch
