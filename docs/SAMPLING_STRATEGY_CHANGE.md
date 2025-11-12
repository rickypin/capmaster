# Sampling Strategy Change

## Summary

**采样策略已从"默认启用"改为"默认禁用"**

## 变更详情

### 之前的行为（旧版本）

- **默认行为**：当连接数超过 1000 时，自动启用采样（保留 50%）
- **禁用采样**：需要使用 `--no-sampling` 参数
- **自定义采样**：使用 `--sampling-threshold` 和 `--sampling-rate`

### 现在的行为（新版本）

- **默认行为**：不采样，处理所有连接
- **启用采样**：需要使用 `--enable-sampling` 参数
- **自定义采样**：使用 `--enable-sampling --sample-threshold` 和 `--sample-rate`

## 参数变更

| 旧参数 | 新参数 | 说明 |
|--------|--------|------|
| `--no-sampling` | （移除） | 默认就是不采样 |
| `--sampling-threshold` | `--sample-threshold` | 重命名，更简洁 |
| `--sampling-rate` | `--sample-rate` | 重命名，更简洁 |
| （无） | `--enable-sampling` | 新增，用于启用采样 |

## 迁移指南

### 场景 1：之前使用默认行为（自动采样）

**旧命令**：
```bash
capmaster match -i captures/
```

**新命令**（如果想保持采样行为）：
```bash
capmaster match -i captures/ --enable-sampling
```

**新命令**（如果想要完整准确性）：
```bash
capmaster match -i captures/
# 默认就是不采样，无需任何参数
```

### 场景 2：之前使用 --no-sampling

**旧命令**：
```bash
capmaster match -i captures/ --no-sampling
```

**新命令**：
```bash
capmaster match -i captures/
# 默认就是不采样，移除 --no-sampling 参数
```

### 场景 3：之前使用自定义采样参数

**旧命令**：
```bash
capmaster match -i captures/ --sampling-threshold 5000 --sampling-rate 0.3
```

**新命令**：
```bash
capmaster match -i captures/ --enable-sampling --sample-threshold 5000 --sample-rate 0.3
```

## 为什么做这个变更？

### 问题背景

在之前的实现中，Match 和 Compare 插件的行为不一致：

1. **Match 插件**：默认启用采样（连接数 > 1000 时）
2. **Compare 插件**：不支持采样，总是处理所有连接

这导致了一个严重的问题：

- Match 输出显示的是采样后的匹配结果
- Compare 使用完整的连接集重新匹配
- **结果不一致**：Compare 比较的连接对可能不在 Match 的 12 对里

### 用户案例

用户报告：
- Match 找到 12 对匹配的连接
- Compare 比较的连接对不在这 12 对里
- 看起来像是逻辑矛盾

实际原因：
- Match 对 4877 个连接进行了采样，只保留了约 2438 个
- 采样后，stream ID 重新分配
- Match 匹配的是 stream 331（端口 2833）
- Compare 没有采样，匹配的是 stream 1046（端口 24083）
- 这是两个不同的 TCP 连接！

### 解决方案

**改为默认不采样**，理由：

1. **一致性优先**：Match 和 Compare 默认行为一致
2. **准确性优先**：默认提供完整、准确的结果
3. **可预测性**：用户不会遇到"神秘的不一致"
4. **性能可选**：需要性能优化时，显式启用采样

## 影响范围

### 受影响的用户

1. **依赖默认采样行为的用户**
   - 需要添加 `--enable-sampling` 参数
   - 或者接受新的默认行为（更准确但可能更慢）

2. **使用 `--no-sampling` 的用户**
   - 可以移除该参数（默认就是不采样）
   - 或者保留（向后兼容，但会有警告）

3. **使用自定义采样参数的用户**
   - 需要添加 `--enable-sampling` 参数
   - 参数名称需要更新（`--sample-threshold` 和 `--sample-rate`）

### 性能影响

对于大型数据集（> 1000 连接）：

- **之前**：自动采样，速度快但可能不准确
- **现在**：处理所有连接，速度慢但完全准确
- **建议**：显式使用 `--enable-sampling` 来优化性能

## 测试验证

### 验证默认行为

```bash
# 默认不采样
python -m capmaster match -i /path/to/pcaps/
# 输出应该显示：Sampling disabled (default behavior)
```

### 验证启用采样

```bash
# 启用采样
python -m capmaster match -i /path/to/pcaps/ --enable-sampling
# 输出应该显示：Applying sampling to first file...
```

### 验证 Match 和 Compare 一致性

```bash
# Match（默认不采样）
python -m capmaster match -i file1.pcap,file2.pcap -o matches.txt

# Compare（默认不采样）
python -m capmaster compare -i file1.pcap,file2.pcap -o compare.txt

# 两者应该使用相同的连接对
```

## 相关文件

- `capmaster/plugins/match/plugin.py` - Match 插件实现
- `docs/SAMPLING_QUICK_REFERENCE.md` - 采样快速参考
- `examples/match_sampling_examples.sh` - 示例脚本
- `tests/test_plugins/test_match/test_units.py` - 单元测试
- `tests/test_plugins/test_match/test_integration.py` - 集成测试

## 向后兼容性

### 已移除的参数

- `--no-sampling`：移除，默认就是不采样

### 重命名的参数

- `--sampling-threshold` → `--sample-threshold`
- `--sampling-rate` → `--sample-rate`

### 建议

1. **更新脚本**：将 `--no-sampling` 移除
2. **更新文档**：使用新的参数名称
3. **测试验证**：确保新行为符合预期

## 常见问题

### Q: 为什么我的 Match 命令变慢了？

A: 因为默认不再采样。如果需要更快的速度，使用 `--enable-sampling`。

### Q: 我的脚本使用了 `--no-sampling`，会报错吗？

A: 不会报错，但该参数已被移除。建议移除该参数。

### Q: Match 和 Compare 现在一致了吗？

A: 是的！默认情况下，两者都不采样，使用相同的连接集。

### Q: 什么时候应该启用采样？

A: 当你有非常大的数据集（> 10,000 连接）且需要快速探索时。

### Q: 采样会影响准确性吗？

A: 会。采样可能会遗漏一些匹配，但对于大型数据集的快速分析很有用。

## 更新日期

2025-01-12

