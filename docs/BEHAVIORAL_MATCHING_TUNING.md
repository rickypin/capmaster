# 行为匹配策略调优报告

## 概述

本文档总结了对行为匹配策略（Behavioral Matching）的效果验证和调优过程。

## 当前实现

### 特征定义

行为匹配策略基于以下 4 个特征：

1. **时间重叠（overlap）**：两个连接的时间范围交集/并集比例
   - 计算：`intersection(time_range1, time_range2) / union(time_range1, time_range2)`
   - 范围：[0.0, 1.0]

2. **持续时间相似度（duration）**：两个连接的持续时间比值
   - 计算：`min(dur1, dur2) / max(dur1, dur2)`
   - 范围：[0.0, 1.0]

3. **报文间隔相似度（IAT - Inter-Arrival Time）**：两个连接的平均报文间隔比值
   - 计算：`min(iat1, iat2) / max(iat1, iat2)`
   - 范围：[0.0, 1.0]

4. **总字节数相似度（bytes）**：两个连接的总字节数比值
   - 计算：`min(bytes1, bytes2) / max(bytes1, bytes2)`
   - 范围：[0.0, 1.0]

### 当前权重配置

```
overlap:  35%
duration: 25%
iat:      20%
bytes:    20%
```

## 验证结果

### 数据集

- 来源：`/Users/ricky/Downloads/2hops/`
- 分析用例数：10 个
- 总匹配对数：3441

### 特征表现

基于 10 个用例的加权平均：

| 特征 | 平均值 | 低值比例 (<0.5) | 评价 |
|------|--------|----------------|------|
| overlap | 0.829 | 10.4% | 在大多数场景有效，但部分场景不重叠 |
| duration | 0.955 | 0.1% | **非常有效** ✓ |
| iat | 0.592 | 52.9% | 区分度一般 |
| bytes | 0.577 | 56.2% | 区分度一般 |

### 单用例深度分析（TC-001-1-20160407）

| 特征 | 平均值 | 范围 | 低值比例 (<0.1) |
|------|--------|------|----------------|
| overlap | 0.006 | [0.00, 0.67] | 99.0% |
| duration | 0.995 | [0.67, 1.00] | 0.0% |
| iat | 0.996 | [0.74, 1.00] | 0.0% |
| bytes | 0.940 | [0.61, 0.98] | 0.0% |

**关键发现**：在该用例中，99% 的匹配对时间不重叠（overlap < 0.1），说明两跳抓包的时间范围基本不重叠。

## 权重配置对比

在 TC-001-1-20160407 用例上测试不同权重配置：

| 配置 | Overlap | Duration | IAT | Bytes | 匹配数 | 平均分数 |
|------|---------|----------|-----|-------|--------|----------|
| Current (default) | 0.35 | 0.25 | 0.20 | 0.20 | 105 | 0.638 |
| Recommended | 0.24 | 0.41 | 0.24 | 0.12 | 110 | 0.749 |
| Duration-focused | 0.10 | 0.50 | 0.25 | 0.15 | 162 | 0.798 |
| **No overlap** | **0.00** | **0.40** | **0.30** | **0.30** | **166** | **0.871** |
| Equal weights | 0.25 | 0.25 | 0.25 | 0.25 | 110 | 0.730 |

**最佳配置**："No overlap"（完全不考虑时间重叠）
- 匹配数：166（vs 当前 105，+58%）
- 平均分数：0.871（vs 当前 0.638，+36%）

## 调优建议

### 推荐配置 1：无时间重叠约束（适用于两跳抓包场景）

```
overlap:  0%
duration: 40%
iat:      30%
bytes:    30%
```

**适用场景**：
- 两跳抓包（时间可能不同步）
- 存在显著网络延迟
- 抓包时间窗口不完全重叠

**CLI 使用**：
```bash
capmaster match -i <case_dir> --mode behavioral \
  --behavioral-weight-overlap 0.0 \
  --behavioral-weight-duration 0.4 \
  --behavioral-weight-iat 0.3 \
  --behavioral-weight-bytes 0.3
```

### 推荐配置 2：保守配置（基于统计分析）

```
overlap:  24%
duration: 41%
iat:      24%
bytes:    12%
```

**适用场景**：
- 需要时间重叠作为辅助约束
- 对匹配质量要求较高
- 希望平衡各特征的贡献

**CLI 使用**：
```bash
capmaster match -i <case_dir> --mode behavioral \
  --behavioral-weight-overlap 0.24 \
  --behavioral-weight-duration 0.41 \
  --behavioral-weight-iat 0.24 \
  --behavioral-weight-bytes 0.12
```

## 进一步优化方向

1. **自适应权重**：根据数据集特征自动调整权重
   - 检测时间重叠比例，动态降低 overlap 权重
   - 根据特征分布自动优化权重配置

2. **新增特征**：
   - TCP 序列号跨度（seq_span）：`max(seq) - min(seq)`
   - 报文数量相似度（packet_count）
   - 连接起始时间差（start_time_delta）：作为软约束

3. **混合策略**：
   - 在 auto 模式中融合行为特征
   - 将行为特征作为额外评分维度，与现有特征打分结合

## 使用示例

### 基本使用

```bash
# 使用默认权重
capmaster match -i /path/to/case --mode behavioral

# 使用推荐配置 1（无时间重叠）
capmaster match -i /path/to/case --mode behavioral \
  --behavioral-weight-overlap 0.0 \
  --behavioral-weight-duration 0.4 \
  --behavioral-weight-iat 0.3 \
  --behavioral-weight-bytes 0.3

# 调整阈值
capmaster match -i /path/to/case --mode behavioral \
  --threshold 0.70 \
  --behavioral-weight-overlap 0.0 \
  --behavioral-weight-duration 0.4 \
  --behavioral-weight-iat 0.3 \
  --behavioral-weight-bytes 0.3
```

### 批量分析

```bash
# 分析前 10 个用例的特征分布
python scripts/batch_analyze_behavioral.py 10

# 对比不同权重配置
python scripts/compare_weight_configs.py

# 单用例深度分析
python scripts/run_behavioral_and_analyze.py
```

## 总结

1. **duration（持续时间）是最有效的特征**，应给予最高权重（40%+）
2. **overlap（时间重叠）在两跳场景中不可靠**，建议降低或移除（0-10%）
3. **iat 和 bytes 有一定区分度**，可作为辅助特征（各 25-30%）
4. **推荐使用"无时间重叠"配置**，在测试用例上表现最佳

## 附录：分析脚本

- `scripts/batch_analyze_behavioral.py`：批量分析多个用例的特征分布
- `scripts/run_behavioral_and_analyze.py`：单用例深度分析
- `scripts/compare_weight_configs.py`：对比不同权重配置的效果
- `scripts/analyze_behavioral_results.py`：分析 behavioral vs auto 的对比结果

