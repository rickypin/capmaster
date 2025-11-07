# Compare Plugin - Silent Mode 功能说明

## 📋 概述

为 `capmaster compare` 插件添加了 `--silent` 参数，允许在批量处理或自动化场景中静默执行，减少屏幕输出干扰。

## ✨ 主要特性

### 启用 `--silent` 后的行为

| 功能 | 状态 | 说明 |
|------|------|------|
| 进度条 | ❌ 禁用 | 不显示 Extracting/Matching/Comparing/Writing 进度条 |
| 屏幕输出 | ❌ 禁用 | 不在 stdout 打印比较结果 |
| 日志输出 | ✅ 保留 | logger 输出仍然正常工作 |
| 文件输出 | ✅ 保留 | `-o` 参数指定的文件输出正常工作 |
| 数据库输出 | ✅ 保留 | `--db-connection` 数据库写入正常工作 |
| 错误提示 | ✅ 保留 | 错误信息仍通过日志输出 |
| 退出码 | ✅ 保留 | 退出码不受影响，可用于脚本错误检查 |

## 🚀 快速开始

### 基本用法

```bash
# 静默模式 + 文件输出
capmaster compare \
  --file1 a.pcap --file1-pcapid 0 \
  --file2 b.pcap --file2-pcapid 1 \
  --silent \
  -o result.txt

# 静默模式 + 数据库输出
capmaster compare \
  --file1 a.pcap --file1-pcapid 0 \
  --file2 b.pcap --file2-pcapid 1 \
  --silent \
  --show-flow-hash \
  --db-connection "postgresql://user:pass@host:port/db" \
  --kase-id 133
```

### 完全静默（连日志都不显示）

```bash
capmaster --log-level ERROR compare \
  --file1 a.pcap --file1-pcapid 0 \
  --file2 b.pcap --file2-pcapid 1 \
  --silent \
  -o result.txt
```

## 📁 文件清单

### 核心代码
- `capmaster/plugins/compare/plugin.py` - 主要修改文件

### 文档
- `README_SILENT_MODE.md` - 本文件，功能总览
- `SILENT_MODE_GUIDE.md` - 详细使用指南
- `SILENT_MODE_QUICK_REF.md` - 快速参考卡片
- `CHANGELOG_SILENT_MODE.md` - 更新日志和技术细节

### 示例
- `examples/batch_compare_silent.sh` - Bash 批处理示例
- `examples/batch_compare_silent.py` - Python 批处理示例

### 测试
- `test_silent_mode.py` - 自动化测试脚本

## 🔧 技术实现

### 1. CLI 参数
```python
@click.option(
    "--silent",
    is_flag=True,
    default=False,
    help="Silent mode: suppress progress bars and screen output (logs and file output still work)",
)
```

### 2. 进度条条件创建
```python
from contextlib import nullcontext
progress_context = nullcontext() if silent else Progress(...)
```

### 3. 屏幕输出控制
```python
if output_file:
    output_file.write_text(output_text)
elif not silent:
    print(output_text)
```

## 📊 使用场景

### ✅ 推荐使用场景
- 批量处理多个文件对
- Cron 定时任务
- CI/CD 自动化流程
- 只需要文件或数据库输出
- 减少日志文件大小

### ❌ 不推荐使用场景
- 交互式调试
- 首次运行测试
- 需要实时查看比较结果
- 需要监控处理进度

## 📖 使用示例

### 示例 1: 单次比较（静默 + 文件输出）

```bash
capmaster compare \
  --file1 baseline.pcap --file1-pcapid 0 \
  --file2 test.pcap --file2-pcapid 1 \
  --silent \
  -o comparison_result.txt
```

**输出**:
```
INFO     Baseline file: baseline.pcap
INFO     Compare file: test.pcap
INFO     Found 10 connections in baseline.pcap
INFO     Found 10 connections in test.pcap
INFO     Found 8 matched connection pairs
INFO     Results written to: comparison_result.txt
INFO     Comparison complete
```

### 示例 2: 批量处理（Bash）

```bash
#!/bin/bash
for i in {1..10}; do
  capmaster compare \
    --file1 "baseline_${i}.pcap" --file1-pcapid 0 \
    --file2 "test_${i}.pcap" --file2-pcapid 1 \
    --silent \
    -o "result_${i}.txt"
done
```

### 示例 3: 批量处理（Python）

```python
import subprocess

pairs = [
    ("baseline_1.pcap", "test_1.pcap"),
    ("baseline_2.pcap", "test_2.pcap"),
    ("baseline_3.pcap", "test_3.pcap"),
]

for i, (file1, file2) in enumerate(pairs, 1):
    subprocess.run([
        "capmaster", "compare",
        "--file1", file1, "--file1-pcapid", "0",
        "--file2", file2, "--file2-pcapid", "1",
        "--silent",
        "-o", f"result_{i}.txt",
    ], check=True)
```

## 🔍 对比：普通模式 vs 静默模式

### 普通模式输出
```
INFO     Baseline file: a.pcap
INFO     Compare file: b.pcap
⠋ Extracting connections...                    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 50%
INFO     Found 10 connections in a.pcap
⠙ Extracting connections...                    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
INFO     Found 10 connections in b.pcap
⠹ Matching connections...                      ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
INFO     Found 8 matched connection pairs
⠸ Comparing packets...                         ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
⠼ Writing results...                           ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
====================================================================================================
TCP Connection Packet-Level Comparison Report
====================================================================================================
Baseline File: a.pcap
Compare File:  b.pcap
...（完整的比较结果）
```

### 静默模式输出
```
INFO     Baseline file: a.pcap
INFO     Compare file: b.pcap
INFO     Found 10 connections in a.pcap
INFO     Found 10 connections in b.pcap
INFO     Found 8 matched connection pairs
INFO     Comparison complete
```

## ⚙️ 配置建议

### 日志级别控制

```bash
# 只显示警告和错误
capmaster --log-level WARNING compare --silent ...

# 只显示错误
capmaster --log-level ERROR compare --silent ...

# 完全静默（只显示严重错误）
capmaster --log-level CRITICAL compare --silent ...
```

### 输出重定向

```bash
# 将日志重定向到文件
capmaster compare --silent ... 2> compare.log

# 完全静默（丢弃所有输出）
capmaster --log-level CRITICAL compare --silent ... 2>/dev/null
```

## 🧪 测试

运行测试脚本：

```bash
# 自动化测试
python test_silent_mode.py

# Bash 批处理示例
bash examples/batch_compare_silent.sh

# Python 批处理示例
python examples/batch_compare_silent.py
```

## 📝 注意事项

1. **日志输出**: `--silent` 只禁用进度条和屏幕输出，不影响日志。如需控制日志，请使用 `--log-level` 参数。

2. **文件输出**: 使用 `-o` 参数时，结果仍会正常写入文件。

3. **数据库输出**: 使用 `--db-connection` 时，数据仍会正常写入数据库。

4. **错误处理**: 即使在静默模式下，错误信息仍会通过日志输出。

5. **退出码**: 静默模式不影响退出码，可以在脚本中正常检查执行结果。

## 🔗 相关文档

- [PCAPID_FEATURE_GUIDE.md](PCAPID_FEATURE_GUIDE.md) - PCAP ID 功能指南
- [SILENT_MODE_GUIDE.md](SILENT_MODE_GUIDE.md) - 详细使用指南
- [SILENT_MODE_QUICK_REF.md](SILENT_MODE_QUICK_REF.md) - 快速参考

## 📞 支持

如有问题或建议，请查看详细文档或联系开发团队。

