# Compare Plugin - Silent Mode 使用指南

## 概述

compare 插件新增了 `--silent` 参数，启用后可以静默执行，不在屏幕上显示进度条和比较结果。这对于以下场景特别有用：

- 批量处理多个文件对
- 在脚本中调用，只需要日志或文件输出
- 写入数据库时不需要屏幕输出
- 减少终端输出干扰

## 新增参数

### `--silent`

- **类型**: 标志参数（flag）
- **默认值**: False（不启用）
- **作用**: 
  - 禁用进度条显示
  - 禁用屏幕输出（stdout）
  - 保留日志输出（logger）
  - 保留文件输出（-o 参数）
  - 保留数据库输出（--db-connection）

## 使用示例

### 示例 1: 基本静默模式

```bash
capmaster compare \
  --file1 a.pcap \
  --file1-pcapid 0 \
  --file2 b.pcap \
  --file2-pcapid 1 \
  --silent
```

**效果**:
- ✅ 不显示进度条
- ✅ 不在屏幕上打印比较结果
- ✅ 日志仍然输出到 stderr（可以看到处理进度）
- ❌ 没有保存结果（因为没有指定输出文件或数据库）

### 示例 2: 静默模式 + 文件输出

```bash
capmaster compare \
  --file1 a.pcap \
  --file1-pcapid 0 \
  --file2 b.pcap \
  --file2-pcapid 1 \
  --silent \
  -o comparison_result.txt
```

**效果**:
- ✅ 不显示进度条
- ✅ 不在屏幕上打印比较结果
- ✅ 结果保存到 `comparison_result.txt` 文件
- ✅ 日志输出显示处理进度

### 示例 3: 静默模式 + 数据库输出

```bash
capmaster compare \
  --file1 a.pcap \
  --file1-pcapid 0 \
  --file2 b.pcap \
  --file2-pcapid 1 \
  --silent \
  --show-flow-hash \
  --db-connection "postgresql://postgres:password@172.16.200.156:5433/r2" \
  --kase-id 133
```

**效果**:
- ✅ 不显示进度条
- ✅ 不在屏幕上打印比较结果
- ✅ 结果写入数据库表 `public.kase_133_tcp_stream_extra`
- ✅ 日志输出显示处理进度和数据库写入状态

### 示例 4: 静默模式 + 文件输出 + 数据库输出

```bash
capmaster compare \
  --file1 a.pcap \
  --file1-pcapid 0 \
  --file2 b.pcap \
  --file2-pcapid 1 \
  --silent \
  -o comparison_result.txt \
  --show-flow-hash \
  --db-connection "postgresql://postgres:password@172.16.200.156:5433/r2" \
  --kase-id 133
```

**效果**:
- ✅ 不显示进度条
- ✅ 不在屏幕上打印比较结果
- ✅ 结果保存到文件
- ✅ 结果写入数据库
- ✅ 日志输出显示处理进度

### 示例 5: 批量处理脚本

```bash
#!/bin/bash
# 批量比较多对 PCAP 文件

PAIRS=(
  "a1.pcap:b1.pcap"
  "a2.pcap:b2.pcap"
  "a3.pcap:b3.pcap"
)

for pair in "${PAIRS[@]}"; do
  IFS=':' read -r file1 file2 <<< "$pair"
  
  echo "Processing: $file1 vs $file2"
  
  capmaster compare \
    --file1 "$file1" \
    --file1-pcapid 0 \
    --file2 "$file2" \
    --file2-pcapid 1 \
    --silent \
    -o "result_${file1%.pcap}_vs_${file2%.pcap}.txt" \
    --show-flow-hash \
    --db-connection "postgresql://postgres:password@172.16.200.156:5433/r2" \
    --kase-id 133
  
  if [ $? -eq 0 ]; then
    echo "✅ Success: $file1 vs $file2"
  else
    echo "❌ Failed: $file1 vs $file2"
  fi
done
```

## 对比：普通模式 vs 静默模式

### 普通模式（默认）

```bash
capmaster compare --file1 a.pcap --file1-pcapid 0 --file2 b.pcap --file2-pcapid 1
```

**输出**:
```
INFO     Baseline file: a.pcap
INFO     Compare file: b.pcap
INFO     Comparison direction: b.pcap relative to a.pcap
⠋ Extracting connections...                                    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 50%
INFO     Found 10 connections in a.pcap
⠙ Extracting connections...                                    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
INFO     Found 10 connections in b.pcap
⠹ Matching connections...                                      ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
INFO     Found 8 matched connection pairs
⠸ Comparing packets...                                         ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
⠼ Writing results...                                           ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
====================================================================================================
TCP Connection Packet-Level Comparison Report
====================================================================================================
Baseline File: a.pcap
Compare File:  b.pcap
...（完整的比较结果）
```

### 静默模式

```bash
capmaster compare --file1 a.pcap --file1-pcapid 0 --file2 b.pcap --file2-pcapid 1 --silent
```

**输出**:
```
INFO     Baseline file: a.pcap
INFO     Compare file: b.pcap
INFO     Comparison direction: b.pcap relative to a.pcap
INFO     Found 10 connections in a.pcap
INFO     Found 10 connections in b.pcap
INFO     Found 8 matched connection pairs
INFO     Comparison complete
```

**区别**:
- ❌ 没有进度条
- ❌ 没有比较结果的详细输出
- ✅ 只有简洁的日志信息

## 日志级别控制

如果你想完全静默（连日志都不显示），可以结合日志级别参数：

```bash
# 只显示错误日志
capmaster --log-level ERROR compare \
  --file1 a.pcap \
  --file1-pcapid 0 \
  --file2 b.pcap \
  --file2-pcapid 1 \
  --silent \
  -o result.txt

# 完全静默（只显示严重错误）
capmaster --log-level CRITICAL compare \
  --file1 a.pcap \
  --file1-pcapid 0 \
  --file2 b.pcap \
  --file2-pcapid 1 \
  --silent \
  -o result.txt
```

## 注意事项

1. **日志输出**: `--silent` 只禁用进度条和屏幕输出，不影响日志输出。如需控制日志，请使用 `--log-level` 参数。

2. **文件输出**: 使用 `-o` 参数指定输出文件时，结果仍会正常写入文件，不受 `--silent` 影响。

3. **数据库输出**: 使用 `--db-connection` 时，数据仍会正常写入数据库，不受 `--silent` 影响。

4. **错误处理**: 即使在静默模式下，错误信息仍会通过日志输出，确保问题可以被发现。

5. **退出码**: 静默模式不影响退出码，可以在脚本中正常检查执行结果。

## 适用场景

### ✅ 适合使用静默模式的场景

- 批量处理多个文件对
- 在 cron 任务中定期执行
- 在 CI/CD 流程中集成
- 只需要文件或数据库输出
- 减少日志文件大小

### ❌ 不适合使用静默模式的场景

- 交互式调试
- 需要实时查看比较结果
- 首次运行，需要确认输出格式
- 需要监控处理进度

## 总结

`--silent` 参数提供了一种灵活的方式来控制 compare 插件的输出行为，特别适合自动化和批量处理场景。通过结合文件输出（`-o`）和数据库输出（`--db-connection`），可以在保持静默的同时确保结果被正确保存。

