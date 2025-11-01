# run_csv_commands.sh - 使用说明

批量执行 CSV 命令并生成 Markdown 报告的高性能脚本。

---

## 🚀 快速开始

```bash
# 给脚本添加执行权限
chmod +x run_csv_commands.sh

# 基础用法：只在终端查看结果
./run_csv_commands.sh user_prompts/group_01.csv

# 推荐用法：保存结果到 Markdown 文件
./run_csv_commands.sh user_prompts/group_01.csv output_results
```

---

## 📖 使用方法

### 语法

```bash
./run_csv_commands.sh <csv_file_path> [output_directory]
```

### 参数说明

- **`csv_file_path`** (必需): CSV 文件路径（相对或绝对路径）
- **`output_directory`** (可选): 输出目录，如不提供则不保存文件

### 使用示例

```bash
# 1. 只在终端显示结果（不保存）
./run_csv_commands.sh user_prompts/group_01.csv

# 2. 保存到指定目录
./run_csv_commands.sh user_prompts/group_01.csv results

# 3. 使用时间戳目录归档结果（推荐）
./run_csv_commands.sh user_prompts/group_01.csv "results/$(date +%Y%m%d_%H%M%S)"

# 4. 使用绝对路径
./run_csv_commands.sh /path/to/commands.csv /path/to/output
```

---

## 📝 CSV 文件格式

CSV 文件每行一条命令，支持注释：

```csv
# 这是注释行，会被自动跳过
codex --full-auto exec "cases/TC-002-1-20211208/ 目录下存放了相关的pcap文件，用户反馈访服务响应慢，分析原因"
echo "测试命令"

# 另一个注释
ls -lh /tmp
```

**规则：**
- 每行一条完整的 shell 命令
- 以 `#` 开头的行会被跳过
- 空行会被自动跳过
- 支持管道、重定向等 shell 语法

---

## 📄 输出文件

### 文件命名

脚本会智能提取 `cases/` 目录名作为文件名：

| 命令中的路径 | 生成的文件名 |
|-------------|-------------|
| `cases/TC-002-1-20211208/` | `TC-002-1-20211208.md` |
| `cases/TC-056-1-20190614/` | `TC-056-1-20190614.md` |
| (无 cases 目录) | `command_N.md` |

### Markdown 文件结构

每个生成的 `.md` 文件包含：

```markdown
# TC-002-1-20211208

## 命令信息
- 命令序号、CSV 行号、执行时间

## 执行命令
```bash
[实际执行的命令]
```

## 执行输出
```
[命令的完整输出]
```

## 执行结果
- 状态、退出码、执行耗时
```

---

## 💡 常见使用场景

### 场景 1：批量网络诊断

```bash
# 执行多个诊断任务并按日期归档
TODAY=$(date +%Y%m%d)
./run_csv_commands.sh user_prompts/network_analysis.csv "analysis/$TODAY"

# 查看结果
ls -lh analysis/$TODAY/
```

### 场景 2：快速验证

```bash
# 测试几条命令，不保存结果
cat > test.csv << 'EOF'
echo "测试 1"
echo "测试 2"
EOF

./run_csv_commands.sh test.csv
rm test.csv
```

### 场景 3：自动化定期任务

```bash
#!/bin/bash
# cron_job.sh

OUTPUT="reports/$(date +%Y%m%d_%H%M%S)"
./run_csv_commands.sh daily_tasks.csv "$OUTPUT"

# 发送通知
echo "任务完成，结果保存到 $OUTPUT" | mail -s "Daily Report" admin@example.com
```

---

## 🎨 终端输出

### 彩色显示

- 🟢 **绿色**: 命令分隔线、序号
- 🟡 **黄色**: 命令内容
- 🔵 **蓝色**: 状态信息、耗时
- 🔴 **红色**: 错误消息

### 输出示例

```
========================================
开始执行 CSV 文件中的命令
CSV 文件: /Users/ricky/Downloads/code/tshark/user_prompts/group_01.csv
输出目录: /Users/ricky/Downloads/code/tshark/results
========================================

----------------------------------------
[命令 #1] 第 1 行
命令: echo "Hello World"
----------------------------------------
Hello World

[执行完成] 状态: 成功 | 耗时: 0.002345678 秒

输出已保存到: /Users/ricky/Downloads/code/tshark/results/command_1.md

========================================
执行总结
========================================
总命令数: 1
成功: 1
失败: 0
========================================
```

**注意**: 当输出被重定向到文件时，颜色会自动禁用，保持纯文本格式。

---

## ⚙️ 系统要求

### 必需

- **Bash**: 4.0+
- **基础工具**: `mktemp`, `tee` (通常已预装)

### 可选 (用于更好的功能)

- **macOS**: 
  - `gdate` (通过 `brew install coreutils` 安装) - 用于纳秒级时间精度
  - 或使用内置的 Perl (已预装)
- **Linux**: `bc` 或 `awk` - 用于浮点数计算

**降级策略**: 脚本会自动检测可用工具并降级：
- 时间测量: `gdate` → `perl` → `date` (秒)
- 耗时计算: `bc` → `awk` → bash 算术 (整数)

---

## ⚠️ 安全提示

**重要**: 脚本使用 `eval` 执行命令，具有完整的 shell 权限。

- ✅ **确保 CSV 文件来源可信**
- ❌ 不要执行来自不明来源的 CSV 文件
- ✅ 建议在执行前检查 CSV 内容：`cat your_file.csv`

---

## 🔧 故障排查

### 问题 1: 脚本无法执行

```bash
# 错误: Permission denied
chmod +x run_csv_commands.sh
```

### 问题 2: 找不到 CSV 文件

```bash
# 检查文件是否存在
ls -l user_prompts/group_01.csv

# 使用绝对路径
./run_csv_commands.sh "$(pwd)/user_prompts/group_01.csv"
```

### 问题 3: 无法创建输出目录

```bash
# 检查父目录权限
ls -ld output_dir/..

# 或手动创建
mkdir -p output_dir
```

### 问题 4: macOS 时间精度问题

如果看到 `.N` 而非纳秒：

```bash
# 选项 1: 安装 GNU coreutils
brew install coreutils

# 选项 2: 脚本会自动使用 Perl (已预装)
# 无需操作，脚本会自动降级
```

### 问题 5: bc 命令未找到

```bash
# Ubuntu/Debian
sudo apt-get install bc

# macOS
brew install bc

# 或者脚本会自动使用 awk 或 bash 算术
```

---

## 📊 性能特性

- ✅ **跨平台**: macOS 和 Linux 完全兼容
- ✅ **自动清理**: 使用 trap 确保临时文件清理，即使 Ctrl+C 中断
- ✅ **错误处理**: `set -euo pipefail` 严格错误检查
- ✅ **智能降级**: 工具不可用时自动使用替代方案
- ✅ **零依赖安装**: 基础功能无需额外安装

---

## 🎯 高级技巧

### 并行执行

```bash
# 同时执行多组任务
./run_csv_commands.sh group_01.csv results/g1 &
./run_csv_commands.sh group_02.csv results/g2 &
wait
echo "所有任务完成"
```

### 只执行部分命令

```bash
# 提取前 5 行命令执行
head -5 large_file.csv > subset.csv
./run_csv_commands.sh subset.csv test_results
```

### 监控执行进度

```bash
# 在另一个终端实时监控
watch -n 2 'ls -lh results/ | tail -10'
```

### 生成执行报告

```bash
OUTPUT="results/$(date +%Y%m%d)"
./run_csv_commands.sh commands.csv "$OUTPUT"

# 生成索引
{
    echo "# 执行报告 - $(date)"
    echo ""
    echo "## 生成的文件"
    echo ""
    for f in "$OUTPUT"/*.md; do
        echo "- [$(basename "$f")]($(basename "$f"))"
    done
} > "$OUTPUT/INDEX.md"
```

---

## 📚 相关文档

- **`BEST_PRACTICES_CHECKLIST.md`** - Shell 脚本最佳实践检查清单
- **脚本源码** - `run_csv_commands.sh`

---

## ❓ 常见问题

**Q: 此脚本有什么特别之处？**  
A: 此脚本遵循 Shell 最佳实践，包括 trap 清理、跨平台兼容、完整错误处理等。详见 `BEST_PRACTICES_CHECKLIST.md`。

**Q: 可以修改 CSV 后缀吗？**  
A: 可以，脚本不检查扩展名，任何文本文件都可以。

**Q: 如何停止执行？**  
A: 按 `Ctrl+C`，脚本会自动清理临时文件并退出。

**Q: 输出文件会覆盖吗？**  
A: 是的，同名文件会被覆盖。建议每次使用不同的输出目录。

**Q: 支持 Windows 吗？**  
A: 需要 WSL (Windows Subsystem for Linux) 或 Git Bash 环境。

---

## 📝 版本信息

**当前版本**: v2.0  
**最后更新**: 2025-10-14

### 特性

- ✅ 跨平台时间测量（macOS/Linux）
- ✅ trap 自动清理临时文件
- ✅ 严格错误处理模式
- ✅ 智能工具降级策略
- ✅ 注释行支持
- ✅ 完整的输入验证
- ✅ 智能颜色输出

---

**需要帮助？** 请查看脚本源码中的注释或参考 `BEST_PRACTICES_CHECKLIST.md`。

