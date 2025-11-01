# Shell 脚本最佳实践检查清单

## 📋 快速参考：你的脚本符合多少条？

基于 ShellCheck 和业界标准，检查你的 Bash 脚本质量。

---

## ✅ 核心最佳实践（必须遵守）

### 1. Shebang 和严格模式
- [ ] 使用明确的 `#!/bin/bash` 而非 `#!/bin/sh`
- [ ] 设置 `set -e`（遇到错误立即退出）
- [ ] 设置 `set -u`（使用未定义变量时报错）
- [ ] 设置 `set -o pipefail`（管道中的任何失败都导致失败）

```bash
#!/bin/bash
set -euo pipefail
```

**你的脚本**:
- ✅ 原版: 使用 `set -e`（部分符合）
- ✅ 改进版: 使用 `set -euo pipefail`（完全符合）

---

### 2. 变量引用
- [ ] **所有**变量使用双引号: `"$var"` 而非 `$var`
- [ ] 数组展开使用: `"${array[@]}"` 而非 `${array[@]}`
- [ ] 避免使用: `$*`，改用 `"$@"`

```bash
# ❌ 错误
echo $var
for i in $@; do :; done

# ✅ 正确
echo "$var"
for i in "$@"; do :; done
```

**你的脚本**:
- ✅ 原版: 大部分变量正确引用
- ✅ 改进版: 所有变量正确引用

---

### 3. 临时文件和资源清理
- [ ] 使用 `mktemp` 创建临时文件（而非硬编码路径）
- [ ] 使用 `trap` 确保清理（即使异常退出）
- [ ] 清理函数保留原退出码

```bash
cleanup_files=()
trap 'rm -f "${cleanup_files[@]}"' EXIT INT TERM

temp=$(mktemp)
cleanup_files+=("$temp")
```

**你的脚本**:
- ⚠️ 原版: 使用 mktemp，但无 trap（不符合）
- ✅ 改进版: mktemp + trap（完全符合）

---

### 4. 错误处理
- [ ] 错误消息输出到 stderr: `>&2`
- [ ] 提供有意义的错误消息
- [ ] 返回适当的退出码（0=成功，非0=失败）
- [ ] 关键操作检查返回值

```bash
# ❌ 错误
echo "错误: 文件不存在"
exit 1

# ✅ 正确
echo "错误: 文件 $file 不存在" >&2
exit 1
```

**你的脚本**:
- ⚠️ 原版: 部分错误输出到 stdout（不符合）
- ✅ 改进版: 所有错误输出到 stderr（符合）

---

### 5. 函数设计
- [ ] 使用 `local` 声明局部变量
- [ ] 函数通过参数接收输入（而非全局变量）
- [ ] 函数通过 `echo`/`return` 返回结果
- [ ] 每个函数只做一件事

```bash
# ❌ 依赖全局变量
get_name() {
    echo "Hello $USER"
}

# ✅ 通过参数传递
get_name() {
    local user=$1
    echo "Hello $user"
}
```

**你的脚本**:
- ⚠️ 原版: 函数访问全局变量 `total_commands`（部分符合）
- ✅ 改进版: 函数完全参数化（完全符合）

---

## 🔐 安全性（重要）

### 6. 避免代码注入
- [ ] 谨慎使用 `eval`（尽可能避免）
- [ ] 如必须使用 `eval`，添加安全注释
- [ ] 验证和清理用户输入
- [ ] 使用数组而非字符串拼接命令

```bash
# ⚠️ 危险（如果 $input 不可信）
eval "$input"

# ✅ 安全
# shellcheck disable=SC2294
# We use eval here because... [说明原因]
# Ensure input is trusted!
eval "$input"
```

**你的脚本**:
- ⚠️ 原版: 使用 eval 但无安全说明（存在风险）
- ✅ 改进版: eval 附带详细安全注释（降低风险）

---

### 7. 文件和路径安全
- [ ] 使用 `mktemp` 而非 `/tmp/myfile`
- [ ] 检查文件权限（可读、可写、可执行）
- [ ] 避免路径遍历攻击（验证路径）
- [ ] 引用所有路径变量

```bash
# ❌ 不安全
temp_file="/tmp/myapp.$$"

# ✅ 安全
temp_file=$(mktemp)
```

**你的脚本**:
- ✅ 原版: 使用 mktemp（符合）
- ✅ 改进版: mktemp + 权限检查（完全符合）

---

## 🔧 可维护性

### 8. 代码可读性
- [ ] 有意义的变量名（避免 `a`, `tmp`, `x`）
- [ ] 添加注释解释"为什么"（而非"是什么"）
- [ ] 使用一致的缩进（2或4空格）
- [ ] 函数前添加说明注释

```bash
# ❌ 难以理解
x=$(cat $f | grep $p | wc -l)

# ✅ 清晰
matching_lines=$(grep "$pattern" "$file" | wc -l)
```

**你的脚本**:
- ✅ 原版: 变量命名清晰（符合）
- ✅ 改进版: 变量命名清晰 + 更多注释（完全符合）

---

### 9. 输入验证
- [ ] 检查必需参数是否提供
- [ ] 验证文件/目录是否存在
- [ ] 检查读写权限
- [ ] 提供有用的帮助信息

```bash
# ✅ 完整的验证
if [ $# -eq 0 ]; then
    echo "用法: $0 <file>" >&2
    exit 1
fi

file=$1
if [ ! -f "$file" ]; then
    echo "错误: 文件 $file 不存在" >&2
    exit 1
fi

if [ ! -r "$file" ]; then
    echo "错误: 文件 $file 不可读" >&2
    exit 1
fi
```

**你的脚本**:
- ✅ 原版: 基本验证（符合）
- ✅ 改进版: 完整验证（完全符合）

---

## 🌐 可移植性

### 10. 跨平台兼容性
- [ ] 避免 Bash 特有语法（如需 POSIX）
- [ ] 检查外部命令是否可用
- [ ] 处理不同 OS 的差异（date, sed, etc.）
- [ ] 提供降级方案

```bash
# ✅ 跨平台时间测量
get_time() {
    if command -v gdate >/dev/null 2>&1; then
        gdate +%s.%N  # macOS with GNU coreutils
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        date +%s      # macOS fallback
    else
        date +%s.%N   # Linux
    fi
}
```

**你的脚本**:
- ❌ 原版: 仅 Linux 兼容（不符合）
- ✅ 改进版: macOS/Linux 兼容（完全符合）

---

### 11. 外部命令依赖
- [ ] 检查命令是否存在: `command -v cmd`
- [ ] 提供降级方案
- [ ] 文档中说明依赖

```bash
# ✅ 检查并降级
if command -v bc >/dev/null 2>&1; then
    result=$(echo "$a + $b" | bc)
else
    result=$((a + b))  # 整数降级
fi
```

**你的脚本**:
- ❌ 原版: 假设 bc 存在（不符合）
- ✅ 改进版: bc → awk → bash 降级链（完全符合）

---

## 📊 评分卡

### 你的脚本得分

| 类别 | 原版得分 | 改进版得分 | 满分 |
|------|---------|-----------|------|
| **核心实践** (1-5) | 14/20 | 20/20 | 20 |
| **安全性** (6-7) | 5/10 | 10/10 | 10 |
| **可维护性** (8-9) | 8/10 | 10/10 | 10 |
| **可移植性** (10-11) | 3/10 | 10/10 | 10 |
| **总分** | **30/50** | **50/50** | **50** |

### 等级评定
- 45-50: ⭐⭐⭐⭐⭐ 优秀（生产级）
- 35-44: ⭐⭐⭐⭐ 良好（可用）
- 25-34: ⭐⭐⭐ 中等（需改进）← **原版在这里**
- 15-24: ⭐⭐ 较差（需重构）
- 0-14:  ⭐ 危险（不可用）

---

## 🚀 快速改进指南

### 如果你的脚本得分 < 35，优先修复：

1. **立即修复**:
   - [ ] 添加 `set -euo pipefail`
   - [ ] 所有变量加双引号
   - [ ] 错误输出到 stderr (`>&2`)

2. **重要改进**:
   - [ ] 添加 trap 清理资源
   - [ ] 检查外部命令可用性
   - [ ] 完善输入验证

3. **质量提升**:
   - [ ] 改善跨平台兼容性
   - [ ] 添加有意义的注释
   - [ ] 函数参数化（减少全局依赖）

---

## 🔍 使用 ShellCheck

**自动检查你的脚本**:

```bash
# 安装 ShellCheck
# macOS
brew install shellcheck

# Ubuntu/Debian
sudo apt-get install shellcheck

# 检查脚本
shellcheck your_script.sh

# 查看详细说明
shellcheck -x your_script.sh
```

**在线检查**: https://www.shellcheck.net/

---

## 📚 推荐资源

1. **ShellCheck Wiki**: https://github.com/koalaman/shellcheck/wiki
2. **Google Shell Style Guide**: https://google.github.io/styleguide/shellguide.html
3. **Bash Hackers Wiki**: https://wiki.bash-hackers.org/
4. **Advanced Bash-Scripting Guide**: https://tldp.org/LDP/abs/html/

---

## ✅ 检查清单总结

打印这个清单，在代码审查时使用：

```
□ Shebang: #!/bin/bash
□ 严格模式: set -euo pipefail
□ 变量引用: "$var"
□ trap 清理资源
□ 错误到 stderr (>&2)
□ local 局部变量
□ 避免或注释 eval
□ mktemp 临时文件
□ 有意义的变量名
□ 输入验证
□ 检查命令可用性
□ 跨平台兼容
```

**目标**: 全部打勾 ✓

---

*基于 ShellCheck、Google Style Guide 和业界最佳实践编制*


