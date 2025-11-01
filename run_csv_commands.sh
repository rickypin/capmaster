#!/bin/bash

# 脚本功能：读取 csv 文件中的命令并逐一执行，统计每条命令的执行耗时，并将输出保存到独立的 md 文件
# 用法: ./run_csv_commands.sh <csv_file_path> [output_directory]
# 示例: ./run_csv_commands.sh user_prompts/group_01.csv
#      ./run_csv_commands.sh user_prompts/group_01.csv output/results
#      ./run_csv_commands.sh /absolute/path/to/commands.csv /absolute/output/path

# 严格模式
set -euo pipefail

# 临时文件清理数组
cleanup_temp_files=()

# 清理函数
cleanup() {
    local exit_code=$?
    if [ ${#cleanup_temp_files[@]} -gt 0 ]; then
        rm -f "${cleanup_temp_files[@]}" 2>/dev/null || true
    fi
    exit $exit_code
}

# 设置清理 trap
trap cleanup EXIT INT TERM HUP

# 颜色定义（仅在交互式终端使用）
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

# 跨平台时间测量函数
get_timestamp() {
    if command -v gdate >/dev/null 2>&1; then
        # macOS with GNU coreutils (brew install coreutils)
        gdate +%s.%N
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS without GNU coreutils - 使用 Perl
        perl -MTime::HiRes=time -e 'printf "%.9f\n", time' 2>/dev/null || date +%s
    else
        # Linux
        date +%s.%N
    fi
}

# 计算耗时的函数
calculate_elapsed() {
    local start=$1
    local end=$2
    if command -v bc >/dev/null 2>&1; then
        echo "$end - $start" | bc
    elif command -v awk >/dev/null 2>&1; then
        awk "BEGIN {printf \"%.9f\", $end - $start}"
    else
        # 降级到整数秒
        echo $((${end%.*} - ${start%.*}))
    fi
}

# 函数：从命令中提取 cases 目录名
extract_case_name() {
    local cmd="$1"
    local fallback_num="${2:-0}"
    # 匹配 cases/XXX/ 格式，提取 XXX 部分
    if [[ "$cmd" =~ cases/([^/]+)/ ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        # 如果没有找到，返回默认名称
        echo "command_${fallback_num}"
    fi
}

# 检查参数
if [ $# -eq 0 ]; then
    echo -e "${RED}错误: 请提供 CSV 文件路径作为参数${NC}" >&2
    echo -e "用法: $0 <csv_file_path> [output_directory]" >&2
    echo -e "示例: $0 user_prompts/group_01.csv" >&2
    echo -e "      $0 user_prompts/group_01.csv output/results" >&2
    echo -e "      $0 /absolute/path/to/commands.csv /absolute/output/path" >&2
    exit 1
fi

# 获取 CSV 文件路径
CSV_FILE="$1"

# 获取输出目录（如果提供）
OUTPUT_DIR="${2:-}"

# 检查文件是否存在
if [ ! -f "$CSV_FILE" ]; then
    echo -e "${RED}错误: 文件 $CSV_FILE 不存在${NC}" >&2
    exit 1
fi

# 检查文件是否可读
if [ ! -r "$CSV_FILE" ]; then
    echo -e "${RED}错误: 文件 $CSV_FILE 不可读${NC}" >&2
    exit 1
fi

# 如果指定了输出目录，创建该目录
if [ -n "$OUTPUT_DIR" ]; then
    if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        echo -e "${RED}错误: 无法创建输出目录 $OUTPUT_DIR${NC}" >&2
        exit 1
    fi
    
    if ! OUTPUT_DIR_ABS=$(cd "$OUTPUT_DIR" && pwd); then
        echo -e "${RED}错误: 无法访问输出目录 $OUTPUT_DIR${NC}" >&2
        exit 1
    fi
    
    # 检查输出目录是否可写
    if [ ! -w "$OUTPUT_DIR_ABS" ]; then
        echo -e "${RED}错误: 输出目录 $OUTPUT_DIR_ABS 不可写${NC}" >&2
        exit 1
    fi
    
    echo -e "${BLUE}输出目录: $OUTPUT_DIR_ABS${NC}"
fi

# 获取文件的绝对路径用于显示
if ! CSV_FILE_ABS=$(cd "$(dirname "$CSV_FILE")" && pwd)/$(basename "$CSV_FILE"); then
    echo -e "${RED}错误: 无法访问文件路径 $CSV_FILE${NC}" >&2
    exit 1
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}开始执行 CSV 文件中的命令${NC}"
echo -e "${BLUE}CSV 文件: $CSV_FILE_ABS${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 统计变量
total_commands=0
successful_commands=0
failed_commands=0

# 读取 csv 文件并执行命令
line_num=0
while IFS= read -r line || [ -n "$line" ]; do
    line_num=$((line_num + 1))
    
    # 跳过空行和注释行
    if [ -z "$line" ] || [[ "$line" =~ ^[[:space:]]*# ]]; then
        continue
    fi
    
    total_commands=$((total_commands + 1))
    
    # 提取 case 名称用于文件名
    case_name=$(extract_case_name "$line" "$total_commands")
    
    # 如果指定了输出目录，准备输出文件
    if [ -n "$OUTPUT_DIR" ]; then
        output_file="${OUTPUT_DIR_ABS}/${case_name}.md"
        # 创建临时文件用于捕获输出
        temp_output=$(mktemp)
        cleanup_temp_files+=("$temp_output")
    fi
    
    # 准备显示内容
    header_line="----------------------------------------"
    cmd_num_line="[命令 #${total_commands}] 第 ${line_num} 行"
    cmd_content_line="命令: ${line}"
    
    # 同时输出到屏幕和文件（如果指定）
    echo -e "${GREEN}${header_line}${NC}"
    echo -e "${GREEN}${cmd_num_line}${NC}"
    echo -e "${YELLOW}${cmd_content_line}${NC}"
    echo -e "${GREEN}${header_line}${NC}"
    
    # 如果有输出文件，写入 md 格式的内容（无颜色）
    if [ -n "$OUTPUT_DIR" ]; then
        {
            echo "# ${case_name}"
            echo ""
            echo "## 命令信息"
            echo ""
            echo "- **命令序号**: #${total_commands}"
            echo "- **CSV 行号**: ${line_num}"
            echo "- **执行时间**: $(date '+%Y-%m-%d %H:%M:%S')"
            echo ""
            echo "## 执行命令"
            echo ""
            echo '```bash'
            echo "$line"
            echo '```'
            echo ""
            echo "## 执行输出"
            echo ""
            echo '```'
        } > "$output_file"
    fi
    
    # 记录开始时间
    start_time=$(get_timestamp)
    
    # 执行命令并捕获输出和退出状态
    # NOTE: 使用 eval 是因为 CSV 中的命令可能包含管道、重定向等 shell 语法
    # 安全警告：确保 CSV 文件来源可信！eval 会执行任意代码。
    # shellcheck disable=SC2294
    set +e
    if [ -n "$OUTPUT_DIR" ]; then
        # 同时输出到屏幕和临时文件
        eval "$line" 2>&1 | tee "$temp_output"
        exit_code=${PIPESTATUS[0]}
    else
        # 只输出到屏幕
        eval "$line"
        exit_code=$?
    fi
    set -e
    
    # 记录结束时间
    end_time=$(get_timestamp)
    
    # 计算耗时
    elapsed=$(calculate_elapsed "$start_time" "$end_time")
    
    # 统计成功/失败
    if [ "$exit_code" -eq 0 ]; then
        successful_commands=$((successful_commands + 1))
        status="${GREEN}成功${NC}"
        status_plain="成功"
    else
        failed_commands=$((failed_commands + 1))
        status="${RED}失败 (退出码: $exit_code)${NC}"
        status_plain="失败 (退出码: $exit_code)"
    fi
    
    # 显示完成信息
    completion_line="[执行完成] 状态: ${status} | 耗时: ${elapsed} 秒"
    echo ""
    echo -e "${BLUE}${completion_line}${NC}"
    echo ""
    
    # 如果有输出文件，完成 md 文件的写入
    if [ -n "$OUTPUT_DIR" ]; then
        {
            cat "$temp_output"
            echo '```'
            echo ""
            echo "## 执行结果"
            echo ""
            echo "- **状态**: ${status_plain}"
            echo "- **退出码**: ${exit_code}"
            echo "- **执行耗时**: ${elapsed} 秒"
            echo ""
            echo "---"
            echo ""
            echo "*生成时间: $(date '+%Y-%m-%d %H:%M:%S')*"
        } >> "$output_file"
        
        echo -e "${BLUE}输出已保存到: ${output_file}${NC}"
        echo ""
    fi
    
done < "$CSV_FILE"

# 打印总结
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}执行总结${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "总命令数: ${total_commands}"
echo -e "${GREEN}成功: ${successful_commands}${NC}"
if [ "$failed_commands" -gt 0 ]; then
    echo -e "${RED}失败: ${failed_commands}${NC}"
else
    echo -e "失败: ${failed_commands}"
fi
echo -e "${BLUE}========================================${NC}"

# 根据失败数量返回适当的退出码
if [ "$failed_commands" -gt 0 ]; then
    exit 1
else
    exit 0
fi

